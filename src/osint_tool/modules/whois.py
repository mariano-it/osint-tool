"""Módulo whois: registro del dominio (RDAP) y certificado TLS en uso."""

from __future__ import annotations

import json
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Callable

import tldextract

from osint_tool import net
from osint_tool.models import Finding, ModuleResult, Severity
from osint_tool.modules.base import Module
from osint_tool.registry import register

CertFetcher = Callable[[str, float], dict[str, Any]]

# Public Suffix List incluida en el paquete: sin descargas ni caché en disco.
_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def registrable_domain(host: str) -> str:
    """Dominio registrable (x.co.uk, no co.uk) para consultar RDAP."""
    ext = _TLD(host)
    return (
        getattr(ext, "top_domain_under_public_suffix", None)
        or ext.registered_domain
        or host
    )


def parse_rdap(doc: dict[str, Any]) -> dict[str, Any]:
    events = {e.get("eventAction"): e.get("eventDate") for e in doc.get("events", [])}
    registrar = None
    for ent in doc.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    return {
        "registrar": registrar,
        "status": doc.get("status", []),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": [
            n.get("ldhName", "").lower() for n in doc.get("nameservers", [])
        ],
        "dnssec": (doc.get("secureDNS") or {}).get("delegationSigned"),
    }


def _days_until(iso: str | None, now: datetime) -> int | None:
    if not iso:
        return None
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (when - now).days


def fetch_tls_cert(host: str, timeout: float, port: int = 443) -> dict[str, Any]:
    """Conexión TLS normal al puerto 443; devuelve datos del certificado."""
    ctx = ssl.create_default_context()
    out: dict[str, Any] = {"verified": True, "verify_error": None}
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                out["tls_version"] = tls.version()
    except ssl.SSLCertVerificationError as exc:
        out.update(verified=False, verify_error=exc.verify_message)
        return out
    except OSError as exc:
        raise net.HttpError(f"TLS {host}:{port}: {exc}") from exc

    def flat(rdns):
        return {k: v for rdn in rdns for k, v in rdn}

    out.update(
        subject=flat(cert.get("subject", ())).get("commonName"),
        issuer=flat(cert.get("issuer", ())).get("organizationName"),
        not_before=datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc
        ).isoformat(),
        not_after=datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc
        ).isoformat(),
        san=[v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
    )
    return out


def analyze(rdap: dict[str, Any] | None, cert: dict[str, Any] | None, now: datetime):
    f: list[Finding] = []
    if rdap:
        days = _days_until(rdap.get("expires"), now)
        if days is not None:
            if days < 0:
                sev, label = Severity.HIGH, "El dominio está expirado"
            elif days < 30:
                sev, label = Severity.HIGH, f"El dominio expira en {days} días"
            elif days < 90:
                sev, label = Severity.MEDIUM, f"El dominio expira en {days} días"
            else:
                sev = None
            if sev is not None:
                f.append(
                    Finding(
                        label,
                        sev,
                        "Un dominio vencido puede ser registrado por un tercero.",
                        "Renovar y activar la renovación automática.",
                        rdap.get("expires") or "",
                    )
                )
        if rdap.get("status") and not any(
            "transfer" in s.lower() and "prohibited" in s.lower() for s in rdap["status"]
        ):
            f.append(
                Finding(
                    "Sin bloqueo de transferencia (clientTransferProhibited)",
                    Severity.LOW,
                    "Facilita el secuestro del dominio por transferencia no autorizada.",
                    "Activar el registrar lock en el registrador.",
                    ", ".join(rdap["status"]),
                )
            )
    if cert:
        if not cert.get("verified", True):
            f.append(
                Finding(
                    "Certificado TLS no válido",
                    Severity.HIGH,
                    "Los navegadores mostrarán advertencia o bloquearán el sitio.",
                    "Instalar un certificado válido y la cadena completa.",
                    cert.get("verify_error") or "",
                )
            )
        else:
            days = _days_until(cert.get("not_after"), now)
            if days is not None and days < 30:
                f.append(
                    Finding(
                        "Certificado TLS caduca pronto"
                        if days >= 0
                        else "Certificado TLS caducado",
                        Severity.HIGH if days < 14 else Severity.MEDIUM,
                        f"Quedan {days} días de validez.",
                        "Renovar y automatizar la renovación (ACME).",
                        cert.get("not_after") or "",
                    )
                )
    return f


@register
class WhoisModule(Module):
    name = "whois"
    description = "Registro del dominio (RDAP) y certificado TLS"

    def __init__(
        self,
        timeout: float = 5.0,
        fetch: Callable[..., net.Response] | None = None,
        cert_fetcher: CertFetcher | None = None,
        now: datetime | None = None,
    ):
        super().__init__(timeout=timeout)
        self._fetch = fetch or net.fetch
        self._cert = cert_fetcher or fetch_tls_cert
        self._now = now

    def _rdap(self, target: str) -> dict[str, Any]:
        # RDAP se consulta por dominio registrable (resuelto con la PSL).
        name = registrable_domain(target)
        last: Exception | None = None
        for _ in range(2):
            try:
                resp = self._fetch(
                    f"https://rdap.org/domain/{name}",
                    timeout=max(self.timeout, 15.0),
                )
            except net.HttpError as exc:
                last = exc
                time.sleep(1)
                continue
            if resp.status == 200:
                return json.loads(resp.body)
            last = net.HttpError(f"RDAP {name}: {resp.status}")
            if resp.status == 404:
                break
        raise net.HttpError(str(last))

    def run(self, target: str) -> ModuleResult:
        result = ModuleResult(module=self.name, target=target)
        errors: list[str] = []
        rdap = cert = None
        try:
            rdap = parse_rdap(self._rdap(target))
        except (net.HttpError, ValueError) as exc:
            errors.append(f"RDAP: {exc}")
        try:
            cert = self._cert(target, self.timeout)
        except net.HttpError as exc:
            errors.append(str(exc))

        if rdap is None and cert is None:
            result.error = "; ".join(errors)
            return result

        result.data = {"rdap": rdap, "certificate": cert, "errors": errors}
        result.findings = analyze(rdap, cert, self._now or datetime.now(timezone.utc))
        return result
