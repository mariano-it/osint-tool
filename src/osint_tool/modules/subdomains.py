"""Módulo subdomains: enumeración pasiva vía Certificate Transparency (crt.sh)."""

from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from urllib.parse import quote

from osint_tool import net
from osint_tool.models import Finding, ModuleResult, Severity
from osint_tool.modules.base import Module
from osint_tool.modules.dns_records import DnsClient, DnsError, DnspythonClient
from osint_tool.registry import register

SENSITIVE = {
    "dev", "test", "testing", "stage", "staging", "qa", "uat", "preprod",
    "sandbox", "demo", "beta", "old", "backup", "bak", "admin", "intranet",
    "internal", "vpn", "jenkins", "git", "gitlab", "grafana", "kibana",
    "phpmyadmin", "db", "sql", "debug", "tmp",
}
MAX_RESOLVE = 300


def parse_crtsh(raw: str, base: str) -> set[str]:
    """Extrae nombres únicos bajo `base` de la respuesta JSON de crt.sh."""
    names: set[str] = set()
    for entry in json.loads(raw):
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if name == base or name.endswith("." + base):
                names.add(name)
    return names


def parse_certspotter(raw: str, base: str) -> set[str]:
    names: set[str] = set()
    for entry in json.loads(raw):
        for name in entry.get("dns_names", []):
            name = str(name).strip().lower().lstrip("*.").rstrip(".")
            if name == base or name.endswith("." + base):
                names.add(name)
    return names


def sensitive_label(name: str, base: str) -> str | None:
    prefix = name[: -len(base)].rstrip(".")
    for token in re.split(r"[.\-_]", prefix):
        if token in SENSITIVE:
            return token
    return None


def make_resolver(timeout: float = 3.0, client: DnsClient | None = None):
    """Resolvedor A/AAAA con timeout real (getaddrinfo ignora los timeouts)."""
    dns_client = client or DnspythonClient(timeout=timeout)

    def resolve(name: str) -> list[str]:
        for rtype in ("A", "AAAA"):
            try:
                ips = dns_client.query(name, rtype)
            except DnsError:
                continue
            if ips:
                return sorted(set(ips))
        return []

    return resolve


@register
class SubdomainsModule(Module):
    name = "subdomains"
    description = "Subdominios vía certificate transparency (crt.sh) + resolución"

    def __init__(
        self,
        timeout: float = 5.0,
        fetch: Callable[..., net.Response] | None = None,
        resolve: Callable[[str], list[str]] | None = None,
    ):
        super().__init__(timeout=timeout)
        self._fetch = fetch or net.fetch
        self._resolve = resolve or make_resolver(timeout=min(timeout, 3.0))

    def _get_json(self, label: str, url: str, attempts: int) -> str:
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                resp = self._fetch(
                    url, timeout=max(self.timeout, 20.0), max_bytes=30_000_000
                )
                if resp.status == 200 and resp.body.strip().startswith(b"["):
                    return resp.body.decode("utf-8", "replace")
                last = net.HttpError(f"respondió {resp.status}")
            except net.HttpError as exc:
                last = exc
            if attempt + 1 < attempts:
                time.sleep(1.5 * (attempt + 1))
        raise net.HttpError(f"{label}: {last}")

    def _collect(self, base: str) -> tuple[set[str], str]:
        """crt.sh primero (inestable: 502/404 frecuentes); Cert Spotter de respaldo."""
        crt = f"https://crt.sh/?q={quote('%.' + base)}&output=json"
        spotter = (
            "https://api.certspotter.com/v1/issuances?domain="
            f"{quote(base)}&include_subdomains=true&expand=dns_names"
        )
        errors = []
        for source, url, parse, tries in (
            ("crt.sh", crt, parse_crtsh, 3),
            ("certspotter", spotter, parse_certspotter, 2),
        ):
            try:
                return parse(self._get_json(source, url, tries), base), source
            except (net.HttpError, ValueError) as exc:
                errors.append(str(exc))
        raise net.HttpError(" | ".join(errors))

    def run(self, target: str) -> ModuleResult:
        result = ModuleResult(module=self.name, target=target)
        base = target[4:] if target.startswith("www.") else target
        try:
            names, source = self._collect(base)
        except net.HttpError as exc:
            result.error = str(exc)
            return result

        names.discard(base)
        ordered = sorted(names)
        to_resolve = ordered[:MAX_RESOLVE]
        with ThreadPoolExecutor(max_workers=32) as pool:
            ips = dict(zip(to_resolve, pool.map(self._resolve, to_resolve)))

        live = {n: ips[n] for n in to_resolve if ips[n]}
        result.data = {
            "base_domain": base,
            "source": source,
            "total": len(ordered),
            "resolved_count": len(live),
            "subdomains": [
                {"name": n, "ips": ips.get(n, []), "resolves": bool(ips.get(n))}
                for n in ordered
            ],
        }
        if len(ordered) > MAX_RESOLVE:
            result.data["note"] = f"solo se resolvieron los primeros {MAX_RESOLVE}"

        for name in ordered:
            token = sensitive_label(name, base)
            if not token:
                continue
            is_live = name in live
            result.findings.append(
                Finding(
                    title=f"Subdominio de entorno interno: {name}",
                    severity=Severity.MEDIUM if is_live else Severity.INFO,
                    description=(
                        f"El nombre contiene '{token}' y "
                        + ("resuelve públicamente." if is_live else "figura en CT pero no resuelve.")
                        + " Estos entornos suelen tener menos controles."
                    ),
                    evidence=f"{name} -> {', '.join(live.get(name, [])) or 'sin resolución'}",
                    remediation=(
                        "Restringir por VPN/lista de IPs o autenticación, o dar de baja "
                        "el registro DNS si ya no se usa."
                    ),
                )
            )
        dangling = [n for n in to_resolve if not ips[n]]
        if dangling:
            result.findings.append(
                Finding(
                    title=f"{len(dangling)} subdominios en CT que ya no resuelven",
                    severity=Severity.INFO,
                    description="Nombres con certificados emitidos sin registro DNS activo.",
                    evidence=", ".join(dangling[:10]) + (" ..." if len(dangling) > 10 else ""),
                    remediation="Confirmar que no quedan CNAME colgantes ni servicios abandonados.",
                )
            )
        return result
