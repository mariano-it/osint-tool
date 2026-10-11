"""Módulo DNS: registros públicos y postura de correo (SPF/DMARC), CAA, DNSSEC.

Solo hace consultas DNS normales a un resolvedor; no toca los servidores
del objetivo.
"""

from __future__ import annotations

import re
from typing import Protocol

import dns.exception
import dns.resolver

from osint_tool.models import Finding, ModuleResult, Severity
from osint_tool.modules.base import Module
from osint_tool.registry import register

RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA")


class DnsError(RuntimeError):
    """Fallo de red/resolvedor (distinto de 'el registro no existe')."""


class DnsClient(Protocol):
    def query(self, name: str, rtype: str) -> list[str]: ...


class DnspythonClient:
    def __init__(self, timeout: float = 5.0, nameservers: list[str] | None = None):
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout
        if nameservers:
            self._resolver.nameservers = nameservers

    def query(self, name: str, rtype: str) -> list[str]:
        try:
            answer = self._resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as exc:
            raise DnsError(f"{rtype} {name}: {exc.__class__.__name__}") from exc

        out = []
        for rdata in answer:
            if rtype == "TXT":
                # Un TXT puede venir partido en varias cadenas de 255 bytes.
                out.append(
                    "".join(s.decode("utf-8", "replace") for s in rdata.strings)
                )
            else:
                out.append(rdata.to_text())
        return out


# --- análisis puro (sin red), fácil de probar -------------------------------

_SPF_ALL = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)
# Mecanismos/modificadores que cuentan para el límite de 10 consultas (RFC 7208 §4.6.4).
_SPF_LOOKUP_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def _spf_lookup_count(tokens: list[str]) -> int:
    """Cuenta por token, mirando solo el nombre del mecanismo al inicio.

    Un regex sobre toda la cadena confunde `a`/`mx` dentro de nombres como
    `_spf.a.com`.
    """
    count = 0
    for token in tokens:
        term = re.split(r"[:/=]", token.lstrip("+-~?").lower(), maxsplit=1)[0]
        if term in _SPF_LOOKUP_TERMS:
            count += 1
    return count


def analyze_spf(txt_records: list[str], sends_mail: bool) -> list[Finding]:
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]

    if not spf:
        return [
            Finding(
                title="Falta registro SPF",
                severity=Severity.MEDIUM if sends_mail else Severity.LOW,
                description=(
                    "El dominio no publica SPF, así que cualquiera puede "
                    "falsificar correo con este dominio sin que el receptor "
                    "tenga una política contra la que comprobarlo."
                ),
                remediation=(
                    "Publicar un TXT en la raíz, p. ej. "
                    '"v=spf1 include:<tu-proveedor> -all". Si el dominio no '
                    'envía correo: "v=spf1 -all".'
                ),
            )
        ]

    if len(spf) > 1:
        return [
            Finding(
                title="Múltiples registros SPF",
                severity=Severity.MEDIUM,
                description=(
                    "RFC 7208 exige un único registro SPF; con varios, los "
                    "receptores devuelven permerror y SPF queda anulado."
                ),
                evidence=" | ".join(spf),
                remediation="Fusionar todos los mecanismos en un solo TXT.",
            )
        ]

    record = spf[0]
    tokens = record.split()[1:]
    all_match = next((m for m in map(_SPF_ALL.match, tokens) if m), None)
    has_redirect = any(t.lower().startswith("redirect=") for t in tokens)
    qualifier = all_match.group(1) if all_match else None
    findings: list[Finding] = []

    if all_match is None:
        # `redirect=` sustituye al `all` final: el registro es válido.
        if not has_redirect:
            findings.append(
                Finding(
                    title="SPF sin mecanismo 'all' final",
                    severity=Severity.LOW,
                    description="Sin 'all' el resultado por defecto es neutral.",
                    evidence=record,
                    remediation="Terminar el registro con '-all' (o '~all').",
                )
            )
    elif qualifier in ("", "+"):
        findings.append(
            Finding(
                title="SPF permite a cualquier servidor (+all)",
                severity=Severity.HIGH,
                description="'+all' autoriza a todo Internet a enviar por ti.",
                evidence=record,
                remediation="Cambiar a '-all' tras listar tus emisores reales.",
            )
        )
    elif qualifier == "?":
        findings.append(
            Finding(
                title="SPF neutral (?all)",
                severity=Severity.MEDIUM,
                description="'?all' no expresa ninguna política de rechazo.",
                evidence=record,
                remediation="Cambiar a '-all' (o '~all' durante la transición).",
            )
        )
    elif qualifier == "~":
        findings.append(
            Finding(
                title="SPF en softfail (~all)",
                severity=Severity.INFO,
                description=(
                    "Aceptable si DMARC está en quarantine/reject; "
                    "'-all' es más estricto."
                ),
                evidence=record,
                remediation="Considerar '-all' cuando la lista de emisores sea estable.",
            )
        )

    lookups = _spf_lookup_count(tokens)
    if lookups > 10:
        findings.append(
            Finding(
                title="SPF supera el límite de 10 consultas DNS",
                severity=Severity.LOW,
                description=f"{lookups} mecanismos que consultan DNS; >10 da permerror.",
                evidence=record,
                remediation="Aplanar includes o eliminar proveedores sin uso.",
            )
        )
    return findings


def _parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags


def analyze_dmarc(dmarc_records: list[str], sends_mail: bool) -> list[Finding]:
    dmarc = [t for t in dmarc_records if t.lower().startswith("v=dmarc1")]

    if not dmarc:
        return [
            Finding(
                title="Falta registro DMARC",
                severity=Severity.MEDIUM if sends_mail else Severity.LOW,
                description=(
                    "Sin DMARC los receptores no saben qué hacer con correo "
                    "que falla SPF/DKIM, y no recibes reportes de abuso."
                ),
                remediation=(
                    'Publicar TXT en _dmarc.<dominio>: '
                    '"v=DMARC1; p=none; rua=mailto:dmarc@<dominio>" y subir '
                    "a quarantine/reject tras revisar los reportes."
                ),
            )
        ]

    record = dmarc[0]
    tags = _parse_tags(record)
    policy = tags.get("p", "").lower()
    findings: list[Finding] = []

    if policy == "none":
        findings.append(
            Finding(
                title="DMARC en modo monitoreo (p=none)",
                severity=Severity.MEDIUM,
                description="p=none no bloquea ni aísla correo falsificado.",
                evidence=record,
                remediation="Pasar a p=quarantine y luego p=reject.",
            )
        )
    elif policy not in ("quarantine", "reject"):
        findings.append(
            Finding(
                title="DMARC con política inválida o ausente",
                severity=Severity.MEDIUM,
                description="El tag p= falta o tiene un valor no válido.",
                evidence=record,
                remediation="Definir p=none|quarantine|reject.",
            )
        )

    if "rua" not in tags:
        findings.append(
            Finding(
                title="DMARC sin destino de reportes agregados (rua)",
                severity=Severity.LOW,
                description="Sin rua no hay visibilidad sobre quién envía como tú.",
                evidence=record,
                remediation="Añadir rua=mailto:<buzón de reportes>.",
            )
        )

    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        findings.append(
            Finding(
                title=f"DMARC aplica solo al {pct}% del correo (pct)",
                severity=Severity.LOW,
                description="Parte del correo fraudulento no se somete a la política.",
                evidence=record,
                remediation="Subir pct a 100 cuando los reportes estén limpios.",
            )
        )
    return findings


def analyze_misc(
    records: dict[str, list[str]], has_dnskey: bool | None
) -> list[Finding]:
    """`records` solo debe contener tipos consultados con éxito;
    `has_dnskey` es None si la consulta falló (no se emite hallazgo)."""
    findings: list[Finding] = []

    if "CAA" in records and not records["CAA"]:
        findings.append(
            Finding(
                title="Sin registros CAA",
                severity=Severity.LOW,
                description="Cualquier CA pública puede emitir certificados.",
                remediation='Publicar CAA, p. ej. 0 issue "letsencrypt.org".',
            )
        )
    if len(records.get("NS", [])) == 1:  # ausente o 0 → no se evalúa
        findings.append(
            Finding(
                title="Un solo servidor de nombres (NS)",
                severity=Severity.LOW,
                description="Sin redundancia de DNS autoritativo.",
                evidence=", ".join(records["NS"]),
                remediation="Añadir al menos un segundo NS en otra red.",
            )
        )
    if has_dnskey is False:
        findings.append(
            Finding(
                title="DNSSEC no habilitado",
                severity=Severity.INFO,
                description="Las respuestas DNS del dominio no están firmadas.",
                remediation="Activar DNSSEC en el registrador/proveedor DNS si es viable.",
            )
        )
    return findings


# --- módulo ----------------------------------------------------------------


@register
class DnsModule(Module):
    name = "dns"
    description = "Registros DNS, SPF, DMARC, CAA y DNSSEC"

    def __init__(self, client: DnsClient | None = None, timeout: float = 5.0):
        super().__init__(timeout=timeout)
        self._client = client or DnspythonClient(timeout=timeout)

    def run(self, target: str) -> ModuleResult:
        result = ModuleResult(module=self.name, target=target)
        errors: list[str] = []

        def safe(name: str, rtype: str) -> list[str] | None:
            # None = la consulta falló (≠ lista vacía = el registro no existe)
            try:
                return self._client.query(name, rtype)
            except DnsError as exc:
                errors.append(str(exc))
                return None

        looked_up = {rt: safe(target, rt) for rt in RECORD_TYPES}
        dmarc = safe(f"_dmarc.{target}", "TXT")
        dnskey = safe(target, "DNSKEY")

        if len(errors) == len(RECORD_TYPES) + 2:
            result.error = errors[0]  # nada respondió: red o resolvedor caído
            return result

        ok = {rt: v for rt, v in looked_up.items() if v is not None}
        has_dnskey = None if dnskey is None else bool(dnskey)
        sends_mail = any(mx.split()[-1].rstrip(".") for mx in ok.get("MX", []))

        result.data = {
            "records": {rt: ok.get(rt, []) for rt in RECORD_TYPES},
            "dmarc": dmarc or [],
            "dnssec": has_dnskey,
            "query_errors": errors,
        }
        # Un tipo que falló no se analiza: evita falsos positivos tipo
        # "falta SPF" cuando en realidad el TXT no se pudo consultar.
        if "TXT" in ok:
            result.findings += analyze_spf(ok["TXT"], sends_mail)
        if dmarc is not None:
            result.findings += analyze_dmarc(dmarc, sends_mail)
        result.findings += analyze_misc(ok, has_dnskey)
        return result
