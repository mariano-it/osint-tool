from __future__ import annotations

import json

from osint_tool.models import ModuleResult, Report, Severity


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _render_dns(r: ModuleResult) -> list[str]:
    lines = ["| Tipo | Valores |", "|---|---|"]
    for rtype, values in r.data.get("records", {}).items():
        lines.append(f"| {rtype} | {_cell('; '.join(values)) or '—'} |")
    lines.append("")
    lines.append(f"- **DMARC:** {_cell('; '.join(r.data.get('dmarc', []))) or '—'}")
    state = {True: "sí", False: "no", None: "desconocido"}[r.data.get("dnssec")]
    lines.append(f"- **DNSSEC:** {state}")
    for err in r.data.get("query_errors", []):
        lines.append(f"- **Consulta fallida:** {_cell(err)}")
    return lines


def _render_subdomains(r: ModuleResult) -> list[str]:
    lines = [
        f"{r.data['total']} subdominios en CT, {r.data['resolved_count']} resuelven.",
        "",
        "| Subdominio | IPs |",
        "|---|---|",
    ]
    for s in r.data["subdomains"]:
        lines.append(f"| {s['name']} | {', '.join(s['ips']) or '— (no resuelve)'} |")
    return lines


def _render_generic(r: ModuleResult) -> list[str]:
    body = json.dumps(r.data, indent=2, ensure_ascii=False, default=str)
    return ["```json", body, "```"]


_RENDERERS = {"dns": _render_dns, "subdomains": _render_subdomains}


def render_markdown(report: Report) -> str:
    data = report.to_dict()
    lines = [
        f"# Reporte OSINT pasivo: {report.target}",
        "",
        f"Generado: {data['generated_at']}",
        "",
        "> Uso exclusivo sobre dominios propios o con autorización por escrito.",
        "",
        "## Resumen",
        "",
        "| Severidad | Hallazgos |",
        "|---|---|",
    ]
    for sev in sorted(Severity, reverse=True):
        lines.append(f"| {sev.label} | {data['summary'][sev.label]} |")

    lines += ["", "## Hallazgos (ordenados por riesgo)", ""]
    findings = report.all_findings()
    if not findings:
        lines += ["Sin hallazgos.", ""]
    for module, f in findings:
        lines += [
            f"### [{f.severity.label.upper()}] {f.title}",
            "",
            f"- **Módulo:** {module}",
            f"- **Descripción:** {f.description}",
        ]
        if f.evidence:
            lines.append(f"- **Evidencia:** `{f.evidence}`")
        lines += [f"- **Remediación:** {f.remediation}", ""]

    lines += ["## Datos recolectados", ""]
    for r in report.results:
        lines += [f"### {r.module}", ""]
        if r.error:
            lines += [f"**Error:** {r.error}", ""]
            continue
        lines += _RENDERERS.get(r.module, _render_generic)(r)
        lines.append("")
    return "\n".join(lines)
