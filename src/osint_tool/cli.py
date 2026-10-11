"""Interfaz de línea de comandos."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from osint_tool import __version__, registry
from osint_tool.models import ModuleResult, Report, Severity
from osint_tool.report import render_json, render_markdown
from osint_tool.target import InvalidTarget, normalize_domain

NOTICE = (
    "[!] Usa esta herramienta solo contra dominios propios o con "
    "autorización por escrito.\n"
)
_COLORS = {
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint-tool",
        description="Recolector OSINT modular y pasivo. "
        "Ejemplo: osint-tool https://ejemplo.com",
    )
    p.add_argument("url", nargs="?", help="dominio o URL autorizada a auditar")
    p.add_argument("-t", "--target", help="igual que el argumento posicional")
    p.add_argument(
        "-m", "--modules", default="all",
        help="módulos separados por coma, o 'all' (por defecto)",
    )
    p.add_argument(
        "-f", "--format", default="json,md",
        help="formatos separados por coma: json, md (por defecto ambos)",
    )
    p.add_argument(
        "-o", "--output-dir", default=str(Path.home() / "osint-reports"),
        help="directorio de reportes (por defecto ~/osint-reports)",
    )
    p.add_argument("--timeout", type=float, default=8.0, help="timeout por petición (s)")
    p.add_argument("--no-color", action="store_true", help="sin colores ANSI")
    p.add_argument("--list-modules", action="store_true", help="lista los módulos y sale")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _paint(text: str, sev: Severity, color: bool) -> str:
    return f"{_COLORS[sev]}{text}\033[0m" if color else text


def print_summary(report: Report, color: bool) -> None:
    findings = report.all_findings()
    print()
    if not findings:
        print("Sin hallazgos.")
    for module, f in findings:
        tag = f"[{f.severity.label.upper():6}]"
        print(f"{_paint(tag, f.severity, color)} {f.title}  ({module})")
        print(f"         -> {f.remediation}")
    counts = report.to_dict()["summary"]
    print(
        "\nResumen: "
        + "  ".join(f"{k}={counts[k]}" for k in ("high", "medium", "low", "info"))
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    modules = registry.available()

    if args.list_modules:
        for name, cls in modules.items():
            print(f"{name:12} {cls.description}")
        return 0

    raw = args.url or args.target
    if not raw:
        parser.error("indica el dominio o URL a auditar: osint-tool https://ejemplo.com")
    try:
        target = normalize_domain(raw)
    except InvalidTarget as exc:
        parser.error(str(exc))

    if args.modules == "all":
        names = list(modules)
    else:
        names = [m.strip() for m in args.modules.split(",") if m.strip()]
        for name in names:
            if name not in modules:
                parser.error(f"módulo desconocido '{name}'. Disponibles: {', '.join(modules)}")
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    for fmt in formats:
        if fmt not in ("json", "md"):
            parser.error(f"formato desconocido '{fmt}' (usa json o md)")

    color = sys.stdout.isatty() and not args.no_color
    sys.stderr.write(NOTICE)
    print(f"[*] Objetivo: {target}", file=sys.stderr)

    results: list[ModuleResult] = []
    for name in names:
        started = time.monotonic()
        print(f"[*] {name} ...", end=" ", flush=True, file=sys.stderr)
        try:
            result = registry.get(name)(timeout=args.timeout).run(target)
        except Exception as exc:  # un módulo roto no debe tumbar el resto
            result = ModuleResult(
                module=name, target=target, error=f"{type(exc).__name__}: {exc}"
            )
        status = "ERROR" if result.error else f"{len(result.findings)} hallazgos"
        print(f"{status} ({time.monotonic() - started:.1f}s)", file=sys.stderr)
        results.append(result)

    report = Report(target=target, results=results)
    print_summary(report, color)

    out_dir = Path(args.output_dir)
    default_dir = Path.home() / "osint-reports"
    created = not out_dir.exists()
    out_dir.mkdir(parents=True, exist_ok=True)
    if created or out_dir == default_dir:
        out_dir.chmod(0o700)  # los reportes contienen datos sensibles del objetivo
    stamp = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
    renderers = {"json": render_json, "md": render_markdown}
    print()
    for fmt in formats:
        path = out_dir / f"{target}_{stamp}.{fmt}"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(renderers[fmt](report))
        print(f"[+] Reporte: {path.resolve()}")

    for r in results:
        if r.error:
            print(f"[!] {r.module}: {r.error}", file=sys.stderr)
    return 1 if all(r.error for r in results) else 0
