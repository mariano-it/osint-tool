"""Módulo headers: tecnología expuesta y cabeceras de seguridad faltantes.

Hace una petición GET a la portada (y una a http:// sin seguir redirecciones
para comprobar el salto a HTTPS), como cualquier navegador.
"""

from __future__ import annotations

import re
from typing import Callable
from urllib.parse import urlparse

from osint_tool import net
from osint_tool.models import Finding, ModuleResult, Severity
from osint_tool.modules.base import Module
from osint_tool.registry import register
from osint_tool.target import in_scope

Fetch = Callable[..., net.Response]

_VERSIONED = re.compile(r"\d+\.\d+")


def analyze_headers(
    h: dict[str, str],
    cookies: list[str],
    https_ok: bool,
    http_redirects_to_https: bool | None,
) -> list[Finding]:
    f: list[Finding] = []

    def add(title, sev, desc, fix, evidence=""):
        f.append(Finding(title, sev, desc, fix, evidence))

    if not https_ok:
        add(
            "El sitio no responde por HTTPS",
            Severity.HIGH,
            "El tráfico viaja en claro y es interceptable/modificable.",
            "Instalar un certificado (p. ej. Let's Encrypt) y servir por HTTPS.",
        )
    else:
        hsts = h.get("strict-transport-security")
        if not hsts:
            add(
                "Falta cabecera HSTS",
                Severity.MEDIUM,
                "Sin HSTS el navegador puede ser degradado a HTTP (SSL stripping).",
                'Añadir "Strict-Transport-Security: max-age=31536000; includeSubDomains".',
            )
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if m and int(m.group(1)) < 15_552_000:
                add(
                    "HSTS con max-age corto",
                    Severity.LOW,
                    "Menos de 180 días reduce la protección real.",
                    "Subir max-age a 31536000 (1 año).",
                    hsts,
                )

    if http_redirects_to_https is False:
        add(
            "HTTP no redirige a HTTPS",
            Severity.MEDIUM,
            "La versión http:// del sitio sirve contenido o no fuerza HTTPS.",
            "Configurar redirección 301 de http:// a https://.",
        )

    csp = h.get("content-security-policy")
    if not csp:
        add(
            "Falta Content-Security-Policy",
            Severity.MEDIUM,
            "Sin CSP, un XSS tiene vía libre para cargar scripts arbitrarios.",
            "Definir una CSP restrictiva (empezar con Report-Only).",
        )

    if h.get("x-content-type-options", "").lower() != "nosniff":
        add(
            "Falta X-Content-Type-Options: nosniff",
            Severity.LOW,
            "El navegador puede adivinar tipos MIME y ejecutar contenido inesperado.",
            'Añadir "X-Content-Type-Options: nosniff".',
        )

    if "x-frame-options" not in h and "frame-ancestors" not in (csp or "").lower():
        add(
            "Sin protección contra clickjacking",
            Severity.LOW,
            "El sitio puede incrustarse en iframes de terceros.",
            'Añadir "X-Frame-Options: DENY" o CSP "frame-ancestors \'none\'".',
        )

    if "referrer-policy" not in h:
        add(
            "Falta Referrer-Policy",
            Severity.LOW,
            "URLs internas pueden filtrarse en la cabecera Referer.",
            'Añadir "Referrer-Policy: strict-origin-when-cross-origin".',
        )

    if "permissions-policy" not in h:
        add(
            "Falta Permissions-Policy",
            Severity.INFO,
            "No se restringen APIs del navegador (cámara, geolocalización...).",
            "Definir Permissions-Policy con solo lo necesario.",
        )

    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        value = h.get(name)
        if value and _VERSIONED.search(value):
            add(
                f"Cabecera {name} revela versión de software",
                Severity.LOW,
                "Facilita buscar vulnerabilidades conocidas de esa versión.",
                f"Ocultar o genericar la cabecera {name} en el servidor/proxy.",
                f"{name}: {value}",
            )
        elif value and name != "server":
            add(
                f"Cabecera {name} expone tecnología",
                Severity.INFO,
                "Revela el stack usado.",
                f"Eliminar la cabecera {name}.",
                f"{name}: {value}",
            )

    for raw in cookies:
        # Atributos exactos tras el primer ';' (no subcadenas del nombre/valor).
        name_value, *attr_parts = (p.strip() for p in raw.split(";"))
        name = name_value.split("=", 1)[0].strip()
        attrs = {a.split("=", 1)[0].strip().lower() for a in attr_parts}
        if https_ok and "secure" not in attrs:
            add(
                f"Cookie '{name}' sin atributo Secure",
                Severity.MEDIUM,
                "Puede enviarse por HTTP en claro.",
                "Añadir el atributo Secure.",
                name,
            )
        if "httponly" not in attrs:
            add(
                f"Cookie '{name}' sin atributo HttpOnly",
                Severity.LOW,
                "Accesible desde JavaScript (riesgo ante XSS).",
                "Añadir HttpOnly si no necesita leerse desde JS.",
                name,
            )
    return f


@register
class HeadersModule(Module):
    name = "headers"
    description = "Cabeceras HTTP, tecnología expuesta, HSTS/CSP, cookies"

    def __init__(self, timeout: float = 5.0, fetch: Fetch | None = None):
        super().__init__(timeout=timeout)
        self._fetch = fetch or net.fetch

    def run(self, target: str) -> ModuleResult:
        result = ModuleResult(module=self.name, target=target)
        https_ok = True
        try:
            resp = self._fetch(f"https://{target}/", timeout=self.timeout)
        except net.HttpError as https_err:
            https_ok = False
            try:
                resp = self._fetch(f"http://{target}/", timeout=self.timeout)
            except net.HttpError:
                result.error = str(https_err)
                return result

        final_host = urlparse(resp.url).hostname or ""
        if not in_scope(final_host, target):
            # Las cabeceras de un tercero no son del objetivo autorizado.
            result.data = {
                "final_url": resp.url,
                "status": resp.status,
                "https": https_ok,
                "out_of_scope": True,
            }
            result.findings = [
                Finding(
                    title=f"Redirige fuera del alcance: {final_host}",
                    severity=Severity.INFO,
                    description=(
                        f"{target} redirige a un dominio distinto; no se "
                        "evaluaron sus cabeceras para no auditar a un tercero."
                    ),
                    evidence=resp.url,
                    remediation=(
                        f"Si {final_host} también es tuyo/autorizado, "
                        "audítalo por separado."
                    ),
                )
            ]
            return result

        redirect: bool | None = None
        if https_ok:
            try:
                plain = self._fetch(
                    f"http://{target}/", timeout=self.timeout, follow_redirects=False
                )
                location = plain.headers.get("location", "")
                redirect = 300 <= plain.status < 400 and location.startswith("https://")
            except net.HttpError:
                redirect = None  # puerto 80 cerrado: no es un fallo

        result.data = {
            "final_url": resp.url,
            "status": resp.status,
            "https": https_ok,
            "http_redirects_to_https": redirect,
            "technology": {
                k: resp.headers[k]
                for k in ("server", "x-powered-by", "via", "x-generator")
                if k in resp.headers
            },
            "security_headers": {
                k: resp.headers.get(k)
                for k in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                    "permissions-policy",
                )
            },
        }
        result.findings = analyze_headers(
            resp.headers, resp.set_cookies, https_ok, redirect
        )
        return result
