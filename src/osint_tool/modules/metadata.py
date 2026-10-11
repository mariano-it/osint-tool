"""Módulo metadata: metadatos de documentos públicos enlazados desde el sitio.

Rastrea la portada y unas pocas páginas internas del mismo host, descarga
(con límites) PDF/Office enlazados y lee sus metadatos.
"""

from __future__ import annotations

import io
import re
import zipfile
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urldefrag, urljoin, urlparse
from xml.etree import ElementTree

from osint_tool import net
from osint_tool.models import Finding, ModuleResult, Severity
from osint_tool.modules.base import Module
from osint_tool.registry import register
from osint_tool.target import in_scope

DOC_EXT = (".pdf", ".docx", ".xlsx", ".pptx")
MAX_PAGES = 8
MAX_DOCS = 10
MAX_DOC_BYTES = 10_000_000

_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\[\w.-]+\\|/home/|/Users/|/var/|/srv/)[^\s\"']*")


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.links.append(v)


def extract_links(html: str, base_url: str) -> list[str]:
    parser = _Links()
    parser.feed(html)
    return [urldefrag(urljoin(base_url, href))[0] for href in parser.links]


def _looks_like_page(path: str) -> bool:
    """Ruta sin extensión (/about) o .html/.htm; descarta imágenes, zips, etc."""
    last = path.rsplit("/", 1)[-1].lower()
    return "." not in last or last.endswith((".html", ".htm"))


def pdf_metadata(body: bytes) -> dict[str, str]:
    from pypdf import PdfReader

    meta = PdfReader(io.BytesIO(body)).metadata or {}
    return {str(k).lstrip("/"): str(v) for k, v in meta.items() if v}


def office_metadata(body: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        for part in ("docProps/core.xml", "docProps/app.xml"):
            if part in z.namelist():
                root = ElementTree.fromstring(z.read(part))
                for el in root:
                    tag = el.tag.rsplit("}", 1)[-1]
                    if el.text and el.text.strip():
                        out[tag] = el.text.strip()
    return out


def analyze_doc(url: str, meta: dict[str, str]) -> list[Finding]:
    f: list[Finding] = []
    people = {
        k: v
        for k, v in meta.items()
        if k in ("Author", "creator", "lastModifiedBy", "Manager", "Company")
        and v.strip()
    }
    if people:
        f.append(
            Finding(
                title=f"El documento revela autores/usuarios: {url.rsplit('/', 1)[-1]}",
                severity=Severity.LOW,
                description=(
                    "Los nombres de autor sirven para ingeniería social y para "
                    "deducir convenciones de nombres de usuario."
                ),
                evidence="; ".join(f"{k}={v}" for k, v in people.items()),
                remediation="Limpiar metadatos antes de publicar (exiftool, 'Inspeccionar documento').",
            )
        )
    paths = {m for v in meta.values() for m in _PATH_RE.findall(v)}
    if paths:
        f.append(
            Finding(
                title=f"El documento filtra rutas internas: {url.rsplit('/', 1)[-1]}",
                severity=Severity.MEDIUM,
                description="Rutas de archivos o recursos de red internos en los metadatos.",
                evidence="; ".join(sorted(paths)),
                remediation="Eliminar metadatos y revisar el flujo de exportación.",
            )
        )
    return f


@register
class MetadataModule(Module):
    name = "metadata"
    description = "Metadatos de PDF/Office públicos enlazados desde el sitio"

    def __init__(
        self, timeout: float = 5.0, fetch: Callable[..., net.Response] | None = None
    ):
        super().__init__(timeout=timeout)
        self._fetch = fetch or net.fetch

    def _get(self, url: str, max_bytes: int, scope: str) -> net.Response | None:
        """GET limitado; descarta la respuesta si tras redirecciones sale del alcance."""
        try:
            resp = self._fetch(url, timeout=self.timeout * 2, max_bytes=max_bytes)
        except net.HttpError:
            return None
        if not in_scope(urlparse(resp.url).hostname or "", scope):
            return None
        return resp

    def run(self, target: str) -> ModuleResult:
        result = ModuleResult(module=self.name, target=target)
        try:
            home = self._fetch(
                f"https://{target}/", timeout=self.timeout * 2, max_bytes=2_000_000
            )
        except net.HttpError:
            try:
                home = self._fetch(
                    f"http://{target}/", timeout=self.timeout * 2, max_bytes=2_000_000
                )
            except net.HttpError:
                result.error = f"no se pudo abrir https://{target}/"
                return result

        final_host = urlparse(home.url).hostname or ""
        if not in_scope(final_host, target):
            result.data = {
                "pages_crawled": 0,
                "documents_found": 0,
                "documents_analyzed": [],
                "out_of_scope": home.url,
            }
            result.findings.append(
                Finding(
                    title=f"Redirige fuera del alcance: {final_host}",
                    severity=Severity.INFO,
                    description=(
                        f"{target} redirige a otro dominio; no se rastreó ni "
                        "se descargó nada de ese tercero."
                    ),
                    evidence=home.url,
                    remediation=(
                        f"Si {final_host} también es tuyo/autorizado, "
                        "audítalo por separado."
                    ),
                )
            )
            return result

        host = urlparse(home.url).netloc.lower()
        pages = [home.url]
        docs: list[str] = []
        queue = [home]
        seen = {home.url}
        while queue:
            page = queue.pop(0)
            html = page.body.decode("utf-8", "replace")
            for link in extract_links(html, page.url):
                parsed = urlparse(link)
                if parsed.scheme not in ("http", "https") or parsed.netloc.lower() != host:
                    continue
                if parsed.path.lower().endswith(DOC_EXT):
                    if link not in docs:
                        docs.append(link)
                elif (
                    link not in seen
                    and len(pages) < MAX_PAGES
                    and _looks_like_page(parsed.path)
                ):
                    seen.add(link)
                    sub = self._get(link, 2_000_000, target)
                    if sub is not None and "html" in sub.headers.get("content-type", ""):
                        pages.append(link)
                        queue.append(sub)

        analyzed = []
        for url in docs[:MAX_DOCS]:
            resp = self._get(url, MAX_DOC_BYTES, target)
            if resp is None or resp.status != 200:
                continue
            try:
                meta = (
                    pdf_metadata(resp.body)
                    if url.lower().split("?")[0].endswith(".pdf")
                    else office_metadata(resp.body)
                )
            except Exception as exc:  # documento corrupto/cifrado: no es fatal
                analyzed.append({"url": url, "error": str(exc)[:120], "metadata": {}})
                continue
            analyzed.append({"url": url, "metadata": meta})
            result.findings += analyze_doc(url, meta)

        result.data = {
            "pages_crawled": len(pages),
            "documents_found": len(docs),
            "documents_analyzed": analyzed,
        }
        return result
