import io
import json
import zipfile
from datetime import datetime, timezone

import pytest

from osint_tool import net
from osint_tool.cli import main
from osint_tool.models import Severity
from osint_tool.modules.headers import HeadersModule, analyze_headers
from osint_tool.modules.metadata import MetadataModule, analyze_doc, office_metadata
from osint_tool.modules.subdomains import SubdomainsModule, parse_crtsh, sensitive_label
from osint_tool.modules.whois import WhoisModule, analyze, parse_rdap


def resp(url="https://x.com/", status=200, headers=None, body=b"", cookies=()):
    return net.Response(
        url=url,
        status=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        set_cookies=list(cookies),
        body=body,
    )


def titles(findings):
    return [f.title for f in findings]


# --- headers ---------------------------------------------------------------


def test_headers_flags_missing_protections():
    found = titles(analyze_headers({}, [], https_ok=True, http_redirects_to_https=True))
    assert "Falta cabecera HSTS" in found
    assert "Falta Content-Security-Policy" in found


def test_headers_clean_site_has_no_medium_or_above():
    h = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }
    assert analyze_headers(h, [], True, True) == []


def test_headers_version_leak_and_cookies():
    found = analyze_headers(
        {"server": "Apache/2.4.41"}, ["sid=1; Path=/"], True, True
    )
    t = titles(found)
    assert any("revela versión" in x for x in t)
    assert any("sin atributo Secure" in x for x in t)
    assert any("sin atributo HttpOnly" in x for x in t)


def test_headers_no_https_is_high():
    (high,) = [
        f
        for f in analyze_headers({}, [], https_ok=False, http_redirects_to_https=None)
        if f.severity == Severity.HIGH
    ]
    assert "HTTPS" in high.title


def test_headers_module_detects_missing_redirect():
    def fake(url, **kw):
        if url.startswith("http://"):
            return resp(url, 200)  # sirve contenido en claro
        return resp(url, headers={"Server": "nginx"})

    result = HeadersModule(fetch=fake).run("x.com")
    assert "HTTP no redirige a HTTPS" in titles(result.findings)


def test_headers_module_falls_back_to_http_then_errors():
    def fake(url, **kw):
        raise net.HttpError("down")

    assert HeadersModule(fetch=fake).run("x.com").error


# --- subdomains --------------------------------------------------------------

CRT = json.dumps(
    [
        {"name_value": "example.com\n*.example.com"},
        {"name_value": "dev.example.com"},
        {"name_value": "www.example.com\nOLD.example.com"},
        {"name_value": "evil.com"},
    ]
)


def test_parse_crtsh_filters_and_dedupes():
    assert parse_crtsh(CRT, "example.com") == {
        "example.com",
        "dev.example.com",
        "www.example.com",
        "old.example.com",
    }


def test_sensitive_label():
    assert sensitive_label("api-staging.example.com", "example.com") == "staging"
    assert sensitive_label("www.example.com", "example.com") is None
    assert sensitive_label("example.com", "example.com") is None


def test_subdomains_module():
    def fetch(url, **kw):
        return resp(url, body=CRT.encode())

    def resolve(name):
        return ["192.0.2.7"] if name.startswith(("dev", "www")) else []

    result = SubdomainsModule(fetch=fetch, resolve=resolve).run("www.example.com")
    assert result.data["base_domain"] == "example.com"
    assert result.data["total"] == 3
    by_title = {f.title: f for f in result.findings}
    assert by_title["Subdominio de entorno interno: dev.example.com"].severity == Severity.MEDIUM
    assert by_title["Subdominio de entorno interno: old.example.com"].severity == Severity.INFO


def test_subdomains_falls_back_to_certspotter(monkeypatch):
    spotter = json.dumps([{"dns_names": ["staging.example.com", "*.example.com"]}])

    def fetch(url, **kw):
        if "crt.sh" in url:
            return resp(url, status=502)
        return resp(url, body=spotter.encode())

    monkeypatch.setattr("osint_tool.modules.subdomains.time.sleep", lambda s: None)
    result = SubdomainsModule(fetch=fetch, resolve=lambda n: []).run("example.com")
    assert result.error is None
    assert result.data["source"] == "certspotter"
    assert result.data["total"] == 1


def test_subdomains_reports_crtsh_failure(monkeypatch):
    def fetch(url, **kw):
        return resp(url, status=502, body=b"bad gateway")

    monkeypatch.setattr("osint_tool.modules.subdomains.time.sleep", lambda s: None)
    assert SubdomainsModule(fetch=fetch).run("example.com").error


# --- whois / cert ------------------------------------------------------------

RDAP = {
    "events": [
        {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-11-01T00:00:00Z"},
    ],
    "status": ["active"],
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "RegCo"]]]}
    ],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
}
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


def test_parse_rdap():
    p = parse_rdap(RDAP)
    assert p["registrar"] == "RegCo"
    assert p["nameservers"] == ["ns1.example.com"]


def test_expiring_domain_and_cert():
    cert = {"verified": True, "not_after": "2026-10-15T00:00:00+00:00"}
    found = analyze(parse_rdap(RDAP), cert, NOW)
    by = {f.title: f.severity for f in found}
    assert by["El dominio expira en 22 días"] == Severity.HIGH
    assert by["Certificado TLS caduca pronto"] == Severity.HIGH


def test_invalid_cert_is_high():
    found = analyze(None, {"verified": False, "verify_error": "expired"}, NOW)
    assert found[0].severity == Severity.HIGH


def test_whois_module_survives_partial_failure():
    def fetch(url, **kw):
        return resp(url, body=json.dumps(RDAP).encode())

    def bad_cert(host, timeout):
        raise net.HttpError("no 443")

    result = WhoisModule(fetch=fetch, cert_fetcher=bad_cert, now=NOW).run("example.com")
    assert result.error is None
    assert result.data["certificate"] is None
    assert result.data["errors"]


# --- metadata ----------------------------------------------------------------


def make_pdf(**meta):
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(100, 100)
    w.add_metadata(meta)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def make_docx(creator, last_by):
    buf = io.BytesIO()
    core = (
        '<cp:coreProperties xmlns:cp="http://x/cp" xmlns:dc="http://x/dc">'
        f"<dc:creator>{creator}</dc:creator><cp:lastModifiedBy>{last_by}</cp:lastModifiedBy>"
        "</cp:coreProperties>"
    )
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docProps/core.xml", core)
    return buf.getvalue()


def test_office_metadata_and_findings():
    meta = office_metadata(make_docx("jperez", r"C:\Users\jperez\Desktop"))
    assert meta["creator"] == "jperez"
    t = titles(analyze_doc("https://x.com/a.docx", meta))
    assert any("autores" in x for x in t)
    assert any("rutas internas" in x for x in t)


def test_metadata_module_end_to_end():
    home = b'<a href="/docs/informe.pdf">pdf</a><a href="/about">about</a><a href="https://otro.com/x.pdf">x</a>'
    pdf = make_pdf(**{"/Author": "Maria Lopez", "/Producer": "Word 2016"})

    def fetch(url, **kw):
        if url.endswith("informe.pdf"):
            return resp(url, headers={"content-type": "application/pdf"}, body=pdf)
        if url.endswith("/about"):
            return resp(url, headers={"content-type": "text/html"}, body=b"<p>hi</p>")
        return resp(url, headers={"content-type": "text/html"}, body=home)

    result = MetadataModule(fetch=fetch).run("x.com")
    assert result.data["documents_found"] == 1  # el PDF de otro host se ignora
    (finding,) = result.findings
    assert "Maria Lopez" in finding.evidence


# --- CLI ----------------------------------------------------------------------


def test_cli_rejects_bad_target(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["no es un dominio"])
    assert exc.value.code == 2
    assert "no parece" in capsys.readouterr().err


def test_cli_accepts_full_url_with_port_and_path(tmp_path, monkeypatch, capsys):
    from osint_tool import registry
    from osint_tool.models import ModuleResult

    class Dummy:
        description = "x"

        def __init__(self, timeout):
            pass

        def run(self, target):
            return ModuleResult(module="dummy", target=target)

    monkeypatch.setattr(registry, "available", lambda: {"dummy": Dummy})
    monkeypatch.setattr(registry, "get", lambda n: Dummy)
    code = main(["https://user:pw@Ejemplo.com:8443/a/b?c=1", "-o", str(tmp_path)])
    assert code == 0
    assert any(p.name.startswith("ejemplo.com_") for p in tmp_path.iterdir())
