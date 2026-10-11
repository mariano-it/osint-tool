"""Un test por cada bug confirmado en la revisión de código."""

import json
import os
import shutil
import ssl
import stat
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from osint_tool import net
from osint_tool.models import Severity
from osint_tool.modules.dns_records import (
    DnsError,
    DnspythonClient,
    analyze_spf,
)
from osint_tool.modules.headers import HeadersModule, analyze_headers
from osint_tool.modules.metadata import MetadataModule
from osint_tool.modules.subdomains import make_resolver
from osint_tool.modules.whois import WhoisModule, fetch_tls_cert, registrable_domain


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


# --- 1. alcance: no salir del dominio autorizado -----------------------------


def test_metadata_does_not_crawl_third_party_after_redirect():
    requested = []

    def fetch(url, **kw):
        requested.append(url)
        if url == "https://x.com/":
            return resp(
                "https://tercero.com/",
                headers={"content-type": "text/html"},
                body=b'<a href="/doc.pdf">d</a>',
            )
        raise AssertionError(f"petición fuera de alcance: {url}")

    result = MetadataModule(fetch=fetch).run("x.com")
    assert requested == ["https://x.com/"]
    assert result.data["documents_found"] == 0
    assert any("fuera del alcance" in t for t in titles(result.findings))


def test_metadata_ignores_subpage_that_redirects_out_of_scope():
    requested = []

    def fetch(url, **kw):
        requested.append(url)
        if url == "https://x.com/":
            return resp(
                url, headers={"content-type": "text/html"}, body=b'<a href="/about">a</a>'
            )
        if url.endswith("/about"):
            return resp(
                "https://tercero.com/about",
                headers={"content-type": "text/html"},
                body=b'<a href="/leak.pdf">p</a>',
            )
        raise AssertionError(f"petición inesperada: {url}")

    result = MetadataModule(fetch=fetch).run("x.com")
    assert result.data["documents_found"] == 0
    assert not any("tercero.com/leak" in u for u in requested)


def test_metadata_allows_www_and_subdomain_redirects():
    def fetch(url, **kw):
        return resp(
            "https://www.x.com/", headers={"content-type": "text/html"}, body=b"<p></p>"
        )

    result = MetadataModule(fetch=fetch).run("x.com")
    assert not any("fuera del alcance" in t for t in titles(result.findings))


def test_headers_do_not_attribute_third_party_headers_to_target():
    def fetch(url, **kw):
        return resp("https://tercero.com/", headers={"Server": "nginx/1.2.3"})

    result = HeadersModule(fetch=fetch).run("x.com")
    found = titles(result.findings)
    assert any("fuera del alcance" in t for t in found)
    assert "Falta cabecera HSTS" not in found  # no se evalúa al tercero


# --- 2. cookies: atributos exactos, no subcadenas del nombre -----------------


def test_cookie_named_secure_still_flagged_without_secure_attr():
    found = titles(
        analyze_headers({}, ["session_secure=abc; Path=/; HttpOnly"], True, True)
    )
    assert "Cookie 'session_secure' sin atributo Secure" in found


def test_cookie_named_httponly_still_flagged_without_httponly_attr():
    found = titles(analyze_headers({}, ["httponly_id=1; Secure"], True, True))
    assert "Cookie 'httponly_id' sin atributo HttpOnly" in found


def test_cookie_with_real_attrs_is_not_flagged():
    found = titles(analyze_headers({}, ["sid=1; Path=/; Secure; HttpOnly"], True, True))
    assert not any("Cookie" in t for t in found)


# --- 3. SPF con redirect= ----------------------------------------------------


def test_spf_redirect_modifier_is_valid_without_all():
    assert analyze_spf(["v=spf1 redirect=_spf.ejemplo.com"], True) == []


def test_spf_without_all_or_redirect_still_flagged():
    (f,) = analyze_spf(["v=spf1 mx"], True)
    assert "sin mecanismo 'all'" in f.title


# --- 4. SPF: conteo de consultas DNS por token ---------------------------------


def test_spf_lookup_count_ignores_a_and_mx_inside_names():
    record = "v=spf1 " + " ".join(
        f"include:_spf{i}.a.com" if i % 2 else f"include:_spf{i}.mx.com"
        for i in range(8)
    ) + " -all"
    assert analyze_spf([record], True) == []  # 8 lookups reales < 10


def test_spf_over_ten_lookups_flagged():
    record = "v=spf1 " + " ".join(f"include:s{i}.ejemplo.com" for i in range(11)) + " -all"
    (f,) = analyze_spf([record], True)
    assert f.severity == Severity.LOW
    assert "11" in f.description


def test_spf_counts_a_mx_mechanisms_with_qualifiers():
    record = "v=spf1 a mx:mail.x.com +a:b.x.com ~ptr exists:%{i}.x.com include:i.com " \
             "include:j.com include:k.com include:l.com include:m.com include:n.com -all"
    (f,) = analyze_spf([record], True)
    assert "11" in f.description


# --- 5. net.fetch ------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.send_header("Set-Cookie", "a=1")
            self.send_header("Set-Cookie", "b=2")
            self.end_headers()
            self.wfile.write(b"x" * 100_000)
        elif self.path == "/missing":
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class _QuietServer(HTTPServer):
    def handle_error(self, request, client_address):  # handshakes TLS fallidos a propósito
        pass


@pytest.fixture
def http_server():
    server = _QuietServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_fetch_follows_redirects_by_default(http_server):
    r = net.fetch(http_server + "/redir")
    assert (r.status, r.body, r.url) == (200, b"ok", http_server + "/ok")


def test_fetch_no_redirect_returns_3xx_with_location(http_server):
    r = net.fetch(http_server + "/redir", follow_redirects=False)
    assert r.status == 302
    assert r.headers["location"] == "/ok"


def test_fetch_caps_body_and_collects_cookies(http_server):
    r = net.fetch(http_server + "/big", max_bytes=1000)
    assert len(r.body) == 1000
    assert r.set_cookies == ["a=1", "b=2"]


def test_fetch_returns_4xx_instead_of_raising(http_server):
    assert net.fetch(http_server + "/missing").status == 404


def test_fetch_raises_httperror_on_connection_refused():
    with pytest.raises(net.HttpError):
        net.fetch("http://127.0.0.1:1/", timeout=2)


# --- 6. TLS -------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("openssl") is None, reason="requiere openssl")
class TestTls:
    @pytest.fixture
    def tls_server(self, tmp_path):
        cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "2",
                "-subj", "/CN=localhost/O=Pruebas",
                "-addext", "subjectAltName=DNS:localhost",
            ],
            check=True, capture_output=True,
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server = _QuietServer(("127.0.0.1", 0), _Handler)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

        def serve():
            while True:
                try:
                    server.handle_request()
                except Exception:
                    return

        threading.Thread(target=serve, daemon=True).start()
        yield server.server_port, cert
        server.socket.close()

    def test_untrusted_self_signed_cert_is_reported_not_raised(self, tls_server, monkeypatch):
        port, _ = tls_server
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        out = fetch_tls_cert("localhost", 5, port=port)
        assert out["verified"] is False
        assert out["verify_error"]

    def test_trusted_cert_returns_details(self, tls_server, monkeypatch):
        port, cert = tls_server
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))
        out = fetch_tls_cert("localhost", 5, port=port)
        assert out["verified"] is True
        assert out["subject"] == "localhost"
        assert out["issuer"] == "Pruebas"
        assert out["san"] == ["localhost"]
        assert out["tls_version"].startswith("TLS")

    def test_connection_failure_raises_httperror(self):
        with pytest.raises(net.HttpError):
            fetch_tls_cert("127.0.0.1", 2, port=1)


# --- 7. DnspythonClient ------------------------------------------------------


class _Rdata:
    def __init__(self, text=None, strings=None):
        self._text, self.strings = text, strings

    def to_text(self):
        return self._text


def _client_with(monkeypatch, behavior):
    client = DnspythonClient(timeout=1)
    monkeypatch.setattr(client._resolver, "resolve", behavior)
    return client


def test_dnspython_client_nxdomain_and_noanswer_are_empty(monkeypatch):
    import dns.resolver

    for exc in (dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()):
        def boom(name, rtype, exc=exc):
            raise exc

        assert _client_with(monkeypatch, boom).query("x.com", "A") == []


def test_dnspython_client_timeout_and_servfail_raise(monkeypatch):
    import dns.exception
    import dns.resolver

    for exc in (dns.exception.Timeout(), dns.resolver.NoNameservers()):
        def boom(name, rtype, exc=exc):
            raise exc

        with pytest.raises(DnsError):
            _client_with(monkeypatch, boom).query("x.com", "A")


def test_dnspython_client_joins_split_txt_strings(monkeypatch):
    answer = [_Rdata(strings=[b"v=spf1 ", b"include:x.com -all"])]
    client = _client_with(monkeypatch, lambda n, t: answer)
    assert client.query("x.com", "TXT") == ["v=spf1 include:x.com -all"]


def test_dnspython_client_uses_to_text_for_other_types(monkeypatch):
    client = _client_with(monkeypatch, lambda n, t: [_Rdata("192.0.2.1")])
    assert client.query("x.com", "A") == ["192.0.2.1"]


# --- 8. resolución con timeout y whois con Public Suffix List ------------------


class _FakeDns:
    def __init__(self):
        self.calls = []

    def query(self, name, rtype):
        self.calls.append((name, rtype))
        if rtype == "A":
            return ["192.0.2.1"] if name == "ok.x.com" else []
        if rtype == "AAAA":
            return ["2001:db8::1"] if name == "v6.x.com" else []
        raise DnsError("fallo")


def test_make_resolver_uses_dns_client_and_falls_back_to_aaaa():
    resolve = make_resolver(client=_FakeDns())
    assert resolve("ok.x.com") == ["192.0.2.1"]
    assert resolve("v6.x.com") == ["2001:db8::1"]
    assert resolve("none.x.com") == []


def test_make_resolver_swallows_dns_errors():
    class Broken:
        def query(self, name, rtype):
            raise DnsError("servfail")

    assert make_resolver(client=Broken())("a.x.com") == []


@pytest.mark.parametrize(
    "host,expected",
    [
        ("www.ejemplo.com", "ejemplo.com"),
        ("x.co.uk", "x.co.uk"),
        ("a.b.x.co.uk", "x.co.uk"),
        ("ejemplo.com.mx", "ejemplo.com.mx"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_whois_queries_registrable_domain_not_public_suffix():
    queried = []

    def fetch(url, **kw):
        queried.append(url)
        return resp(url, body=json.dumps({"events": []}).encode())

    def cert(host, timeout):
        raise net.HttpError("sin 443")

    WhoisModule(fetch=fetch, cert_fetcher=cert).run("www.x.co.uk")
    assert queried == ["https://rdap.org/domain/x.co.uk"]


# --- 9. CLI: códigos de salida y permisos ------------------------------------


@pytest.fixture
def fake_modules(monkeypatch):
    from osint_tool import registry
    from osint_tool.models import ModuleResult

    class Good:
        description = "ok"

        def __init__(self, timeout):
            pass

        def run(self, target):
            return ModuleResult(module="good", target=target)

    class Bad(Good):
        def run(self, target):
            return ModuleResult(module="bad", target=target, error="caído")

    class Boom(Good):
        def run(self, target):
            raise RuntimeError("bug")

    table = {"good": Good, "bad": Bad, "boom": Boom}
    monkeypatch.setattr(registry, "available", lambda: dict(table))
    monkeypatch.setattr(registry, "get", lambda n: table[n])
    return table


def test_cli_exit_0_when_a_module_works(fake_modules, tmp_path):
    from osint_tool.cli import main

    assert main(["x.com", "-m", "good,bad", "-o", str(tmp_path)]) == 0


def test_cli_exit_1_when_all_modules_fail(fake_modules, tmp_path):
    from osint_tool.cli import main

    assert main(["x.com", "-m", "bad,boom", "-o", str(tmp_path)]) == 1


def test_cli_survives_module_exception(fake_modules, tmp_path, capsys):
    from osint_tool.cli import main

    assert main(["x.com", "-m", "boom,good", "-o", str(tmp_path)]) == 0
    assert "RuntimeError" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["no es dominio"],
        ["x.com", "-m", "inexistente"],
        ["x.com", "-f", "pdf"],
    ],
)
def test_cli_exit_2_on_bad_arguments(fake_modules, argv):
    from osint_tool.cli import main

    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_reports_are_private(fake_modules, tmp_path):
    from osint_tool.cli import main

    out = tmp_path / "nuevo" / "reportes"
    main(["x.com", "-m", "good", "-o", str(out)])
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for f in out.iterdir():
        assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_default_output_dir_is_forced_private(fake_modules, tmp_path, monkeypatch):
    from pathlib import Path

    from osint_tool.cli import main

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    default = tmp_path / "osint-reports"
    default.mkdir(mode=0o755)
    os.chmod(default, 0o755)
    main(["x.com", "-m", "good"])
    assert stat.S_IMODE(default.stat().st_mode) == 0o700
