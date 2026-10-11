from osint_tool.models import Report, Severity
from osint_tool.modules.dns_records import (
    DnsError,
    DnsModule,
    analyze_dmarc,
    analyze_misc,
    analyze_spf,
)
from osint_tool.report import render_json, render_markdown


class FakeClient:
    def __init__(self, table=None, fail=False, fail_types=()):
        self.table = table or {}
        self.fail = fail
        self.fail_types = fail_types

    def query(self, name, rtype):
        if self.fail or rtype in self.fail_types:
            raise DnsError("boom")
        return self.table.get((name, rtype), [])


def titles(findings):
    return [f.title for f in findings]


def test_spf_missing_is_medium_when_domain_sends_mail():
    (f,) = analyze_spf([], sends_mail=True)
    assert f.severity == Severity.MEDIUM


def test_spf_missing_is_low_when_no_mail():
    (f,) = analyze_spf([], sends_mail=False)
    assert f.severity == Severity.LOW


def test_spf_plus_all_is_high():
    (f,) = analyze_spf(["v=spf1 include:_spf.x.com +all"], True)
    assert f.severity == Severity.HIGH


def test_spf_bare_all_is_high():
    (f,) = analyze_spf(["v=spf1 all"], True)
    assert f.severity == Severity.HIGH


def test_spf_hardfail_has_no_findings():
    assert analyze_spf(["v=spf1 include:_spf.x.com -all"], True) == []


def test_spf_softfail_is_info():
    (f,) = analyze_spf(["v=spf1 mx ~all"], True)
    assert f.severity == Severity.INFO


def test_spf_multiple_records():
    (f,) = analyze_spf(["v=spf1 -all", "v=spf1 mx -all"], True)
    assert "Múltiples" in f.title


def test_dmarc_missing():
    (f,) = analyze_dmarc([], sends_mail=True)
    assert f.severity == Severity.MEDIUM


def test_dmarc_p_none_without_rua():
    found = titles(analyze_dmarc(["v=DMARC1; p=none"], True))
    assert any("p=none" in t for t in found)
    assert any("rua" in t for t in found)


def test_dmarc_reject_with_rua_is_clean():
    assert analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:d@x.com"], True) == []


def test_misc_flags_missing_caa_and_dnssec():
    found = titles(analyze_misc({"CAA": [], "NS": ["a.", "b."]}, has_dnskey=False))
    assert "Sin registros CAA" in found
    assert "DNSSEC no habilitado" in found


def test_module_end_to_end_with_fake_client():
    client = FakeClient(
        {
            ("ejemplo.com", "A"): ["192.0.2.1"],
            ("ejemplo.com", "MX"): ["10 mail.ejemplo.com."],
            ("ejemplo.com", "TXT"): ["v=spf1 +all"],
        }
    )
    result = DnsModule(client=client).run("ejemplo.com")
    assert result.error is None
    assert result.data["records"]["A"] == ["192.0.2.1"]
    severities = {f.severity for f in result.findings}
    assert Severity.HIGH in severities  # +all
    assert any("DMARC" in f.title for f in result.findings)


def test_module_reports_error_on_network_failure():
    result = DnsModule(client=FakeClient(fail=True)).run("ejemplo.com")
    assert result.error == "boom"
    assert result.findings == []


def test_partial_failure_keeps_results_and_skips_unknowns():
    client = FakeClient(
        {("ejemplo.com", "A"): ["192.0.2.1"]}, fail_types=("DNSKEY", "TXT")
    )
    result = DnsModule(client=client).run("ejemplo.com")
    assert result.error is None
    assert result.data["dnssec"] is None
    assert result.data["records"]["A"] == ["192.0.2.1"]
    found = titles(result.findings)
    # TXT (y por tanto _dmarc) y DNSKEY fallaron: no se afirma que falten
    assert "Falta registro SPF" not in found
    assert "Falta registro DMARC" not in found
    assert "DNSSEC no habilitado" not in found
    assert "Sin registros CAA" in found  # CAA sí se consultó bien


def test_reports_render():
    result = DnsModule(client=FakeClient()).run("ejemplo.com")
    report = Report(target="ejemplo.com", results=[result])
    assert '"target": "ejemplo.com"' in render_json(report)
    md = render_markdown(report)
    assert "# Reporte OSINT pasivo: ejemplo.com" in md
    assert "Remediación" in md
