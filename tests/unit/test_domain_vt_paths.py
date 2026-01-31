from phishing_analyzer.agents.domain_agent import DomainAgent


class DummyWhois:
    def lookup_age_days(self, d):
        return 5


class DummyVTBad:
    def enabled(self):
        return True
    def check_domain(self, d):
        return {"status": "enabled", "malicious": 4}


def test_domain_vt_malicious():
    out = DomainAgent().run(
        whois_tool=DummyWhois(),
        vt_tool=DummyVTBad(),
        domain="bad.com",
    )

    assert out.risk > 0
    assert out.vt_status == "enabled"
    assert any("VirusTotal" in i for i in out.indicators)
