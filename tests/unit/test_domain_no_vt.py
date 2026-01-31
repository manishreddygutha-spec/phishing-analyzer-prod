from phishing_analyzer.agents.domain_agent import DomainAgent

class DummyWhois:
    def lookup_age_days(self, domain): return 5

class DummyVT:
    def enabled(self): return False

def test_domain_recent_no_vt():
    out = DomainAgent().run(
        whois_tool=DummyWhois(),
        vt_tool=DummyVT(),
        domain="newdomain.com",
        recent_days=30,
    )

    assert out.age_days == 5
    assert out.risk > 0
    assert out.vt_status == "not_configured"
