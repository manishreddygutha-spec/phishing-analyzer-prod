from phishing_analyzer.agents.domain_agent import DomainAgent
from phishing_analyzer.tools.virustotal_tool import VirusTotalTool

class FakeWhois:
    def __init__(self, age):
        self.age = age

    def lookup_age_days(self, domain):
        return self.age

def test_recent_domain_increases_risk(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    whois = FakeWhois(age=5)
    vt = VirusTotalTool()

    out = DomainAgent().run(whois, vt, "example.com", recent_days=30)
    assert out.risk > 0

def test_old_domain_low_risk(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    whois = FakeWhois(age=365)
    vt = VirusTotalTool()

    out = DomainAgent().run(whois, vt, "example.com", recent_days=30)
    assert out.risk == 0
