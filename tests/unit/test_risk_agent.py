from phishing_analyzer.agents.risk_agent import RiskAgent
from phishing_analyzer.config.risk_config import RiskConfig

class Dummy:
    def __init__(self, risk):
        self.risk = risk

def test_risk_agent_quarantine_high_risk():
    cfg = RiskConfig()
    agent = RiskAgent()

    h = Dummy(100)
    c = Dummy(100)
    d = Dummy(100)
    url = Dummy(100)
    att = Dummy(100)

    out = agent.run(h, c, d, url, att, cfg)
    assert out["action"] == "Quarantine"

def test_risk_agent_allow():
    cfg = RiskConfig()
    agent = RiskAgent()

    h = Dummy(0)
    c = Dummy(0)
    d = Dummy(0)
    url = Dummy(0)
    att = Dummy(0)

    out = agent.run(h, c, d, url, att, cfg)
    assert out["action"] == "Allow"
