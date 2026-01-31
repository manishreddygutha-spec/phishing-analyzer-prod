from phishing_analyzer.agents.reporter_agent import build_json_report

class Dummy:
    def __init__(self):
        self.anomalies = []
        self.indicators = []
        self.age_days = 100
        self.vt_status = "not_configured"

class DummyEmail:
    from_email = "a@b.com"
    from_domain = "b.com"

def test_report_structure():
    report = build_json_report(
        DummyEmail(),
        Dummy(),
        Dummy(),
        Dummy(),
        Dummy(),
        Dummy(),
        {"score": 0, "severity": "Info", "action": "Allow"}
    )

    assert "risk" in report
    assert "findings" in report
    assert "urls" in report["findings"]
    assert "attachments" in report["findings"]
