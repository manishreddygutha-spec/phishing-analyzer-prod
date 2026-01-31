from phishing_analyzer.tools.virustotal_tool import VirusTotalTool


class DummyResp:
    def __init__(self, code):
        self.status_code = code
    def json(self):
        return {}


def test_vt_domain_rate_limited(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "x")
    monkeypatch.setattr("requests.get", lambda *a, **k: DummyResp(429))

    vt = VirusTotalTool()
    res = vt.check_domain("example.com")
    assert res["status"] == "rate_limited"


def test_vt_domain_error(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "x")
    monkeypatch.setattr("requests.get", lambda *a, **k: DummyResp(500))

    vt = VirusTotalTool()
    res = vt.check_domain("example.com")
    assert res["status"] == "error"


def test_vt_file_hash_clean(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "x")
    monkeypatch.setattr("requests.get", lambda *a, **k: DummyResp(404))

    vt = VirusTotalTool()
    res = vt.check_file_hash("hash")
    assert res["status"] == "enabled"
    assert res["malicious"] == 0
