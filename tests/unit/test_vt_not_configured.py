from phishing_analyzer.tools.virustotal_tool import VirusTotalTool


def test_vt_not_configured_domain(monkeypatch):
    """
    VirusTotal domain check should report not_configured
    when VT_API_KEY is missing.
    """
    monkeypatch.delenv("VT_API_KEY", raising=False)

    vt = VirusTotalTool()
    res = vt.check_domain("example.com")

    assert res["status"] == "not_configured"


def test_vt_not_configured_file_hash(monkeypatch):
    """
    VirusTotal attachment hash check should report not_configured
    when VT_API_KEY is missing.
    """
    monkeypatch.delenv("VT_API_KEY", raising=False)

    vt = VirusTotalTool()
    res = vt.check_file_hash("dummyhash")

    assert res["status"] == "not_configured"


def test_vt_enabled_flag(monkeypatch):
    """
    enabled() should correctly reflect presence of VT_API_KEY.
    """
    monkeypatch.setenv("VT_API_KEY", "fake-key")

    vt = VirusTotalTool()
    assert vt.enabled() is True