from phishing_analyzer.agents.url_agent import URLAnalyzerAgent
from phishing_analyzer.tools.url_tool import URLTool
from phishing_analyzer.tools.virustotal_tool import VirusTotalTool

def test_clean_url_no_risk(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    urls = ["https://www.example.com/about"]
    out = URLAnalyzerAgent().run(urls, URLTool(), VirusTotalTool())

    assert out.risk == 0
    assert out.indicators == []
