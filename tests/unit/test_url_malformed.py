from phishing_analyzer.agents.url_agent import URLAnalyzerAgent
from phishing_analyzer.tools.url_tool import URLTool

class DummyVT:
    def enabled(self): return False

def test_malformed_url():
    agent = URLAnalyzerAgent()
    urls = ["hxxp://bad[.]url"]

    out = agent.run(urls, URLTool(), DummyVT())

    assert out.risk > 0
    assert "Malformed" in out.indicators[0]
