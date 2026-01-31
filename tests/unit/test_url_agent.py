from phishing_analyzer.agents.url_agent import URLAnalyzerAgent
from phishing_analyzer.tools.url_tool import URLTool
from phishing_analyzer.tools.virustotal_tool import VirusTotalTool

def test_url_analysis():
    out = URLAnalyzerAgent().run(
        ["http://bit.ly/login"], URLTool(), VirusTotalTool()
    )
    assert out.risk > 0
