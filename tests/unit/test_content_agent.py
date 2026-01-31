from phishing_analyzer.agents.content_agent import ContentAnalyzerAgent
from phishing_analyzer.agents.ingestion import IngestionOutput

def test_content_phishing():
    email = IngestionOutput("verify password", [], [], "a@b.com", "b.com")
    out = ContentAnalyzerAgent().run(email)
    assert out.risk > 0
