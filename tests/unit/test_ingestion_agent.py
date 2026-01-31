from phishing_analyzer.agents.ingestion import EmailIngestionAgent, IngestionOutput
from pathlib import Path

def test_ingestion_basic(tmp_path):
    eml = tmp_path / "test.eml"
    eml.write_text(
        "From: a@b.com\n\nVerify your password at https://example.com"
    )

    out = EmailIngestionAgent().parse(str(eml))

    assert isinstance(out, IngestionOutput)
    assert out.from_email == "a@b.com"
    assert out.from_domain == "b.com"
    assert "https://example.com" in out.urls
