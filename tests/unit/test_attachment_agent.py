from phishing_analyzer.agents.attachment_agent import AttachmentAnalyzerAgent
from phishing_analyzer.tools.attachment_tool import AttachmentTool


class DummyVTDisabled:
    def enabled(self):
        return False


class DummyVTEnabledClean:
    def enabled(self):
        return True

    def sha256_bytes(self, data):
        return "dummyhash"

    def check_file_hash(self, sha256):
        return {"status": "enabled", "malicious": 0}


class DummyVTEnabledMalicious:
    def enabled(self):
        return True

    def sha256_bytes(self, data):
        return "bad-hash"

    def check_file_hash(self, sha256):
        return {"status": "enabled", "malicious": 5}


def test_attachment_no_vt():
    agent = AttachmentAnalyzerAgent()

    attachments = [
        {"filename": "doc.pdf", "content": b"hello world"}
    ]

    out = agent.run(
        attachments,
        AttachmentTool(),
        DummyVTDisabled(),
    )

    assert out.virustotal == "not_configured"
    assert out.risk == 0


def test_attachment_vt_clean():
    agent = AttachmentAnalyzerAgent()

    attachments = [
        {"filename": "report.pdf", "content": b"clean file"}
    ]

    out = agent.run(
        attachments,
        AttachmentTool(),
        DummyVTEnabledClean(),
    )

    assert out.virustotal == "enabled"
    assert out.risk == 0
    assert out.indicators == []


def test_attachment_vt_malicious():
    agent = AttachmentAnalyzerAgent()

    attachments = [
        {"filename": "invoice.exe", "content": b"malware bytes"}
    ]

    out = agent.run(
        attachments,
        AttachmentTool(),
        DummyVTEnabledMalicious(),
    )

    assert out.virustotal == "enabled"
    assert out.risk > 0
    assert any("VirusTotal" in i for i in out.indicators)
