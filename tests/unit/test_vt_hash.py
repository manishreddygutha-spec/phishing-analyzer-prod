from phishing_analyzer.tools.virustotal_tool import VirusTotalTool


def test_sha256_hash_consistency():
    data = b"test data"
    h1 = VirusTotalTool.sha256_bytes(data)
    h2 = VirusTotalTool.sha256_bytes(data)

    assert h1 == h2
    assert len(h1) == 64
