from phishing_analyzer.tools.attachment_tool import AttachmentTool


def test_attachment_tool_none():
    """
    AttachmentTool should safely handle empty filename/content.
    """
    tool = AttachmentTool()

    result = tool.analyze(None, None)

    assert result == {}
