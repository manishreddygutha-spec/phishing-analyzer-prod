class AttachmentTool:
    def analyze(self, filename, content):
        """
        Analyze attachment metadata safely.

        Returns an empty dict for invalid or missing inputs.
        """
        if not filename or not content:
            return {}

        try:
            ext = "." + filename.lower().split(".")[-1]
        except Exception:
            return {}

        indicators = {}

        if ext in (".exe", ".js", ".vbs", ".scr", ".bat"):
            indicators["executable"] = True

        return indicators
