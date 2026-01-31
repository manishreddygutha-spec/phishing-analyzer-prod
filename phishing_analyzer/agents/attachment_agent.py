from dataclasses import dataclass


@dataclass
class AttachmentOutput:
    indicators: list
    risk: int
    virustotal: str
    vt_status: str  # ✅ alias for reporter compatibility


class AttachmentAnalyzerAgent:
    def run(self, attachments, attachment_tool, vt_tool) -> AttachmentOutput:
        indicators = []
        risk = 0
        vt_status = "not_configured"

        for att in attachments:
            name = att.get("filename")
            data = att.get("content")

            if not name or not data:
                continue

            # Basic extension check
            if name.lower().endswith((".exe", ".js", ".vbs", ".scr", ".bat")):
                indicators.append(f"Executable attachment detected: {name}")
                risk += 30

            # -------------------------
            # VirusTotal hash check
            # -------------------------
            if vt_tool and vt_tool.enabled():
                sha256 = vt_tool.sha256_bytes(data)
                vt_result = vt_tool.check_file_hash(sha256)

                if vt_result["status"] == "enabled":
                    vt_status = "enabled"
                    malicious = vt_result.get("malicious", 0)
                    if malicious > 0:
                        indicators.append(
                            f"Attachment flagged by VirusTotal ({malicious} engines): {name}"
                        )
                        risk += 40

                elif vt_result["status"] == "rate_limited":
                    vt_status = "enabled (rate limited)"
                    indicators.append("VirusTotal rate limit hit for attachment")
                    risk += 5

                else:
                    vt_status = "enabled (error)"
                    indicators.append("VirusTotal attachment lookup error")
                    risk += 5

        return AttachmentOutput(
            indicators=indicators,
            risk=min(risk, 100),
            virustotal=vt_status,  # used by UI / JSON
            vt_status=vt_status,   # used by reporter
        )
