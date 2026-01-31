from dataclasses import dataclass


@dataclass
class DomainOutput:
    age_days: int | None
    risk: int
    vt_status: str
    indicators: list


class DomainAgent:
    def run(
        self,
        whois_tool,
        vt_tool,
        domain: str,
        recent_days: int = 30,
    ) -> DomainOutput:
        indicators = []
        risk = 0
        age_days = None
        vt_status = "not_configured"

        # -----------------------------
        # WHOIS / DOMAIN AGE
        # -----------------------------
        if whois_tool:
            try:
                age_days = whois_tool.lookup_age_days(domain)
                if age_days is not None and age_days < recent_days:
                    risk += 20
                    indicators.append("Recently registered domain")
            except Exception:
                pass  # WHOIS failures must NOT break pipeline

        # -----------------------------
        # VIRUSTOTAL DOMAIN CHECK
        # -----------------------------
        if vt_tool and vt_tool.enabled():
            vt_result = vt_tool.check_domain(domain)
            vt_status = vt_result.get("status", "error")

            if vt_status == "enabled":
                malicious = vt_result.get("malicious", 0)
                if malicious > 0:
                    risk += 40
                    indicators.append("Domain flagged by VirusTotal")
        else:
            vt_status = "not_configured"

        # -----------------------------
        # FINAL GUARANTEED RETURN
        # -----------------------------
        return DomainOutput(
            age_days=age_days,
            risk=risk,
            vt_status=vt_status,
            indicators=indicators,
        )
