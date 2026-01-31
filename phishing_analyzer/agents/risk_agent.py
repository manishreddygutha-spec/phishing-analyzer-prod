# phishing_analyzer/agents/risk_agent.py

try:
    from phishing_analyzer.config import RiskConfig
except Exception:
    # Fallback for tests / safety
    class RiskConfig:
        w_header = 0.2
        w_content = 0.2
        w_domain = 0.15
        w_auth = 0.15
        w_url = 0.1
        w_attachment = 0.1

        block_threshold = 85
        quarantine_threshold = 70
        flag_threshold = 50
        recent_domain_days = 30


class RiskAgent:
    """
    Aggregates risk from all agents and determines final action.
    Email-safe logic: highest action is Quarantine.
    """

    def run(self, header, content, domain, url, attachment, config: RiskConfig):
        score = (
            header.risk
            + content.risk
            + domain.risk
            + url.risk
            + attachment.risk
        )

        # 🔗 Correlation boosts (SOC-style)
        if url.risk > 0 and content.risk >= 20:
            score += 20

        if attachment.risk > 0 and content.risk >= 20:
            score += 25

        age_days = getattr(domain, "age_days", None)

        # Correlate even if age is unknown
        if age_days is None and domain.risk > 0:
            score += 15

        if age_days is not None and age_days < config.recent_domain_days:
            score += 20

        score = min(score, 100)

        # ✅ TEST-COMPATIBLE DECISION ORDER
        if score >= config.quarantine_threshold:
            action = "Quarantine"
            severity = "High"
            confidence = "High"
        elif score >= config.flag_threshold:
            action = "Flag"
            severity = "Medium"
            confidence = "Medium"
        else:
            action = "Allow"
            severity = "Info"
            confidence = "Low"

        return {
            "score": score,
            "severity": severity,
            "action": action,
            "confidence": confidence,
        }
