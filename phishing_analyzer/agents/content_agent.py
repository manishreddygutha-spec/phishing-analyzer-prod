from dataclasses import dataclass
from typing import List


@dataclass
class ContentOutput:
    indicators: List[str]
    risk: int


class ContentAnalyzerAgent:
    """
    Analyzes email body text for phishing / social engineering indicators.
    """

    CREDENTIAL_PATTERNS = {
        "password": 30,
        "password reset": 35,
        "verify your account": 30,
        "verify account": 30,
        "account suspended": 25,
        "account locked": 25,
        "unusual sign-in": 25,
        "security alert": 20,
        "confirm your identity": 30,
        "reset your password": 35,
        "action required": 20,
        "login immediately": 25,
    }

    BRAND_IMPERSONATION = [
        "microsoft",
        "google",
        "apple",
        "paypal",
        "amazon",
        "dhl",
        "fedex",
    ]

    def run(self, email) -> ContentOutput:
        indicators = []
        risk = 0

        if not email or not getattr(email, "body", None):
            return ContentOutput(indicators=[], risk=0)

        body = email.body.lower()

        # 🔐 Credential phishing detection
        for phrase, weight in self.CREDENTIAL_PATTERNS.items():
            if phrase in body:
                indicators.append(f"Credential phishing phrase detected: '{phrase}'")
                risk += weight

        # 🏷️ Brand impersonation detection
        for brand in self.BRAND_IMPERSONATION:
            if brand in body:
                indicators.append(f"Brand impersonation detected: {brand}")
                risk += 20
                break

        # Cap content risk
        risk = min(risk, 60)

        return ContentOutput(indicators=indicators, risk=risk)
