import os
import hashlib
import requests
from phishing_analyzer.utils.resilience import resilient_call


class VirusTotalTool:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base = "https://www.virustotal.com/api/v3"

    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self):
        return {"x-apikey": self.api_key}

    # -------------------------------------------------
    # DOMAIN CHECK
    # -------------------------------------------------
    @resilient_call(retries=3, delay=1, backoff=2)
    def check_domain(self, domain: str) -> dict:
        if not self.enabled():
            return {"status": "not_configured"}

        response = requests.get(
            f"{self.base}/domains/{domain}",
            headers=self._headers(),
            timeout=10,
        )

        if response.status_code == 429:
            return {"status": "rate_limited"}

        if response.status_code != 200:
            return {"status": "error"}

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]

        return {
            "status": "enabled",
            "malicious": stats.get("malicious", 0),
        }

    # -------------------------------------------------
    # FILE HASH CHECK (ATTACHMENTS)
    # -------------------------------------------------
    @resilient_call(retries=3, delay=1, backoff=2)
    def check_file_hash(self, sha256: str) -> dict:
        if not self.enabled():
            return {"status": "not_configured"}

        response = requests.get(
            f"{self.base}/files/{sha256}",
            headers=self._headers(),
            timeout=10,
        )

        if response.status_code == 404:
            # Known clean / not indexed
            return {"status": "enabled", "malicious": 0}

        if response.status_code == 429:
            return {"status": "rate_limited"}

        if response.status_code != 200:
            return {"status": "error"}

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]

        return {
            "status": "enabled",
            "malicious": stats.get("malicious", 0),
        }

    # -------------------------------------------------
    # HASH HELPER
    # -------------------------------------------------
    @staticmethod
    def sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
