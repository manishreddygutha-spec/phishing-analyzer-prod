from urllib.parse import urlparse
import re


class URLTool:
    DEFANG_PATTERNS = (
        "[.]",
        "hxxp://",
        "hxxps://",
    )

    def _is_defanged(self, url: str) -> bool:
        return any(p in url.lower() for p in self.DEFANG_PATTERNS)

    def _refang(self, url: str) -> str:
        url = url.strip()
        url = url.replace("hxxp://", "http://").replace("hxxps://", "https://")
        url = url.replace("[.]", ".")
        return url

    def analyze(self, url: str) -> dict:
        # ✅ Detect obfuscation FIRST
        if self._is_defanged(url):
            return {
                "shortener": False,
                "suspicious_tld": False,
                "login_path": False,
                "malformed": True,
            }

        try:
            clean = self._refang(url)
            p = urlparse(clean)

            host = (p.netloc or "").lower()
            path = p.path or ""

            return {
                "shortener": any(x in host for x in ("bit.ly", "t.co", "tinyurl")),
                "suspicious_tld": host.endswith(".xyz"),
                "login_path": bool(re.search(r"login|verify|auth|secure", path, re.I)),
                "malformed": False,
            }

        except Exception:
            return {
                "shortener": False,
                "suspicious_tld": False,
                "login_path": False,
                "malformed": True,
            }
