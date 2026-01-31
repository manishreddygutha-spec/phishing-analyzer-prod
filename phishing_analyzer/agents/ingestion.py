import re
import html
from dataclasses import dataclass
from typing import List
from urllib.parse import unquote
from email import policy
from email.parser import BytesParser


# =================================================
# URL extraction helpers
# =================================================

URL_REGEX = re.compile(
    r"https?://[^\s\"'>]+",
    re.IGNORECASE,
)


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from raw text or HTML.
    Handles quoted-printable and HTML entities.
    """
    if not text:
        return []

    try:
        decoded = html.unescape(unquote(text))
    except Exception:
        decoded = text

    return URL_REGEX.findall(decoded)


# =================================================
# Ingestion output
# =================================================

@dataclass
class IngestionOutput:
    body: str
    urls: List[str]
    attachments: List[dict]
    from_email: str
    from_domain: str


# =================================================
# Ingestion Agent
# =================================================

class IngestionAgent:
    def run(self, eml_path: str) -> IngestionOutput:
        with open(eml_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        body_text = ""
        body_html = ""
        urls: List[str] = []
        attachments: List[dict] = []

        # -----------------------------------------
        # Walk MIME parts
        # -----------------------------------------
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            # -------- Text parts --------
            if content_type == "text/plain":
                try:
                    body_text += part.get_content()
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    body_html += part.get_content()
                except Exception:
                    pass

            # -------- Attachments --------
            elif disposition == "attachment":
                try:
                    attachments.append(
                        {
                            "filename": part.get_filename(),
                            "content": part.get_payload(decode=True),
                        }
                    )
                except Exception:
                    pass

        # -----------------------------------------
        # URL extraction (TEXT + HTML)
        # -----------------------------------------
        urls.extend(extract_urls(body_text))
        urls.extend(extract_urls(body_html))
        urls = list(set(urls))  # deduplicate

        # -----------------------------------------
        # Sender parsing
        # -----------------------------------------
        from_header = msg.get("From", "")
        from_email = from_header

        match = re.search(r"@([A-Za-z0-9.-]+)", from_header)
        from_domain = match.group(1).lower() if match else ""

        return IngestionOutput(
            body=body_text.strip(),
            urls=urls,
            attachments=attachments,
            from_email=from_email,
            from_domain=from_domain,
        )

    # -------------------------------------------------
    # Backward-compatibility wrapper (tests depend on it)
    # -------------------------------------------------
    def parse(self, eml_path: str) -> IngestionOutput:
        """
        Backward-compatible alias for run().
        """
        return self.run(eml_path)


# -------------------------------------------------
# Backward-compatibility class alias (tests depend on it)
# -------------------------------------------------
EmailIngestionAgent = IngestionAgent
