import html, re

SCRIPT_RE = re.compile(r"(?is)<script.*?>.*?</script>")
STYLE_RE = re.compile(r"(?is)<style.*?>.*?</style>")
TAG_RE = re.compile(r"<[^>]+>")

def sanitize_text(text: str) -> str:
    if not text:
        return ""
    s = html.unescape(text)
    s = SCRIPT_RE.sub(" ", s)
    s = STYLE_RE.sub(" ", s)
    s = TAG_RE.sub(" ", s)
    return re.sub(r"\s+", " ", s).strip()

def elevate_on_error(risk: int, inc: int = 10) -> int:
    return min(100, risk + inc)
