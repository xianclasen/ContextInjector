import html
import re
from typing import Optional


def normalize_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def clean_text(s: Optional[str]) -> str:
    if not s:
        return ""
    s = html.unescape(s)
    s = re.sub(r"<[^>]+>", "", s)
    return normalize_ws(s)


def one_line(s: str, max_len: int = 240) -> str:
    flat = " ".join(str(s).split())
    return flat if len(flat) <= max_len else flat[:max_len] + "…"


def truncate(s: str, n: int = 6000) -> str:
    return s if len(s) <= n else s[:n] + "\n…(truncated)…"
