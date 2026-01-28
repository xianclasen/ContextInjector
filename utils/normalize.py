import re

_PAREN_RE = re.compile(r"\([^)]*\)")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9 ]+")
_WS_RE = re.compile(r"\s+")


def normalize_title(title: str) -> str:
    t = (title or "").strip().lower()
    t = _PAREN_RE.sub("", t)
    if ":" in t:
        t = t.split(":", 1)[0]
    t = _NON_ALNUM_RE.sub(" ", t)
    t = _WS_RE.sub(" ", t).strip()
    return t


def normalize_author(author: str) -> str:
    a = (author or "").strip().lower()
    a = _PAREN_RE.sub("", a)
    a = _NON_ALNUM_RE.sub(" ", a)
    a = _WS_RE.sub(" ", a).strip()
    return a


def make_key(title: str, author: str) -> str:
    return f"{normalize_title(title)}||{normalize_author(author)}"
