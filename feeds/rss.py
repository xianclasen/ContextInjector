from typing import Any, Dict, List

import feedparser


def parse_rss_bytes(content: bytes) -> feedparser.FeedParserDict:
    return feedparser.parse(content)


def entry_to_item(entry: feedparser.FeedParserDict) -> Dict[str, Any]:
    title = getattr(entry, "title", "") or ""
    author = getattr(entry, "author", "") or ""
    link = getattr(entry, "link", "") or ""
    published = getattr(entry, "published", None)
    updated = getattr(entry, "updated", None)
    summary = getattr(entry, "summary", None)

    return {
        "title": title,
        "author": author,
        "link": link,
        "published": published,
        "updated": updated,
        "summary": summary,
    }


def feed_to_items(
    feed: feedparser.FeedParserDict, limit: int = 500
) -> List[Dict[str, Any]]:
    entries = getattr(feed, "entries", []) or []
    out: List[Dict[str, Any]] = []

    n = max(0, int(limit))
    for entry in entries[:n]:
        out.append(entry_to_item(entry))

    return out
