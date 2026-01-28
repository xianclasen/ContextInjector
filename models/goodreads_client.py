from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class GoodreadsRssClient:
    user_id: str
    user_agent: str
    timeout_seconds: float = 20.0

    def __post_init__(self) -> None:
        self._client = httpx.Client(
            headers={"User-Agent": self.user_agent},
            timeout=self.timeout_seconds,
            follow_redirects=True,
        )

    def build_base_url(self) -> str:
        return f"https://www.goodreads.com/review/list_rss/{self.user_id}"

    def fetch_shelf_bytes(
        self, shelf: str, sort: str = "date_updated", order: str = "d"
    ) -> bytes:
        if not shelf:
            raise ValueError("shelf is required")

        url = self.build_base_url()
        resp = self._client.get(
            url, params={"shelf": shelf, "sort": sort, "order": order}
        )
        resp.raise_for_status()
        return resp.content

    def close(self) -> None:
        self._client.close()
