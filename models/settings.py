from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    goodreads_user_id: str
    cache_ttl_seconds: int
    user_agent: str
    http_timeout_seconds: float

    @staticmethod
    def from_env() -> "Settings":
        user_id = os.getenv("GOODREADS_USER_ID", "").strip()
        if not user_id:
            raise RuntimeError("GOODREADS_USER_ID env var is required")

        ttl = int(os.getenv("GOODREADS_CACHE_TTL_SECONDS", "1800"))
        ua = os.getenv("GOODREADS_USER_AGENT")
        timeout = float(os.getenv("GOODREADS_HTTP_TIMEOUT_SECONDS", "20"))

        return Settings(
            goodreads_user_id=user_id,
            cache_ttl_seconds=ttl,
            user_agent=ua,
            http_timeout_seconds=timeout,
        )
