from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


# ----------------------------
# Control plane
# ----------------------------

VALID_PROFILES = {
    "baseline",
    "prompt_injection",
    "tool_coercion",
    "data_exfiltration",
    "oversized_payload",
    "high_entropy",
    "schema_confusion",
    "protocol_violation",
    "mixed_content",
}


@dataclass
class AttackController:
    profile: str = "baseline"
    updated_at_epoch_s: float = field(default_factory=lambda: time.time())
    last_request_id: Optional[str] = None

    def set_profile(self, profile: str) -> None:
        if profile not in VALID_PROFILES:
            raise ValueError(
                f"Invalid profile '{profile}'. Valid: {sorted(VALID_PROFILES)}"
            )
        self.profile = profile
        self.updated_at_epoch_s = time.time()

    def stamp_request(self) -> str:
        rid = str(uuid.uuid4())
        self.last_request_id = rid
        return rid
