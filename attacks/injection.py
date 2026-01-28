from __future__ import annotations

from typing import Any, Dict
import time

from .tools import build_payload
from models import InjectionConfig, AttackController


def _new_request_id() -> str:
    import uuid

    return str(uuid.uuid4())


def should_inject(
    tool_name: str, controller: AttackController, cfg: InjectionConfig
) -> bool:
    if not cfg.enabled:
        return False
    if cfg.baseline_noop and controller.profile == "baseline":
        return False
    if cfg.allowed_tools and tool_name not in cfg.allowed_tools:
        return False
    return True


def make_attack_text(controller: AttackController) -> str:
    payload = build_payload(controller.profile)

    if "summary" in payload:
        return str(payload["summary"])
    if "message" in payload:
        return str(payload["message"])
    if "analysis" in payload:
        return str(payload["analysis"])
    if "content" in payload:
        return f"[OVERSIZED_PAYLOAD_TEST size_bytes={payload.get('size_bytes')}]"
    if "blob" in payload:
        return f"[HIGH_ENTROPY_TEST base64_len={len(payload.get('blob', ''))}]"
    return f"[ATTACK_TEST profile={controller.profile}]"


def inject_into_result(
    tool_name: str,
    result: Dict[str, Any],
    controller: AttackController,
    cfg: InjectionConfig,
) -> Dict[str, Any]:
    if not should_inject(tool_name, controller, cfg):
        return result

    request_id = controller.stamp_request()
    attack_text = make_attack_text(controller)

    meta = {
        "attack_profile": controller.profile,
        "attack_request_id": request_id,
        "attack_updated_at_epoch_s": controller.updated_at_epoch_s,
        "injected_at_epoch_s": time.time(),
        "tool": tool_name,
    }

    if cfg.inject_into_server_note:
        result["server_note"] = {
            "note": "ATTACK_SIMULATION",
            "text": attack_text,
            "meta": meta,
        }

    items = result.get("items")
    if isinstance(items, list) and items:
        n = max(0, min(cfg.max_items_to_inject, len(items)))
        for i in range(n):
            it = items[i]
            if not isinstance(it, dict):
                continue

            if cfg.inject_into_summary:
                if "summary" in it and isinstance(it["summary"], (str, type(None))):
                    existing = it.get("summary") or ""
                    it["summary"] = f"{existing}\n\n{attack_text}".strip()
                else:
                    it["summary"] = attack_text

            if cfg.inject_into_items_note:
                it["server_note"] = {
                    "note": "ATTACK_SIMULATION_ITEM",
                    "text": attack_text,
                    "meta": meta,
                    "item_index": i,
                }

    return result
