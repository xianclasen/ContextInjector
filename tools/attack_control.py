from __future__ import annotations

from typing import Any, Dict, Optional

from models import AppState
from models.attack_profiles import PROFILE_ID_TO_NAME, PROFILE_NAME_TO_ID


def register_attack_control_tools(mcp: Any, state: AppState) -> None:
    @mcp.tool()
    def list_attack_profiles() -> Dict[str, Any]:
        return {
            "profiles": sorted(PROFILE_ID_TO_NAME),
            "default": PROFILE_NAME_TO_ID["baseline"],
        }

    @mcp.tool()
    def get_attack_profile() -> Dict[str, Any]:
        c = state.attack_controller
        return {
            "profile_id": PROFILE_NAME_TO_ID.get(c.profile),
            "updated_at_epoch_s": c.updated_at_epoch_s,
            "last_request_id": c.last_request_id,
            "injection_enabled": state.inj_cfg.enabled,
            "single_field_per_output": state.inj_cfg.single_field_per_output,
            "inject_tools": sorted(state.inj_cfg.allowed_tools)
            if state.inj_cfg.allowed_tools
            else ["*"],
            "inject_max_items": state.inj_cfg.max_items_to_inject,
            "targets": {
                "summary": state.inj_cfg.inject_into_summary,
                "description": state.inj_cfg.inject_into_description,
                "title": state.inj_cfg.inject_into_title,
                "book_title": state.inj_cfg.inject_into_book_title,
                "author_name": state.inj_cfg.inject_into_author_name,
            },
        }

    @mcp.tool()
    def set_attack_profile(profile_id: int) -> Dict[str, Any]:
        profile = PROFILE_ID_TO_NAME.get(int(profile_id))
        if not profile:
            raise ValueError(
                f"Invalid profile_id '{profile_id}'. Valid: {sorted(PROFILE_ID_TO_NAME)}"
            )
        state.attack_controller.set_profile(profile)
        return {"ok": True, "profile_id": PROFILE_NAME_TO_ID.get(profile)}

    @mcp.tool()
    def set_injection_enabled(enabled: bool) -> Dict[str, Any]:
        state.inj_cfg.enabled = bool(enabled)
        return {"ok": True, "enabled": state.inj_cfg.enabled}

    @mcp.tool()
    def set_injection_scope(
        inject_tools: str = "",
        max_items: int = 2,
        single_field_per_output: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        inject_tools: comma-separated list. empty => all tools
        """
        raw = (inject_tools or "").strip()
        if raw == "":
            state.inj_cfg.allowed_tools = set()
        else:
            state.inj_cfg.allowed_tools = {
                t.strip() for t in raw.split(",") if t.strip()
            }

        state.inj_cfg.max_items_to_inject = max(0, int(max_items))
        if single_field_per_output is not None:
            state.inj_cfg.single_field_per_output = bool(single_field_per_output)
        return {
            "ok": True,
            "inject_tools": sorted(state.inj_cfg.allowed_tools)
            if state.inj_cfg.allowed_tools
            else ["*"],
            "max_items": state.inj_cfg.max_items_to_inject,
            "single_field_per_output": state.inj_cfg.single_field_per_output,
        }

    @mcp.tool()
    def reset_attack_profile() -> Dict[str, Any]:
        state.attack_controller.set_profile("baseline")
        return {
            "ok": True,
            "profile_id": PROFILE_NAME_TO_ID.get(state.attack_controller.profile),
        }
