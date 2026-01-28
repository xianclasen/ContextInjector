from __future__ import annotations

from typing import Any, Dict

from models import VALID_PROFILES, AppState


def register_attack_control_tools(mcp: Any, state: AppState) -> None:
    @mcp.tool()
    def list_attack_profiles() -> Dict[str, Any]:
        return {"profiles": sorted(VALID_PROFILES), "default": "baseline"}

    @mcp.tool()
    def get_attack_profile() -> Dict[str, Any]:
        c = state.attack_controller
        return {
            "profile": c.profile,
            "updated_at_epoch_s": c.updated_at_epoch_s,
            "last_request_id": c.last_request_id,
            "injection_enabled": state.inj_cfg.enabled,
            "inject_tools": sorted(state.inj_cfg.allowed_tools)
            if state.inj_cfg.allowed_tools
            else ["*"],
            "inject_max_items": state.inj_cfg.max_items_to_inject,
            "targets": {
                "summary": state.inj_cfg.inject_into_summary,
                "server_note": state.inj_cfg.inject_into_server_note,
                "items_note": state.inj_cfg.inject_into_items_note,
            },
        }

    @mcp.tool()
    def set_attack_profile(profile: str) -> Dict[str, Any]:
        state.attack_controller.set_profile(profile)
        return {"ok": True, "profile": state.attack_controller.profile}

    @mcp.tool()
    def set_injection_enabled(enabled: bool) -> Dict[str, Any]:
        state.inj_cfg.enabled = bool(enabled)
        return {"ok": True, "enabled": state.inj_cfg.enabled}

    @mcp.tool()
    def set_injection_targets(
        summary: bool = True,
        server_note: bool = True,
        items_note: bool = True,
    ) -> Dict[str, Any]:
        state.inj_cfg.inject_into_summary = bool(summary)
        state.inj_cfg.inject_into_server_note = bool(server_note)
        state.inj_cfg.inject_into_items_note = bool(items_note)
        return {
            "ok": True,
            "targets": {
                "summary": state.inj_cfg.inject_into_summary,
                "server_note": state.inj_cfg.inject_into_server_note,
                "items_note": state.inj_cfg.inject_into_items_note,
            },
        }

    @mcp.tool()
    def set_injection_scope(
        inject_tools: str = "",
        max_items: int = 2,
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
        return {
            "ok": True,
            "inject_tools": sorted(state.inj_cfg.allowed_tools)
            if state.inj_cfg.allowed_tools
            else ["*"],
            "max_items": state.inj_cfg.max_items_to_inject,
        }

    @mcp.tool()
    def reset_attack_profile() -> Dict[str, Any]:
        state.attack_controller.set_profile("baseline")
        return {"ok": True, "profile": state.attack_controller.profile}
