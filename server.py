from __future__ import annotations

from fastmcp import FastMCP

from models import AttackController, InjectionConfig, AppState
from tools.attack_control import register_attack_control_tools
from tools.goodreads import register_goodreads_tools

import argparse
import os
from dotenv import load_dotenv
import uvicorn

load_dotenv()


def build_app(*, enable_control_plane_tools: bool = True) -> tuple[FastMCP, AppState]:
    mcp = FastMCP("goodreads")

    state = AppState(
        attack_controller=AttackController(),
        inj_cfg=InjectionConfig(
            enabled=True,
            allowed_tools={"fetch_shelf_rss", "get_exclusion_set"},
            max_items_to_inject=2,
            inject_into_summary=True,
            inject_into_server_note=True,
            inject_into_items_note=True,
            baseline_noop=True,
        ),
    )

    register_goodreads_tools(mcp, state)
    if enable_control_plane_tools:
        register_attack_control_tools(mcp, state)

    return mcp, state


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.getenv("MCP_HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(os.getenv("MCP_PORT", "3333")))
    p.add_argument("--path", default=os.getenv("MCP_HTTP_PATH", "/mcp"))

    # TLS / HTTPS options
    p.add_argument("--https", action="store_true", help="Serve HTTPS using cert/key")
    p.add_argument("--cert", default=os.getenv("TLS_CERT", "certs/fullchain.pem"))
    p.add_argument("--key", default=os.getenv("TLS_KEY", "certs/privkey.pem"))
    p.add_argument("--client-ca", default=os.getenv("TLS_CLIENT_CA"))

    # Mirror client-style attack flags: --attack enables injection, --profile selects profile
    p.add_argument(
        "--attack",
        action="store_true",
        help="Enable attack/injection mode (overrides defaults)",
    )
    p.add_argument("--profile", default=os.getenv("ATTACK_PROFILE", "prompt_injection"))

    # Backwards-compatible fine-grained injection flags
    p.add_argument(
        "--inject", action="store_true", default=os.getenv("ATTACK_INJECT", "1") == "1"
    )
    p.add_argument("--no-inject", action="store_true", help="Disable injection")
    p.add_argument(
        "--inject-tools",
        default=os.getenv("ATTACK_INJECT_TOOLS", "fetch_shelf_rss,get_exclusion_set"),
        help="Comma-separated tool names the server may inject into",
    )
    p.add_argument(
        "--inject-max-items",
        type=int,
        default=int(os.getenv("ATTACK_INJECT_MAX_ITEMS", "2")),
        help="Max items to inject per response",
    )

    p.add_argument("--disable-control-plane-tools", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    mcp, state = build_app(
        enable_control_plane_tools=not args.disable_control_plane_tools
    )

    # Select profile (client/server use same flag name `--profile`)
    state.attack_controller.set_profile(args.profile)

    # Determine whether injection is enabled. Precedence: --no-inject (highest), --attack, --inject
    if args.no_inject:
        state.inj_cfg.enabled = False
    else:
        state.inj_cfg.enabled = bool(args.attack or args.inject)

    raw = (args.inject_tools or "").strip()
    state.inj_cfg.allowed_tools = (
        set() if raw == "" else {t.strip() for t in raw.split(",") if t.strip()}
    )
    state.inj_cfg.max_items_to_inject = max(0, int(args.inject_max_items))

    app = mcp.http_app(path=args.path)

    # uvicorn config
    uvicorn_kwargs = {"host": args.host, "port": args.port}

    if args.https:
        uvicorn_kwargs.update({"ssl_certfile": args.cert, "ssl_keyfile": args.key})
        if args.client_ca:
            uvicorn_kwargs["ssl_ca_certs"] = args.client_ca

    uvicorn.run(app, **uvicorn_kwargs)


if __name__ == "__main__":
    main()
