import argparse
import json
import uuid
from typing import Any, Dict, Optional

import httpx
import logging

from logutils.formatters import setup_logging


def _mk_id() -> str:
    return str(uuid.uuid4())


def _truncate(s: str, n: int = 6000) -> str:
    return s if len(s) <= n else s[:n] + "\n…(truncated)…"

def _one_line(s: str, n: int = 240) -> str:
    flat = " ".join(str(s).split())
    return flat if len(flat) <= n else flat[:n] + "…"


def _summarize_response(resp: Dict[str, Any]) -> str:
    """Return a short one-line summary for a JSON-RPC response dict."""
    if not isinstance(resp, dict):
        return _truncate(str(resp), 200)

    if resp.get("error"):
        err = resp["error"]
        if isinstance(err, dict):
            return f"ERROR: {err.get('message') or err.get('code') or str(err)}"
        return f"ERROR: {str(err)}"

    if "result" in resp:
        r = resp["result"]
        if isinstance(r, dict):
            if "tools" in r and isinstance(r["tools"], list):
                names = [
                    t.get("name")
                    for t in r["tools"]
                    if isinstance(t, dict) and t.get("name")
                ]
                return f"tools: {len(names)} available ({', '.join(names[:8])}{'…' if len(names) > 8 else ''})"
            if "items" in r and isinstance(r["items"], list):
                return f"items: {len(r['items'])}"
            parts = []
            for k, v in list(r.items())[:6]:
                vs = _truncate(str(v), 120).replace("\n", " ")
                parts.append(f"{k}={vs}")
            return ", ".join(parts) if parts else "(empty result)"
        if isinstance(r, list):
            return f"result: list[{len(r)}]"
        return _truncate(str(r), 200)

    return _truncate(json.dumps(resp, separators=(",", ":"), ensure_ascii=False), 400)


def _report_injected_items(resp: Dict[str, Any]) -> None:
    """Print which items appear to have been injected (index + title/book_title).

    Detects explicit `server_note` injection metadata or common attack markers
    injected into text fields.
    """
    if not isinstance(resp, dict):
        return
    r = resp.get("result")
    if not isinstance(r, dict):
        return

    # MCP tool results may wrap structured JSON at result.structuredContent
    # or inside content[].structuredContent depending on gateway.
    payload_root = r
    sc_top = r.get("structuredContent")
    if isinstance(sc_top, dict):
        payload_root = sc_top
    else:
        content = r.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    sc = block.get("structuredContent")
                    if isinstance(sc, dict):
                        payload_root = sc
                        break

    note = payload_root.get("server_note")
    meta = {}
    if isinstance(note, dict):
        meta = note.get("meta") or {}
        profile_id = meta.get("attack_profile_id")
        req_id = meta.get("attack_request_id")
        if profile_id is not None:
            logger = logging.getLogger("mcp_client")
            if req_id:
                logger.info("Attack profile id: %s (request=%s)", profile_id, req_id)
            else:
                logger.info("Attack profile id: %s", profile_id)
    items = payload_root.get("items")
    if not isinstance(items, list) or not items:
        return

    injected = []
    for idx, it in enumerate(items):
        if not isinstance(it, dict):
            continue

        note = it.get("server_note")
        if isinstance(note, dict):
            meta = note.get("meta") or {}
            if meta.get("attack_request_id") or note.get("note", "").startswith("ATTACK_SIMULATION"):
                injected.append((idx, it, meta))
                continue

        fields_found: list[str] = []
        for key in ("summary", "description", "title", "book_title", "author", "author_name"):
            v = it.get(key)
            if isinstance(v, str) and any(m in v for m in ("ATTACK_TEST", "ATTACK_SIMULATION", "OVERSIZED_PAYLOAD_TEST", "HIGH_ENTROPY_TEST")):
                fields_found.append(key)
        if fields_found:
            injected.append((idx, it, {"injected_fields": fields_found}))
            continue

    logger = logging.getLogger("mcp_client")
    if injected:
        logger.info("Injected items detected:")
        for idx, it, meta in injected:
            title = it.get("book_title") or it.get("title") or "(no title)"
            short = _truncate(str(title), 200).replace("\n", " ")
            payload = None
            fields = meta.get("injected_fields") if isinstance(meta.get("injected_fields"), list) else None
            if fields:
                for key in fields:
                    v = it.get(key)
                    if isinstance(v, str):
                        payload = _one_line(v)
                        break
            if meta and meta.get("attack_request_id"):
                if fields:
                    logger.info(
                        " - item[%d]: %s  (profile_id=%s, request=%s) fields=%s payload=%s",
                        idx,
                        short,
                        meta.get("attack_profile_id"),
                        meta.get("attack_request_id"),
                        ",".join(fields),
                        payload or "",
                    )
                else:
                    logger.info(
                        " - item[%d]: %s  (profile_id=%s, request=%s) payload=%s",
                        idx,
                        short,
                        meta.get("attack_profile_id"),
                        meta.get("attack_request_id"),
                        payload or "",
                    )
            else:
                if fields:
                    logger.info(
                        " - item[%d]: %s  (fields=%s) payload=%s",
                        idx,
                        short,
                        ",".join(fields),
                        payload or "",
                    )
                else:
                    logger.info(" - item[%d]: %s payload=%s", idx, short, payload or "")
        return

    fields = meta.get("injected_fields") if isinstance(meta.get("injected_fields"), list) else None
    item_index = meta.get("injected_item_index")
    if fields and isinstance(item_index, int) and 0 <= item_index < len(items):
        it = items[item_index]
        if isinstance(it, dict):
            payload = None
            for key in fields:
                v = it.get(key)
                if isinstance(v, str):
                    payload = _one_line(v)
                    break
            if payload:
                logger.info(
                    "Injected items detected: item[%d] fields=%s payload=%s",
                    item_index,
                    ",".join(fields),
                    payload,
                )


class McpGatewayError(Exception):
    pass


def _parse_sse_first_json(body_text: str) -> Dict[str, Any]:
    for line in body_text.splitlines():
        if line.startswith("data:"):
            data = line[len("data:") :].strip()
            if data:
                return json.loads(data)
    raise McpGatewayError(
        f"SSE response had no data: lines.\nBody:\n{_truncate(body_text)}"
    )


class McpHttpClient:
    def __init__(
        self,
        url: str,
        timeout_s: float = 20.0,
        http2: bool = False,
        verify_tls: bool = True,
    ):
        self.url = url
        self.session_id: Optional[str] = None

        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_s, connect=timeout_s),
            http2=http2,
            verify=verify_tls,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )

    def close(self) -> None:
        self._client.close()

    def _headers(self) -> Dict[str, str]:
        h = {"X-Request-Id": _mk_id()}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _decode(self, resp: httpx.Response, method: str) -> Dict[str, Any]:
        ct = (resp.headers.get("content-type") or "").lower()

        sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
        if sid and not self.session_id:
            self.session_id = sid

        if resp.status_code >= 400:
            text = resp.text
            if "application/json" in ct:
                try:
                    msg = resp.json()
                    if isinstance(msg, dict) and msg.get("error"):
                        raise McpGatewayError(
                            f"[JSON-RPC ERROR] HTTP {resp.status_code} method={method}\n"
                            f"{json.dumps(msg['error'], indent=2)}"
                        )
                    raise McpGatewayError(
                        f"[HTTP ERROR] HTTP {resp.status_code} method={method}\n{_truncate(json.dumps(msg, indent=2))}"
                    )
                except json.JSONDecodeError:
                    pass
            raise McpGatewayError(
                f"[BLOCKED/ERROR] HTTP {resp.status_code} method={method}\n"
                f"Content-Type: {ct or '<none>'}\n"
                f"Body:\n{_truncate(text)}"
            )

        if "application/json" in ct:
            return resp.json()

        if "text/event-stream" in ct:
            return _parse_sse_first_json(resp.text)

        raise McpGatewayError(
            f"Unexpected Content-Type for method={method}: {ct!r}\nBody:\n{_truncate(resp.text)}"
        )

    def call(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": _mk_id(),
            "method": method,
            "params": params or {},
        }
        resp = self._client.post(self.url, json=payload, headers=self._headers())
        return self._decode(resp, method)

    def notify(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        """Send a JSON-RPC notification (no 'id') to the MCP gateway."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        resp = self._client.post(self.url, json=payload, headers=self._headers())
        if resp.status_code >= 400:
            raise McpGatewayError(
                f"[HTTP ERROR] HTTP {resp.status_code} method={method}\nBody:\n{_truncate(resp.text)}"
            )

    def initialize(self) -> Dict[str, Any]:
        msg = self.call(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "mcp-http-test-client", "version": "0.2.0"},
            },
        )
        if not self.session_id:
            raise McpGatewayError(
                "Initialize succeeded but no Mcp-Session-Id header was provided."
            )
        self.notify("notifications/initialized", {})
        return msg

    def list_tools(self) -> Dict[str, Any]:
        return self.call("tools/list", {})

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self.call("tools/call", {"name": name, "arguments": arguments})


def main() -> None:
    ap = argparse.ArgumentParser(description="Simple MCP test client.")
    ap.add_argument("--url", default="http://127.0.0.1:3333/mcp")
    ap.add_argument("--http2", action="store_true", help="Enable HTTP/2")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification")

    ap.add_argument(
        "--skip-set-profile",
        action="store_true",
        help="Do not call set_attack_profile (use server-side profile config)",
    )
    ap.add_argument(
        "--profile-id",
        type=int,
        help="Numeric profile id to pass as tool arg (avoids set_attack_profile)",
    )
    ap.add_argument(
        "--attack-only",
        action="store_true",
        help="Request attack-only tool output (per-request override)",
    )

    ap.add_argument("--tool", default="fetch_shelf_rss", help="Tool name to call")
    ap.add_argument("--shelf", default="read", help="Shelf name for default tool args")
    ap.add_argument("--limit", type=int, default=20, help="Limit for default tool args")
    ap.add_argument(
        "--tool-args",
        help="Raw JSON string to use as tool arguments (overrides --shelf/--limit)",
    )

    args = ap.parse_args()

    setup_logging("mcp_client")
    logger = logging.getLogger("mcp_client")

    c = McpHttpClient(
        args.url, timeout_s=args.timeout, http2=args.http2, verify_tls=not args.insecure
    )

    try:
        logger.info("Initializing…")
        c.initialize()
        logger.info("Session: %s", c.session_id)

        logger.info("Listing tools…")
        try:
            tools = c.list_tools()
            logger.info("tools/list ok")
            logger.info(_summarize_response(tools))
        except McpGatewayError:
            logger.warning("tools/list failed or blocked — continuing")

        if args.skip_set_profile:
            logger.info("Skipping set_attack_profile (server-side profile expected)")

        if args.tool_args:
            tool_args = json.loads(args.tool_args)
        else:
            tool_args = {"shelf": args.shelf, "limit": args.limit}
            if args.profile_id is not None:
                tool_args["profile_id"] = args.profile_id
            if args.attack_only:
                tool_args["attack_only"] = True

        logger.info("Calling tool: %s args=%s", args.tool, tool_args)
        res = c.call_tool(args.tool, tool_args)
        logger.info("tools/call ok")
        logger.info(_summarize_response(res))
        _report_injected_items(res)

    except McpGatewayError as e:
        logger.error(str(e))
    finally:
        c.close()


if __name__ == "__main__":
    main()
