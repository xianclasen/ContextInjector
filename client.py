import argparse
import json
import uuid
from typing import Any, Dict, Optional

import httpx


def _mk_id() -> str:
    return str(uuid.uuid4())


def _truncate(s: str, n: int = 6000) -> str:
    return s if len(s) <= n else s[:n] + "\n…(truncated)…"


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
            # common shapes: tools list, items, simple status objects
            if "tools" in r and isinstance(r["tools"], list):
                names = [
                    t.get("name")
                    for t in r["tools"]
                    if isinstance(t, dict) and t.get("name")
                ]
                return f"tools: {len(names)} available ({', '.join(names[:8])}{'…' if len(names) > 8 else ''})"
            if "items" in r and isinstance(r["items"], list):
                return f"items: {len(r['items'])}"
            # fall back to summarizing top-level keys
            parts = []
            for k, v in list(r.items())[:6]:
                vs = _truncate(str(v), 120).replace("\n", " ")
                parts.append(f"{k}={vs}")
            return ", ".join(parts) if parts else "(empty result)"
        # non-dict result (string/number/array)
        if isinstance(r, list):
            return f"result: list[{len(r)}]"
        return _truncate(str(r), 200)

    # fallback
    return _truncate(json.dumps(resp, separators=(",", ":"), ensure_ascii=False), 400)


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

        # capture session id if present
        sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
        if sid and not self.session_id:
            self.session_id = sid

        # handle http errors: try json-rpc first
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

    # Initialize the MCP session
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
        _ = self.call("notifications/initialized", {})
        return msg

    # List available tools
    def list_tools(self) -> Dict[str, Any]:
        return self.call("tools/list", {})

    # Call a tool
    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self.call("tools/call", {"name": name, "arguments": arguments})


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Simple MCP test client — choose legit or attack mode."
    )
    ap.add_argument("--url", default="http://127.0.0.1:3333/mcp")
    ap.add_argument("--http2", action="store_true", help="Enable HTTP/2")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification")

    # Mode selection: normal (legit) or attack
    ap.add_argument(
        "--attack",
        action="store_true",
        help="Enable attack mode (will call set_attack_profile if available)",
    )
    ap.add_argument(
        "--profile",
        default="prompt_injection",
        help="Attack profile to set when --attack is used",
    )

    # Tool selection: simple defaults for Goodreads shelf fetching, with small helpers
    ap.add_argument("--tool", default="fetch_shelf_rss", help="Tool name to call")
    ap.add_argument("--shelf", default="read", help="Shelf name for default tool args")
    ap.add_argument("--limit", type=int, default=20, help="Limit for default tool args")
    ap.add_argument(
        "--tool-args",
        help="Raw JSON string to use as tool arguments (overrides --shelf/--limit)",
    )

    args = ap.parse_args()

    c = McpHttpClient(
        args.url, timeout_s=args.timeout, http2=args.http2, verify_tls=not args.insecure
    )

    try:
        print("Initializing…")
        c.initialize()
        print("Session:", c.session_id)

        # Lightweight tools listing for visibility
        print("\nListing tools…")
        try:
            tools = c.list_tools()
            print("tools/list ok")
            print(_summarize_response(tools))
        except McpGatewayError:
            print("tools/list failed or blocked — continuing")

        # If attack mode selected, attempt to set the attack profile
        if args.attack:
            print(f"\nSetting attack profile: {args.profile}")
            try:
                res = c.call_tool("set_attack_profile", {"profile": args.profile})
                print("set_attack_profile ok")
                print(_summarize_response(res))
            except McpGatewayError:
                print("set_attack_profile failed or not exposed — continuing")

        # Build tool arguments
        if args.tool_args:
            tool_args = json.loads(args.tool_args)
        else:
            tool_args = {"shelf": args.shelf, "limit": args.limit}

        print(f"\nCalling tool: {args.tool} args={tool_args}")
        res = c.call_tool(args.tool, tool_args)
        print("tools/call ok")
        print(_summarize_response(res))

    except McpGatewayError as e:
        print(str(e))
    finally:
        c.close()


if __name__ == "__main__":
    main()
