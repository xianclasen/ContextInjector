import json
import logging
import time
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger("goodreads_mcp.mcp")

MCP_PATH = "/mcp"
MAX_FIELD_LEN = 1500


def _truncate(v: Any, max_len: int = MAX_FIELD_LEN) -> Any:
    if isinstance(v, str):
        return v if len(v) <= max_len else v[:max_len] + "…"
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    try:
        s = json.dumps(v, ensure_ascii=False)
        if len(s) <= max_len:
            return v
        return s[:max_len] + "…"
    except Exception:
        s = str(v)
        return s if len(s) <= max_len else s[:max_len] + "…"


def _sanitize_jsonrpc(payload: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k in ("jsonrpc", "id", "method", "params", "result", "error"):
        if k in payload:
            out[k] = _truncate(payload[k])
    return out


class McpHttpJsonRpcLoggingMiddleware:
    def __init__(self, app, mcp_path: str = MCP_PATH):
        self.app = app
        self.mcp_path = mcp_path

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != self.mcp_path:
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        content_type = headers.get("content-type", "")
        client = scope.get("client")
        client_ip = client[0] if client else None

        request_id = headers.get("x-request-id") or str(uuid.uuid4())
        start = time.perf_counter()

        body_chunks = []
        more_body = True
        while more_body:
            msg = await receive()
            if msg["type"] != "http.request":
                continue
            body_chunks.append(msg.get("body", b""))
            more_body = msg.get("more_body", False)
        body = b"".join(body_chunks)

        async def replay_receive():
            return {"type": "http.request", "body": body, "more_body": False}

        response_status: Optional[int] = None
        response_headers: Dict[str, str] = {}
        response_body_chunks = []

        async def send_wrapper(message):
            nonlocal response_status, response_headers
            if message["type"] == "http.response.start":
                response_status = message.get("status")
                response_headers = {k.decode().lower(): v.decode() for k, v in message.get("headers", [])}
            elif message["type"] == "http.response.body":
                chunk = message.get("body", b"")
                if sum(len(c) for c in response_body_chunks) < 64_000:
                    response_body_chunks.append(chunk)
            await send(message)

        payload_in = None
        if body and "application/json" in content_type:
            try:
                obj = json.loads(body.decode("utf-8", errors="replace"))
                if isinstance(obj, list):
                    payload_in = [_sanitize_jsonrpc(p) for p in obj if isinstance(p, dict)]
                elif isinstance(obj, dict):
                    payload_in = _sanitize_jsonrpc(obj)
                else:
                    payload_in = _truncate(obj)
            except Exception as e:
                payload_in = {"parse_error": str(e), "body_preview": _truncate(body.decode("utf-8", errors="replace"))}

        logger.info(
            "mcp jsonrpc request",
            extra={
                "event": "mcp_jsonrpc_in",
                "direction": "in",
                "transport": "http-json",
                "request_id": request_id,
                "http_method": method,
                "path": path,
                "client_ip": client_ip,
                "content_type": content_type,
                "jsonrpc": payload_in,
            },
        )

        try:
            await self.app(scope, replay_receive, send_wrapper)
        finally:
            duration_ms = (time.perf_counter() - start) * 1000.0
            resp_ct = response_headers.get("content-type", "")
            resp_body = b"".join(response_body_chunks) if response_body_chunks else b""

            payload_out = None
            if resp_body and "application/json" in resp_ct:
                try:
                    obj = json.loads(resp_body.decode("utf-8", errors="replace"))
                    if isinstance(obj, list):
                        payload_out = [_sanitize_jsonrpc(p) for p in obj if isinstance(p, dict)]
                    elif isinstance(obj, dict):
                        payload_out = _sanitize_jsonrpc(obj)
                    else:
                        payload_out = _truncate(obj)
                except Exception as e:
                    payload_out = {"parse_error": str(e), "body_preview": _truncate(resp_body.decode("utf-8", errors="replace"))}

            logger.info(
                "mcp jsonrpc response",
                extra={
                    "event": "mcp_jsonrpc_out",
                    "direction": "out",
                    "transport": "http-json",
                    "request_id": request_id,
                    "http_method": method,
                    "path": path,
                    "client_ip": client_ip,
                    "status": response_status,
                    "duration_ms": round(duration_ms, 2),
                    "response_content_type": resp_ct,
                    "jsonrpc": payload_out,
                },
            )
