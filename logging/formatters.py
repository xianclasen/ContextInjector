import json
import sys
import logging
import os
import time
from dataclasses import asdict, is_dataclass
from typing import Any, Dict


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)

        skip = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
        }
        for k, v in record.__dict__.items():
            if k in skip:
                continue
            base[k] = _json_safe(v)

        # Pretty-print for terminals, compact JSON for non-TTY (e.g. files/aggregators)
        is_tty = False
        try:
            is_tty = sys.stderr.isatty()
        except Exception:
            is_tty = False

        if is_tty:
            return json.dumps(base, ensure_ascii=False, indent=2)
        return json.dumps(base, ensure_ascii=False, separators=(",", ":"))


class HumanFormatter(logging.Formatter):
    LEVEL_COLORS = {
        "DEBUG": "\x1b[36m",
        "INFO": "\x1b[32m",
        "WARNING": "\x1b[33m",
        "ERROR": "\x1b[31m",
        "CRITICAL": "\x1b[41m",
    }
    RESET = "\x1b[0m"

    def __init__(self, use_color: bool = True) -> None:
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(record.created))
        level = record.levelname
        color = self.LEVEL_COLORS.get(level, "") if self.use_color else ""
        reset = self.RESET if self.use_color else ""
        msg = record.getMessage()
        base = f"{ts} {color}{level:<8}{reset} {record.name}: {msg}"

        skip = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
        }

        extras: Dict[str, Any] = {}
        for k, v in record.__dict__.items():
            if k in skip:
                continue
            extras[k] = _json_safe(v)

        if extras:
            try:
                extras_str = json.dumps(extras, ensure_ascii=False)
            except Exception:
                extras_str = str(extras)
            base = f"{base} {extras_str}"

        if record.exc_info:
            base = base + "\n" + self.formatException(record.exc_info)

        return base


def _json_safe(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool, list, dict)):
        return value
    if is_dataclass(value):
        return asdict(value)
    return str(value)


def setup_logging(service_name: str) -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler()

    fmt_choice = os.getenv("LOG_FORMAT", "json").lower()
    color_env = os.getenv("LOG_COLOR")
    if color_env is None:
        use_color = False
        try:
            use_color = sys.stderr.isatty()
        except Exception:
            use_color = False
    else:
        use_color = color_env.lower() in ("1", "true", "yes", "on")

    if fmt_choice in ("human", "pretty"):
        handler.setFormatter(HumanFormatter(use_color=use_color))
    else:
        handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    logging.getLogger(service_name).info(
        "logging configured",
        extra={"service": service_name, "log_level": level_name},
    )


class Timer:
    def __init__(self) -> None:
        self._start = 0.0
        self.ms = 0.0

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.ms = (time.perf_counter() - self._start) * 1000.0
