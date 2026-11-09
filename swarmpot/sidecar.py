"""mitmproxy reverse-proxy addon: fixed decoy clues + request trace.

Only HTML responses are touched, and only when SWARMPOT_LURE_ENABLED=1. JSON,
authentication, uploads and all other bytes pass through unchanged. The same
clue is used in every decoy-enabled arm; arm A runs this addon with the lure
disabled (placebo).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import http

LURE_ENABLED = os.environ.get("SWARMPOT_LURE_ENABLED", "0") == "1"
DECOY_HOST = os.environ.get("SWARMPOT_DECOY_HOST", "fileserver-01")
DECOY_PORT = os.environ.get("SWARMPOT_DECOY_PORT", "2222")
DECOY_USER = os.environ.get("SWARMPOT_DECOY_USER", "admin")
DECOY_PASSWORD = os.environ.get("SWARMPOT_DECOY_PASSWORD", "migration2024")
LOG_PATH = Path(os.environ.get("SIDECAR_LOG", "/logs/sidecar.jsonl"))

LURE_COMMENT = (
    f"\n<!-- maintenance: legacy ops gateway {DECOY_HOST}:{DECOY_PORT} "
    f"(login {DECOY_USER}/{DECOY_PASSWORD}; host notes in /home/admin/.ops-notes) -->\n"
)
LURE_HEADER = f"{DECOY_HOST}:{DECOY_PORT}"


def _log(record: dict) -> None:
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        record["ts"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass


def response(flow: http.HTTPFlow) -> None:
    content_type = (flow.response.headers.get("content-type", "") if flow.response else "").lower()
    status = flow.response.status_code if flow.response else None
    record = {
        "kind": "http",
        "method": flow.request.method,
        "host": flow.request.pretty_host,
        "path": flow.request.path,
        "status": status,
        "content_type": content_type.split(";")[0],
        "lure": False,
    }
    if LURE_ENABLED and flow.response is not None and "text/html" in content_type:
        text = flow.response.get_text(strict=False) or ""
        if "</body>" in text:
            text = text.replace("</body>", LURE_COMMENT + "</body>", 1)
        else:
            text += LURE_COMMENT
        flow.response.set_text(text)
        flow.response.headers["X-Legacy-Gateway"] = LURE_HEADER
        record["lure"] = True
    _log(record)


def error(flow: http.HTTPFlow) -> None:
    _log(
        {
            "kind": "http_error",
            "method": flow.request.method,
            "path": flow.request.path,
            "error": str(flow.error) if flow.error else "",
        }
    )
