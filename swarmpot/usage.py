"""Account-level usage snapshots for provider cost reconciliation.

Codex does not expose reliable per-request token usage through the adapter in
all configurations. We therefore record OpenRouter's account-wide credit usage
before and after each episode. The delta covers every provider call made during
the episode (attacker and defenders); it is labeled account-wide rather than
misattributed to one team.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict

from .util import now_iso


def fetch_openrouter_credits(timeout: float = 20.0) -> Dict[str, Any]:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        return {"available": False, "reason": "no_openrouter_key", "fetched_at": now_iso()}
    request = urllib.request.Request(
        "https://openrouter.ai/api/v1/credits",
        headers={"Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        return {
            "available": True,
            "total_credits": data.get("total_credits"),
            "total_usage": data.get("total_usage"),
            "fetched_at": now_iso(),
            "source": "openrouter /api/v1/credits",
        }
    except Exception as exc:  # noqa: BLE001 - accounting failure is data
        return {"available": False, "reason": repr(exc), "fetched_at": now_iso()}


def account_delta(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    if not before.get("available") or not after.get("available"):
        return {"available": False, "reason": "snapshot_unavailable"}
    try:
        delta = float(after["total_usage"]) - float(before["total_usage"])
    except (KeyError, TypeError, ValueError):
        return {"available": False, "reason": "usage_missing"}
    return {
        "available": True,
        "before_usage": before.get("total_usage"),
        "after_usage": after.get("total_usage"),
        "delta_usd": round(delta, 6),
        "total_credits": after.get("total_credits"),
        "attribution": (
            "account-wide delta covering every provider call in the episode "
            "(attacker plus defenders, plus any concurrent local use of the key)"
        ),
    }
