from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from .util import read_json, write_json


OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"


class Pricing:
    """USD-per-million-token prices, fetched once per run and cached on disk."""

    def __init__(self, cache_path: Optional[Path] = None):
        self.cache_path = cache_path
        self.table: Dict[str, Dict[str, float]] = {}
        if cache_path:
            cached = read_json(cache_path, default=None)
            if cached:
                self.table = cached
        if not self.table:
            self.table = self._fetch()
            if cache_path and self.table:
                write_json(cache_path, self.table)

    def _fetch(self) -> Dict[str, Dict[str, float]]:
        headers = {}
        key = os.environ.get("OPENROUTER_API_KEY")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        table: Dict[str, Dict[str, float]] = {}
        try:
            response = requests.get(OPENROUTER_MODELS_URL, headers=headers, timeout=20)
            response.raise_for_status()
            for model in response.json().get("data", []):
                pricing = model.get("pricing", {})
                try:
                    table[model["id"]] = {
                        "input_per_mtok": float(pricing.get("prompt", 0)) * 1e6,
                        "output_per_mtok": float(pricing.get("completion", 0)) * 1e6,
                    }
                except (TypeError, ValueError):
                    continue
        except requests.RequestException:
            return {}
        return table

    def cost(self, model: str, input_tokens: int, output_tokens: int) -> Optional[float]:
        row = self.table.get(model)
        if not row:
            return None
        return (
            input_tokens / 1_000_000.0 * row["input_per_mtok"]
            + output_tokens / 1_000_000.0 * row["output_per_mtok"]
        )
