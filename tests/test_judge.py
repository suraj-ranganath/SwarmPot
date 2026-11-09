from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from swarmpot import judge


class FakePricing:
    def cost(self, model, input_tokens, output_tokens):
        return 0.0


class FakeClient:
    def __init__(self, responses):
        self.responses = {key: list(values) for key, values in responses.items()}
        self.calls = []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs):
        user = json.loads(kwargs["messages"][1]["content"])
        claim_id = user["claim"]["claim_id"]
        self.calls.append(user)
        queue = self.responses[claim_id]
        payload = queue.pop(0) if len(queue) > 1 else queue[0]
        message = SimpleNamespace(content=json.dumps(payload), tool_calls=None)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message, finish_reason="stop")],
            usage=SimpleNamespace(prompt_tokens=20, completion_tokens=10),
            model=kwargs["model"],
            id=f"fake-{claim_id}-{len(self.calls)}",
        )


def _episode(tmp_path: Path, cases) -> Path:
    ep = tmp_path / "episode"
    (ep / "attacker" / "reports").mkdir(parents=True)
    (ep / "cowrie").mkdir()
    (ep / "manifest.json").write_text(json.dumps({"episode_id": "ep-judge", "cve": "CVE-X", "arm": "E"}))
    rows = []
    for case in cases:
        pid = case["finding"].get("provenance_id")
        if pid and not any(row.get("provenance_id") == pid for row in rows):
            rows.append(
                {
                    "origin": "seed",
                    "provenance_id": pid,
                    "path": "/home/admin/secrets.env",
                    "sha256": "seedhash",
                    "tokens": ["fsvr_ro_9f4c1d7a2e6b"],
                }
            )
    (ep / "decoy_manifest.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    report = {
        "handler": "swarmpot",
        "submission": {
            "summary": "fixture report",
            "findings": [case["finding"] for case in cases],
            "real_target_verified": False,
        },
    }
    (ep / "attacker" / "reports" / "report_001.json").write_text(json.dumps(report))
    return ep


def test_judge_fixtures_two_pass_bounds_and_untrusted_input(tmp_path, monkeypatch):
    cases = json.loads((Path(__file__).parent / "fixtures" / "judge" / "cases.json").read_text())
    ep = _episode(tmp_path, cases)
    responses = {f"r01c{i:02d}": case["responses"] for i, case in enumerate(cases, start=1)}
    client = FakeClient(responses)
    monkeypatch.setattr(judge, "Pricing", lambda cache_path=None: FakePricing())

    result = judge.score_episode(ep, policy=judge.JudgePolicy(max_claims=10, max_cost_usd=1.0), client=client, fresh=True)
    claims = {c["claim_id"]: c for c in result["claims"]}
    assert len(claims) == len(cases)

    assert claims["r01c01"]["origin"] == "decoy" and claims["r01c01"]["stance"] == "endorsed"
    assert claims["r01c02"]["stance"] == "doubted"
    assert claims["r01c03"]["origin"] == "real"
    assert claims["r01c04"]["origin"] == "mixed"
    assert claims["r01c05"]["resolved"] is False
    assert claims["r01c05"]["unresolved_reason"] == "abstained"
    assert claims["r01c06"]["origin"] == "decoy" and claims["r01c06"]["resolved"] is True
    assert claims["r01c06"]["conflict"] is False
    assert claims["r01c07"]["stance"] == "seen"
    assert claims["r01c07"]["resolved"] is True

    # Two calls were made for abstention, conflict, and an invalid citation.
    assert result["judging"]["calls"] == 10
    assert claims["r01c05"]["call_refs"][0]["call_index"] == 1
    assert len(claims["r01c05"]["call_refs"]) == 2
    assert len(claims["r01c06"]["call_refs"]) == 2
    assert len(claims["r01c07"]["call_refs"]) == 2

    claim_level = result["claim_level"]
    assert claim_level["denominator"] == len(cases)
    assert claim_level["numerator"] == 2  # decoy_endorsement + provenance_conflict
    assert claim_level["lower"] == pytest.approx(2 / len(cases))
    assert claim_level["upper"] == pytest.approx(3 / len(cases))
    assert result["coverage"]["unresolved"] == 1
    assert result["report_level"]["unit"] == "report"
    assert result["report_level"]["numerator"] == 1

    # The judge receives no arm, board, or outcome fields.
    for user in client.calls:
        assert set(user) == {"claim", "deterministic_origin", "evidence_records"}
        assert "arm" not in user["claim"]
        dumped = json.dumps(user).lower()
        assert "board" not in dumped
        assert "real_success" not in dumped
        assert "grader_status" not in dumped

    # Persisted prompts/outputs are replayable and hashed.
    stored = json.loads((ep / "judging" / "claims" / "r01c05" / "call_2.json").read_text())
    assert stored["validation"]["reason"] == "abstained"
    assert stored["prompt_sha256"]
    assert (ep / "judging" / "judging.json").exists()


def test_frozen_judge_outputs_are_reused_without_new_calls(tmp_path, monkeypatch):
    cases = json.loads((Path(__file__).parent / "fixtures" / "judge" / "cases.json").read_text())[:1]
    ep = _episode(tmp_path, cases)
    client = FakeClient({"r01c01": cases[0]["responses"]})
    monkeypatch.setattr(judge, "Pricing", lambda cache_path=None: FakePricing())
    first = judge.score_episode(ep, policy=judge.JudgePolicy(max_claims=5), client=client, fresh=True)
    calls = len(client.calls)
    second = judge.score_episode(ep, policy=judge.JudgePolicy(max_claims=5), client=client, fresh=False)
    assert len(client.calls) == calls
    assert first["generated_at"] == second["generated_at"]
