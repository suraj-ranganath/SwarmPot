"""Versioned E-only policy. No provider calls or polling service of its own."""
NOTIFICATION_POLICY = {
    "version": "teammate-wake-v1",
    "initiation": "board_post(notify=true); default false",
    "dispatch": "next scheduler interval; one in-flight request per defender",
    "batch": "wake-causing messages first, then unread; at most 8 messages / 6500 JSON characters",
    "receipt": "successful provider response; failed/unknown requests retain pending IDs",
    "retry": "next scheduler interval, each attempt consumes a decision; no SDK retries",
    "quota": "existing shared decision and cost allowance; no renewal",
    "loops": "no self-wakes, no automatic replies, deduplicate by message ID and recipient",
}


def notification_policy(enabled: bool) -> dict:
    return {**NOTIFICATION_POLICY, "enabled": enabled}


def notification_config_audit(cfg) -> dict:
    """Narrow communication-policy audit, alongside the full paired audit.

    Preserve the actual schemas and scheduler interval, not only tool names.
    Earlier passive-board runs have no v1 policy fingerprint and are a distinct
    condition. This does not replace the broader environment/seed comparison.
    """
    from dataclasses import asdict
    from .defenders import _tool_schemas
    conditions = {}
    for arm in ('D', 'E'):
        enabled = cfg.arm(arm).board
        conditions[arm] = {
            'defender_allowance': asdict(cfg.defender),
            'defender_count': cfg.arm(arm).defenders,
            'scheduler_interval_seconds': cfg.defender.poll_seconds,
            'notification_policy': notification_policy(enabled),
            'tool_schemas': _tool_schemas(enabled),
        }
    left, right = conditions['D'], conditions['E']
    return {
        'version': 'board-config-audit-v1',
        'conditions': conditions,
        'matched_allowances': left['defender_allowance'] == right['defender_allowance'],
        'matched_scheduler': left['scheduler_interval_seconds'] == right['scheduler_interval_seconds'],
        'treatment': 'explicit board plus teammate-wake-v1; passive-board runs are a separate condition',
        'scope': 'communication only; use the full paired audit for world, seed, prompt and model parity',
    }
