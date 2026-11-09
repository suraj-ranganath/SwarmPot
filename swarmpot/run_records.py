"""Descriptive lifecycle facts. These never change budgets, grading or actions."""
from __future__ import annotations

import logging
import math
import re
from datetime import datetime, timezone
from pathlib import Path

from .util import append_jsonl, now_iso
from .view_data import read_object, redact

PHASES = {'setup': 'Setup & health checks', 'attack': 'Attacker & defender execution',
          'grading': 'Official grading', 'finalization': 'Cleanup & bookkeeping'}


def phase_for_stage(stage):
    if not isinstance(stage, str):
        return 'unknown'
    if stage in ('grading_start', 'grading_done', 'grading_skipped', 'metrics_written'):
        return 'grading'
    if stage in ('teardown_start', 'teardown_done', 'kept', 'attempt_finalized', 'teardown_error'):
        return 'finalization'
    if stage.startswith(('attacker_', 'supervisor_', 'worker_')) or stage in ('budget_stop', 'runner_started', 'runner_finished', 'ensure_subagent', 'spawn_refused'):
        return 'attack'
    return 'setup'


def parse_time(value):
    try:
        result = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (TypeError, ValueError):
        return None


def seconds_between(start, end):
    a, b = parse_time(start), parse_time(end)
    delta = (b - a).total_seconds() if a and b else None
    return delta if delta is not None and delta >= 0 else None


def duration(value):
    if value is None:
        return 'an unknown duration'
    value = round(value)
    return f'{value // 60}m {value % 60:02d}s' if value >= 60 else f'{value}s'


def termination_facts(root: Path, manifest=None, exit_record=None):
    manifest = manifest or read_object(root / 'manifest.json')
    summary = read_object(root / 'attacker/attacker_summary.json')
    budget = read_object(root / 'attacker/budget.json')
    exit_record = exit_record or read_object(root / 'attacker/exit.json')
    state = read_object(root / 'attacker/state.json')
    session = read_object(root / 'attacker/artemis_session/session_metadata.json').get('session_info', {})
    attempt = read_object(root / 'attempt.json')
    recorded = summary.get('termination') or {}
    # Resolved per-run budget wins over a YAML copy that can predate CLI overrides.
    minutes = manifest.get('budget', {}).get('attacker_wall_clock_minutes')
    if minutes is None:
        minutes = session.get('duration_minutes')
    if minutes is None:
        minutes = read_object(root / 'attacker/attacker_input.json').get('wall_clock_minutes')
    limit = float(minutes) * 60 if isinstance(minutes, (int, float)) else None
    def numeric(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0
    elapsed = summary.get('wall_seconds')
    if not numeric(elapsed):
        elapsed = None
    elapsed_source = 'attacker/attacker_summary.json:wall_seconds'
    if elapsed is None:
        elapsed = exit_record.get('waited_seconds')
        if not numeric(elapsed):
            elapsed = None
        elapsed_source = 'attacker/exit.json:waited_seconds'
    if elapsed is None:
        elapsed = seconds_between(state.get('StartedAt'), state.get('FinishedAt'))
        elapsed_source = 'attacker/state.json:StartedAt/FinishedAt'
    exited = (type(exit_record.get('exit_code')) is int and not exit_record.get('wait_error')) or state.get('Status') == 'exited'
    reason = recorded.get('reason') or summary.get('stop_reason') or budget.get('stop_reason') or attempt.get('stop_reason')
    reason_source = recorded.get('source') or ('attacker summary / budget / attempt' if reason else None)
    if exit_record.get('wait_error') is True:
        reason, reason_source = 'controller_wait_error', 'attacker/exit.json:wait_error'
    elif exit_record.get('timed_out') is True:
        reason, reason_source = 'controller_wait_timeout', 'attacker/exit.json:timed_out'
    elif state.get('OOMKilled') is True:
        reason, reason_source = 'out_of_memory', 'attacker/state.json:OOMKilled'
    elif attempt.get('status') == 'interrupted':
        reason, reason_source = 'operator_interrupt', 'attempt.json:status'
    elif not reason and exit_record.get('exit_code') not in (None, 0):
        reason, reason_source = 'process_error', 'attacker/exit.json:exit_code'
    # Legacy logs sometimes contain an explicit finish/interrupt/error message.
    if not reason:
        try:
            with (root / 'attacker/supervisor.log').open('rb') as handle:
                handle.seek(max(0, handle.seek(0, 2) - 128 * 1024))
                text = handle.read().decode('utf-8', errors='replace')
            for marker, name in [('Supervisor completed session after benchmark submission', 'benchmark_submission'),
                                 ('Supervisor completed session after submission (finish_on_submit mode)', 'submission'),
                                 ('CRITICAL ERROR - Supervisor exiting', 'supervisor_internal_error'),
                                 ('Supervisor interrupted', 'operator_interrupt')]:
                if marker in text:
                    reason, reason_source = name, 'attacker/supervisor.log:explicit message'
                    break
            if not reason and re.search(r'Supervisor completed session\s*$', text, re.M):
                reason, reason_source = 'supervisor_finished', 'attacker/supervisor.log:explicit message'
        except OSError:
            pass
    early = elapsed < limit if exited and elapsed is not None and limit is not None else None
    labels = {'wall_clock_limit': 'the supervisor reached its configured time deadline',
              'tool_budget_exhausted': 'the shared tool-action budget was exhausted',
              'supervisor_finished': 'the supervisor declared the session finished',
              'benchmark_submission': 'the supervisor ended after a benchmark submission',
              'submission': 'the supervisor ended after a submission',
              'operator_interrupt': 'an operator interrupted execution',
              'supervisor_internal_error': 'the supervisor encountered a critical internal error',
              'controller_wait_error': 'the Docker wait command failed; the attacker process exit is unconfirmed',
              'controller_wait_timeout': 'the controller wait timed out and requested a stop',
              'out_of_memory': 'Docker recorded an out-of-memory kill',
              'process_error': 'the attacker process exited with an error'}
    reason_text = labels.get(reason, str(reason).replace('_', ' ')) if reason else 'the exact stop reason was not recorded'
    code = exit_record.get('exit_code', state.get('ExitCode'))
    title = 'Attacker process still unconfirmed' if not exited else ('Attacker stopped before its time allowance' if early else 'Attacker process exited')
    description = f'Elapsed {duration(elapsed)}'
    if limit is not None:
        description += f' against the resolved {duration(limit)} allowance'
    if code is not None:
        description += f'; process exit code {code}'
    description += f'. {reason_text[0].upper() + reason_text[1:]}.'
    if early:
        description += f' It ended {duration(limit - elapsed)} before the time allowance; this alone does not explain why.'
    elif early is False:
        description += f' It did not finish early against that allowance (overrun {duration(max(0, elapsed - limit))}).'
    if reason is None and exited and session.get('planned_end_time'):
        description += ' A planned supervisor deadline is recorded, but deadline timing alone does not prove the exit cause.'
    if not exited:
        description = ('No attacker process exit has been confirmed. ' + reason_text[0].upper() + reason_text[1:] + '.' if reason in ('controller_wait_error', 'controller_wait_timeout') else 'No attacker process exit has been recorded yet. The stop reason and final duration are not available.')
    return {'version': 'run-lifecycle-v1', 'exited': exited, 'title': title, 'description': description,
            'reason': reason, 'reason_source': reason_source, 'elapsed_seconds': elapsed,
            'elapsed_source': elapsed_source, 'wall_clock_limit_seconds': limit,
            'ended_before_time_allowance': early, 'exit_code': code, 'timed_out': exit_record.get('timed_out'),
            'planned_end_time': session.get('planned_end_time'), 'actual_end_time': session.get('actual_end_time'),
            'actions_used': budget.get('counted', summary.get('counted_actions')),
            'action_limit': budget.get('limit', summary.get('max_tool_actions'))}


def finalization_facts(final, *, metrics_written=None, grader_status=None):
    status, valid = final.get('status'), final.get('valid')
    explanation = 'The controller saved the final attempt/ledger record, including which execution, grading and cleanup steps completed. '
    explanation += f'Recorded status: {status or "unknown"}. '
    explanation += ('This attempt is marked eligible for valid-run analysis. ' if valid is True else 'This attempt is marked ineligible for valid-run analysis. ' if valid is False else 'Analysis eligibility was not recorded. ')
    if final.get('exclusion_reason'):
        explanation += 'Exclusion reason: ' + str(final['exclusion_reason']) + '. '
    explanation += 'Completed means the harness finished its bookkeeping; it does not mean the attack succeeded.'
    return {'version': 'run-lifecycle-v1', 'title': 'Run record finalized', 'description': explanation,
            'status': status, 'valid': valid, 'exclusion_reason': final.get('exclusion_reason'),
            'metrics_written': metrics_written, 'official_attack_success': grader_status,
            'error': final.get('error')}


class LifecycleCapture(logging.Handler):
    """Observe the pinned ARTEMIS logger; never alter its execution or tools."""
    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        self.planned_end = None
        self.running_probe = lambda: None
        self.termination = {}

    def emit(self, record):
        try:
            text = record.getMessage()
            if 'Session will end at:' in text:
                stamp = text.split('Session will end at:', 1)[1].strip().replace(' UTC', '+00:00')
                self.planned_end = parse_time(stamp)
            reason = None
            for marker, name in [('Supervisor completed session after benchmark submission', 'benchmark_submission'),
                                 ('Supervisor completed session after submission (finish_on_submit mode)', 'submission'),
                                 ('CRITICAL ERROR - Supervisor exiting', 'supervisor_internal_error'),
                                 ('Supervisor interrupted', 'operator_interrupt')]:
                if marker in text:
                    reason = name
                    break
            if text.endswith('Supervisor completed session'):
                reason = 'supervisor_finished'
            if 'Supervisor loop completed' in text and not self.termination:
                # At this exact log site upstream has left `while running and
                # deadline > now`, before shutdown sets running=False.
                if self.running_probe() is True and self.planned_end and record.created >= self.planned_end.timestamp():
                    reason = 'wall_clock_limit'
            if reason:
                self.termination = {'reason': reason, 'source': 'artemis_loop_observation',
                                    'occurred_at': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
                                    'evidence': text, 'planned_end_time': self.planned_end.isoformat() if self.planned_end else None}
                self._write('supervisor_stopped', self.termination)
            if 'Force killing instance ' in text:
                self._write('worker_shutdown_requested', {'reason': 'supervisor_cleanup', 'evidence': text})
            elif 'Supervisor shutdown complete' in text:
                self._write('supervisor_shutdown_completed', {'evidence': text})
        except Exception:
            self.handleError(record)

    def _write(self, stage, payload):
        append_jsonl(self.path, redact({'ts': now_iso(), 'actor': 'system', 'kind': 'lifecycle',
                                      'payload': {'stage': stage, 'phase': 'attack', **payload}}))
