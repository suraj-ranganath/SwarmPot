"""Deterministic, source-backed run summaries and bounded operator traces.

No model calls, scoring changes, Docker access or agent cursor mutations.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .run_records import PHASES, finalization_facts, parse_time, termination_facts, duration, seconds_between
from .view_data import read_object, redact

SCAN_BYTES = 2 * 1024 * 1024
RECORD_BYTES = 128 * 1024
DISPLAY_CHARS = 24000



def _payload(row):
    value = row.get('payload')
    return value if isinstance(value, dict) else {}

def records(path):
    try:
        with path.open('rb') as handle:
            size = handle.seek(0, 2)
            start = max(0, size - SCAN_BYTES)
            handle.seek(start)
            if start:
                handle.readline()
            lines = handle.read(SCAN_BYTES).splitlines(keepends=True)
    except OSError:
        return [], False
    out = []
    for line in lines:
        if not line.endswith(b'\n'):
            continue
        try:
            row = json.loads(line)
            if isinstance(row, dict):
                out.append(row)
        except (ValueError, UnicodeDecodeError):
            pass
    return out, bool(start)


def phase_windows(rows):
    lifecycle = [r for r in rows if r.get('kind') == 'lifecycle']
    def stamp(stage):
        return next((r.get('ts') for r in lifecycle if _payload(r).get('stage') == stage), None)
    start, attack, grading, cleanup, finish = (stamp(s) for s in ('seed', 'attacker_started', 'grading_start', 'teardown_start', 'attempt_finalized'))
    return [{'id': 'setup', 'title': PHASES['setup'], 'start': start, 'end': attack},
            {'id': 'attack', 'title': PHASES['attack'], 'start': attack, 'end': grading or cleanup},
            {'id': 'grading', 'title': PHASES['grading'], 'start': grading, 'end': cleanup},
            {'id': 'finalization', 'title': PHASES['finalization'], 'start': cleanup, 'end': finish}]


def record_phase(row, windows):
    explicit = _payload(row).get('phase')
    if explicit in PHASES:
        return explicit
    stage = _payload(row).get('stage')
    if stage:
        from .run_records import phase_for_stage
        return phase_for_stage(stage)
    if row.get('kind') == 'grader':
        return 'grading'
    if row.get('kind') in ('artifact', 'attempt_error', 'interrupted'):
        return 'finalization' if row.get('kind') == 'artifact' else 'attack'
    ts = parse_time(row.get('ts') or row.get('timestamp'))
    if not ts:
        return 'unknown'
    for window in reversed(windows):
        start, end = parse_time(window['start']), parse_time(window['end'])
        if start and ts >= start and (not end or ts < end):
            return window['id']
    return 'unknown'


def sources(root):
    candidates = [('controller', 'Controller lifecycle & defender audit', 'events.jsonl', 'jsonl'),
                  ('attacker', 'Attacker commands & lifecycle', 'attacker/attacker_events.jsonl', 'jsonl'),
                  ('http', 'HTTP requests & lure responses', 'sidecar/sidecar.jsonl', 'jsonl'),
                  ('ssh', 'Cowrie connections, logins & commands', 'cowrie/cowrie.json', 'jsonl'),
                  ('supervisor', 'Supervisor operational log', 'attacker/supervisor.log', 'text')]
    workspaces = root / 'attacker/artemis_session/workspaces'
    if workspaces.is_dir() and not workspaces.is_symlink():
        for folder in sorted(workspaces.iterdir())[:50]:
            if folder.is_dir() and not folder.is_symlink() and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', folder.name):
                candidates.append(('worker:'+folder.name, 'Worker '+folder.name+' · tool requests & results', str((folder / 'realtime_context.txt').relative_to(root)), 'worker'))
    agents = root / 'agents'
    if agents.is_dir() and not agents.is_symlink():
        for folder in sorted(agents.glob('defender-*'))[:4]:
            for call in sorted((folder / 'decisions').glob('*.json'))[:100]:
                candidates.append(('decision:'+folder.name+':'+call.stem, folder.name+' · decision '+call.stem, str(call.relative_to(root)), 'decision'))
    out = []
    for key, title, name, kind in candidates:
        path = root / name
        if path.is_file() and root.resolve() in path.resolve().parents and not any(p.is_symlink() for p in [path, *path.parents] if p != root.parent):
            out.append({'id': key, 'title': title, 'path': name, 'kind': kind, 'bytes': path.stat().st_size})
    return out


def build_inspection(root, manifest, rows):
    metrics, attempt = read_object(root / 'metrics.json'), read_object(root / 'attempt.json')
    audit = metrics.get('audit', {})
    windows = phase_windows(rows)
    attacker = audit.get('attacker', {})
    recorded_budget = read_object(root / 'attacker/budget.json')
    original_summary = read_object(root / 'attacker/attacker_summary.json')
    by_class = recorded_budget.get('by_class') or attacker.get('by_class') or original_summary.get('by_class') or {}
    used = recorded_budget.get('counted', attacker.get('counted_actions', original_summary.get('counted_actions')))
    terminal = termination_facts(root, manifest)
    exit_event = next((r for r in reversed(rows) if _payload(r).get('stage') == 'attacker_exit'), {})
    if not terminal['exited'] and exit_event:
        terminal = termination_facts(root, manifest, exit_event['payload'])
    final = next((r for r in reversed(rows) if _payload(r).get('stage') == 'attempt_finalized'), None)
    final_data = {**attempt, **(final.get('payload', {}) if final else {})}
    grade = read_object(root / 'grader.json') or metrics.get('audit', {}).get('grader', {})
    grading_recorded = any(r.get('kind') == 'grader' or _payload(r).get('stage') == 'grading_done' for r in rows) or bool(audit.get('grader'))
    verdict = grade.get('status') if grading_recorded and isinstance(grade.get('status'), bool) and not grade.get('grader_error') else None
    ssh, ssh_windowed = records(root / 'cowrie/cowrie.json')
    ssh_available = (root / 'cowrie/cowrie.json').is_file()
    unphased_ssh = sum(record_phase(r, windows) == 'unknown' for r in ssh)
    if next((p for p in windows if p['id'] == 'attack'), {}).get('start'):
        ssh = [r for r in ssh if record_phase(r, windows) == 'attack']
    connections = {r['session'] for r in ssh if r.get('eventid') == 'cowrie.session.connect' and r.get('session')}
    logins = sum(r.get('eventid') == 'cowrie.login.success' for r in ssh)
    commands = sum(r.get('eventid') == 'cowrie.command.input' for r in ssh)
    non_ssh = [r for r in ssh if r.get('eventid') == 'cowrie.client.version' and str(r.get('version', '')).startswith(('GET ', 'HEAD ', 'POST ', 'PUT ', 'OPTIONS '))]
    if manifest.get('config', {}).get('arms', {}).get(manifest.get('arm'), {}).get('decoy') is False:
        decoy_text = 'The decoy was disabled in this arm. Steering by a decoy is not applicable.'
    elif not ssh_available:
        decoy_text = 'SSH evidence is unavailable; decoy engagement is unknown.'
    elif unphased_ssh:
        decoy_text = f'Timestamped attack-phase records show {logins} successful login(s) and {commands} command(s), but {unphased_ssh} SSH record(s) cannot be assigned to a phase. Engagement totals are incomplete.'
    elif ssh_windowed:
        decoy_text = f'The recent SSH window contains {logins} successful login(s) and {commands} command(s); complete run totals are unavailable.'
    elif commands or logins:
        decoy_text = f'Cowrie recorded {logins} successful SSH login(s) and {commands} SSH command(s). This is observed engagement, not proof the decoy caused the final outcome.'
    elif connections:
        decoy_text = f'{len(connections)} connection(s) reached the SSH port, with no successful SSH login or SSH command recorded.'
        if non_ssh:
            decoy_text += ' A client sent an HTTP request banner to the SSH port, so a port connection is not confirmed interactive decoy use.'
    else:
        decoy_text = 'No connection to the decoy SSH port, successful login or SSH command was recorded.'
    target_text = f'{used} counted attacker tool action(s)' if used is not None else 'The total attacker action count is unavailable'
    if by_class:
        target_text += f": {by_class.get('real', 'unknown')} classified real-target, {by_class.get('decoy', 'unknown')} classified decoy, {by_class.get('other', 'unknown')} other."
    else:
        target_text += '.'
    agents = recorded_budget.get('by_agent') or original_summary.get('by_agent') or {}
    if agents:
        target_text += ' Recorded worker actions: ' + ', '.join(f'{name}: {count}' for name, count in agents.items()) + '.'
    target_text += ' Counts describe tool calls, not individual HTTP requests or verified exploit success.'
    defender = audit.get('defender', {})
    budget = defender.get('budget') or next((r.get('budget') for r in reversed(rows) if r.get('actor') == 'defender' and r.get('budget')), {})
    decisions = budget.get('decisions_used')
    edits = sum(r.get('kind') in ('decoy_edit', 'decoy_write') and r.get('status', 'committed') == 'committed' for r in rows)
    reported_messages = defender.get('board_messages')
    defender_text = f"{decisions if decisions is not None else 'Unknown'} defender decision(s), {edits} committed file edit(s) in the available audit window"
    if reported_messages is not None:
        defender_text += f', {reported_messages} recorded board message(s)'
    defender_text += '.'
    if manifest.get('config', {}).get('arms', {}).get(manifest.get('arm'), {}).get('defenders') == 0:
        defender_text = 'No defenders were configured for this arm.'
        decisions = 0
    if manifest.get('config', {}).get('arms', {}).get(manifest.get('arm'), {}).get('board') is False:
        defender_text += ' The explicit defender board was disabled in this arm.'
    windows = phase_windows(rows)
    final_fact = finalization_facts(final_data, metrics_written=(root / 'metrics.json').is_file(), grader_status=verdict)
    verdict_text = ('The unchanged official grader reported attack success.' if verdict is True else
                    'The unchanged official grader reported the real-target attack unsuccessful.' if verdict is False else
                    'No trustworthy official exploit verdict is recorded; the attack outcome is unknown.')
    if grade.get('grader_error'):
        verdict_text = 'Official grading failed; the exploit outcome is unknown. ' + str(grade.get('message') or grade.get('error') or 'No additional grader error detail was recorded.')
    narrative = [target_text, terminal['description'] if terminal['exited'] else 'No attacker process exit has been confirmed.', verdict_text, decoy_text, defender_text]
    return redact({'version': 'operator-summary-v1', 'narrative': narrative,
                   'termination': terminal, 'outcome': {'official_success': verdict, 'message': grade.get('message'), 'description': verdict_text},
                   'attacker': {'actions_used': used, 'action_limit': terminal['action_limit'], 'by_class': by_class, 'description': target_text},
                   'decoy': {'description': decoy_text, 'ssh_source_available': ssh_available, 'source_windowed': ssh_windowed, 'unphased_records': unphased_ssh,
                             'connections': len(connections) if ssh_available else None,
                             'successful_logins': logins if ssh_available and not unphased_ssh else None, 'commands': commands if ssh_available and not unphased_ssh else None,
                             'non_ssh_banners': len(non_ssh), 'causal_steering': 'not established', 'scope': 'attack phase when its start timestamp is recorded',
                             'lure_responses': audit.get('environment', {}).get('sidecar', {}).get('lure_responses'),
                             'metric_reported_decoy_entry': metrics.get('headline', {}).get('decoy_entry')},
                   'defender': {'description': defender_text, 'decisions': decisions, 'edits_in_window': edits, 'board_messages': reported_messages},
                   'finalization': final_fact if final else None,
                   'phases': [{**p, 'elapsed_seconds': seconds_between(p['start'], p['end'])} for p in windows],
                   'sources': sources(root), 'limits': ['Summary generated from recorded files without an LLM.', 'No claim that deception caused the outcome.', 'Missing evidence stays unknown; older raw artifacts are not rewritten.']})


def describe_event(row, inspection):
    """Human explanation plus source-backed facts, separate from raw records."""
    p = _payload(row)
    stage = p.get('stage')
    if stage == 'attacker_exit':
        t = inspection['termination']
        return {'title': t['title'], 'description': t['description'], 'phase': 'attack', 'sources': ['attacker','supervisor'], 'facts': t}
    if stage == 'attempt_finalized':
        f = inspection['finalization'] or finalization_facts(p)
        return {'title': f['title'], 'description': f['description'], 'phase': 'finalization', 'sources': ['controller'], 'facts': f}
    if stage == 'grading_done' or row.get('kind') == 'grader':
        return {'title': 'Official grading: '+('attack successful' if inspection['outcome']['official_success'] is True else 'attack unsuccessful' if inspection['outcome']['official_success'] is False else 'verdict unknown'),
                'description': inspection['outcome']['description'], 'phase': 'grading', 'sources': ['controller'], 'facts': inspection['outcome']}
    titles = {'attacker_started': ('Attacker container started', 'The attacker runtime was started with the resolved episode allowance. This does not itself prove any exploit action occurred.'),
              'teardown_start': ('Cleaning up the disposable environment', 'The controller began its cleanup command after execution and grading handling.'),
              'grading_skipped': ('Official grading was skipped', 'The controller skipped grading; the recorded reason is ' + str(p.get('reason', 'unavailable')) + '.'),
              'kept': ('Disposable environment intentionally retained', 'Cleanup was skipped because this episode was launched with environment retention enabled.'),
              'teardown_done': ('Disposable environment cleanup completed', 'The controller finished its cleanup command. Leftover container IDs, if any, are recorded separately.'),
              'metrics_written': ('Run measurements saved', 'The controller saved a metrics artifact containing the measurements available at that point in the run.'),
              'grading_start': ('Official grader started', 'The controller invoked the unchanged benchmark grader against the real application.'),
              'infra_up_start': ('Starting disposable services', 'The controller began starting the target and episode infrastructure.'),
              'health': ('Infrastructure health check', 'Recorded health checks indicate whether the prepared services responded, not whether an attack succeeded.')}
    if stage in titles:
        title, text = titles[stage]
        return {'title': title, 'description': text, 'phase': record_phase(row, inspection['phases']), 'sources': ['controller']}
    return None


def _safe_payload(value):
    """Bound individual values; redact() additionally omits model reasoning."""
    if isinstance(value, dict):
        return {str(k): _safe_payload(v) for k, v in list(value.items())[:100]}
    if isinstance(value, list):
        return [_safe_payload(v) for v in value[:100]]
    if isinstance(value, str) and len(value) > DISPLAY_CHARS:
        return value[:DISPLAY_CHARS] + '\n[excerpt truncated; original remains on disk]'
    return value


def trace_page(root, source, phase='all', cursor=0, limit=50):
    if phase not in ('all', *PHASES):
        raise ValueError('unknown phase')
    entry = next((r for r in sources(root) if r['id'] == source), None)
    if not entry:
        raise ValueError('unknown trace source')
    path = root / entry['path']
    rows, _ = records(root / 'events.jsonl')
    windows = phase_windows(rows)
    limit = max(1, min(int(limit), 100))
    items, scanned, invalid = [], 0, 0
    clipped_line = False
    cursor = int(cursor)
    if cursor < 0:
        raise ValueError('invalid cursor')
    if entry['kind'] == 'decision':
        if cursor:
            return {'source': entry, 'records': [], 'next_cursor': None, 'scan_limited': False}
        value = read_object(path)
        # Captured request/response, never provider-side hidden reasoning.
        stamp = value.get('started_at') or value.get('completed_at')
        row = {'ts': stamp, 'kind': 'defender_model_payload', 'agent_id': value.get('agent_id'), 'payload': value}
        if phase in ('all', 'attack'):
            items.append({'id': source+':0', 'source': entry['path'], 'offset': 0, 'ts': stamp, 'phase': 'attack', 'record': redact(_safe_payload(row)), 'excerpt': path.stat().st_size > DISPLAY_CHARS})
        return {'source': entry, 'records': items, 'next_cursor': None, 'scan_limited': False, 'missing': [] if value else ['Decision payload missing or exceeds the 1 MiB JSON bound.']}
    with path.open('rb') as handle:
        size = handle.seek(0, 2)
        if cursor > size:
            raise ValueError('cursor exceeds source')
        # Cursors must be line boundaries; paths are server-selected allowlisted
        # artifacts, never supplied filesystem paths.
        if cursor:
            handle.seek(cursor-1)
            if handle.read(1) != b'\n':
                raise ValueError('cursor must identify a complete line')
        handle.seek(cursor)
        while scanned < SCAN_BYTES and len(items) < limit:
            offset = handle.tell()
            raw = handle.readline(RECORD_BYTES+1)
            if not raw:
                break
            if not raw.endswith(b'\n') and handle.tell() == size:
                handle.seek(offset)  # concurrent partial tail: revisit next poll
                break
            oversized = len(raw) > RECORD_BYTES
            if oversized:
                # Drain only this oversized line, recording an explicit excerpt.
                more = raw
                while raw and not raw.endswith(b'\n') and scanned < SCAN_BYTES:
                    more = handle.readline(RECORD_BYTES+1)
                    scanned += len(more)
                    if not more or more.endswith(b'\n'):
                        break
                if more and not more.endswith(b'\n'):
                    clipped_line = True
                    break
                text = '[Oversized line omitted; inspect the original file on disk.]' if entry['kind'] == 'jsonl' else raw[:DISPLAY_CHARS].decode('utf-8', errors='replace')
            else:
                text = raw.decode('utf-8', errors='replace').rstrip('\n')
            scanned += len(raw)
            stamp = None
            if entry['kind'] == 'jsonl':
                try:
                    row = json.loads(text)
                    if not isinstance(row, dict):
                        raise ValueError()
                except ValueError:
                    invalid += 1
                    if not oversized:
                        continue
                    row = {'kind': 'oversized_record_excerpt', 'payload': {'excerpt': text}}
                # A controller file cannot leak records from another episode.
                expected = read_object(root / 'manifest.json').get('episode_id')
                if row.get('episode_id') not in (None, expected):
                    continue
                stamp = row.get('ts') or row.get('timestamp')
                actual_phase = record_phase(row, windows)
            elif entry['kind'] == 'worker':
                match = re.match(r'^\[(\d\d:\d\d:\d\d)\] (EXECUTING|COMMAND RESULT|TOOL CALL|TOOL RESULT|STDOUT|STDERR)(.*)$', text)
                # Tool results' continuation lines are intentionally exposed as
                # output excerpts, excluding system prompts and thought labels.
                if not match:
                    continue
                clock, name, body = match.groups()
                row = {'kind': 'worker_tool_trace', 'agent_id': source.split(':',1)[1], 'payload': {'event': name, 'text': body.strip()}}
                actual_phase = 'attack'
                stamp = clock  # time-of-day only; do not fabricate a date
                # Collect non-timestamp result continuations, with a hard bound.
                if name in ('COMMAND RESULT', 'TOOL RESULT'):
                    chunks, chars = [], 0
                    while scanned < SCAN_BYTES and chars < DISPLAY_CHARS:
                        pos = handle.tell(); continuation = handle.readline(RECORD_BYTES+1)
                        if not continuation:
                            break
                        if re.match(rb'^\[\d\d:\d\d:\d\d\]', continuation):
                            handle.seek(pos);break
                        if not continuation.endswith(b'\n'):
                            oversized = True
                            handle.seek(pos);break
                        decoded = continuation.decode('utf-8', errors='replace')
                        chars += len(decoded); scanned += len(continuation); chunks.append(decoded[:DISPLAY_CHARS])
                    row['payload']['output_excerpt'] = ''.join(chunks)[:DISPLAY_CHARS]
                    oversized = oversized or chars > DISPLAY_CHARS
            else:
                match = re.match(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d[,\.]\d+)\s+-\s+(\w+)\s+-\s+(.*)$', text)
                if not match:
                    continue
                stamp, level, body = match.groups()
                stamp = stamp.replace(',', '.')+'+00:00'  # runtime logger uses container UTC
                row = {'ts': stamp, 'kind': 'supervisor_log', 'payload': {'level': level, 'text': body}}
                actual_phase = record_phase(row, windows)
            if phase != 'all' and actual_phase != phase:
                continue
            items.append({'id': source+':'+str(offset), 'source': entry['path'], 'offset': offset,
                          'ts': stamp, 'phase': actual_phase, 'record': redact(_safe_payload(row)), 'excerpt': oversized or len(text)>DISPLAY_CHARS})
        next_cursor = handle.tell() if handle.tell() < size and not clipped_line else None
    return {'source': entry, 'records': items, 'next_cursor': next_cursor, 'scan_limited': scanned >= SCAN_BYTES, 'end_cursor': next_cursor if next_cursor is not None else size,
            'invalid_records_skipped': invalid, 'missing': ['A line exceeds the bounded scan window; the remaining original source stays on disk.'] if clipped_line else [], 'ordering': 'source file order; phase windows are timestamp evidence, not cross-process causal order'}
