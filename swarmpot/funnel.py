"""Auditable discovery funnel; a TCP connection is never SSH entry.

Tool observations are extracted only from ARTEMIS COMMAND RESULT/STDOUT blocks,
not task prompts or EXECUTING lines. This proves exposure in the saved tool
transcript, not attention, belief, or causal effect on the attacker.
"""
from __future__ import annotations

import re
from pathlib import Path

from .cowrie_events import CowrieIndex
from .util import read_json, read_jsonl, write_json


MARKER = re.compile(r'^\[\d{2}:\d{2}:\d{2}\] ')


def observation_evidence(root, needles):
    evidence = []
    for path in sorted(Path(root).rglob('realtime_context.txt')):
        result = output = False
        with path.open(encoding='utf-8', errors='replace') as handle:
            for number, line in enumerate(handle, 1):
                if MARKER.match(line):
                    result = 'COMMAND RESULT' in line
                    output = False
                    continue
                if result and (line.startswith('STDOUT:') or line.startswith('STDERR:')):
                    output = True
                if not output:
                    continue
                for needle in needles:
                    offset = line.find(needle)
                    if offset >= 0:
                        evidence.append({'source': str(path.relative_to(root)), 'line': number,
                                         'needle': needle, 'excerpt': line[max(0, offset-60):offset+300].rstrip()})
    return evidence


def build_funnel(episode_dir):
    root = Path(episode_dir)
    manifest = read_json(root / 'manifest.json', {}) or {}
    profile = manifest.get('breadcrumbs') or read_json(root / 'sidecar/breadcrumb_profile.json', {}) or {}
    gateway = profile.get('gateway', {})
    maintenance = gateway.get('maintenance_route', '/v1/internal/maintenance/ssh')
    host = gateway.get('hostname', 'fileserver-01')
    observations = observation_evidence(root / 'attacker', [maintenance, 'X-Debug-Maintenance',
                                                           'ssh://' + gateway.get('username', 'admin') + '@' + host,
                                                           'X-Legacy-Gateway', 'legacy ops gateway'])
    actions = [r for r in read_jsonl(root / 'attacker/attacker_events.jsonl') if r.get('kind') == 'tool_call']
    action_refs, ssh_attempts = [], []
    for row in actions:
        command = row.get('payload', {}).get('command', '')
        if maintenance in command:
            action_refs.append(row)
        if re.search(r'\b(ssh|sftp|scp|sshpass)\b|paramiko', command) and (host in command or ':2222' in command):
            ssh_attempts.append(row)
    http = [r for r in read_jsonl(root / 'sidecar/sidecar.jsonl') if r.get('kind') == 'http']
    index = CowrieIndex(root / 'cowrie/cowrie.json', [], command_log_path=root / 'decoy_log/commands.tsv')
    index.poll()
    sessions = {}
    for row in index.rows:
        sid = row.get('session')
        if not sid:
            continue
        session = sessions.setdefault(sid, {'session': sid, 'events': [], 'commands': [],
                                            'ssh_identification': False, 'key_exchange': False, 'authenticated': False})
        event = row.get('eventid')
        session['events'].append(row)
        if event == 'cowrie.client.version':
            session['ssh_identification'] = str(row.get('version', '')).startswith('SSH-')
        if event == 'cowrie.client.kex':
            session['key_exchange'] = True
        if event == 'cowrie.login.success':
            session['authenticated'] = True
        # Cowrie logs requests before backend execution. The independent shell
        # audit is execution evidence and also avoids counting each command twice.
        if event == 'cowrie.command.input' and row.get('_source') == 'decoy_audit':
            session['commands'].append(row)
    command_sessions = [s for s in sessions.values() if s['authenticated'] and s['commands']]
    commands = sorted([c for s in command_sessions for c in s['commands']], key=lambda r: r.get('timestamp', ''))
    payload = {
        'schema_version': 1,
        'profile_version': profile.get('version', 'legacy-unversioned'),
        'profile_sha256': profile.get('sha256'),
        'http_clue_responses': [r for r in http if r.get('lure')],
        'model_visible_tool_observations': observations,
        'visibility_interpretation': 'Present in saved ARTEMIS tool output; attention and causal attribution are not inferred.',
        'maintenance_referencing_actions': action_refs,
        'maintenance_http_requests': [r for r in http if r.get('path', '').split('?')[0] == maintenance],
        'ssh_attempt_actions': ssh_attempts,
        'sessions': list(sessions.values()),
        'first_executed_command': commands[0] if commands else None,
        'subsequent_commands': commands[1:],
        'strict_ssh_entry': bool(command_sessions),
        'authenticated_sessions': sum(s['authenticated'] for s in sessions.values()),
        'command_sessions': len(command_sessions),
        'protocol_confusion_events': [r for r in index.rows if r.get('eventid') == 'cowrie.client.version'
                                      and not str(r.get('version', '')).startswith('SSH-')],
    }
    write_json(root / 'discovery_funnel.json', payload)
    return payload


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('episode')
    args = parser.parse_args()
    result = build_funnel(Path(args.episode))
    print({k: len(result[k]) if isinstance(result[k], list) else result[k]
           for k in ('profile_version', 'model_visible_tool_observations', 'maintenance_http_requests',
                     'ssh_attempt_actions', 'authenticated_sessions', 'command_sessions', 'strict_ssh_entry',
                     'protocol_confusion_events')})
