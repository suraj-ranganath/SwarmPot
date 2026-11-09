"""Loopback-only, read-only projection of SQLite and recorded audit evidence.

No Board/Defender imports: viewing cannot advance delivery state or run models.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .util import RUNS_DIR

ASSETS = Path(__file__).with_name('board_ui')
EVENT_WINDOW = 2 * 1024 * 1024


def redact(value):
    if isinstance(value, dict):
        return {k: '[redacted]' if re.search(r'password|secret|api_key|authorization|credential|access_token', k, re.I)
                else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if not isinstance(value, str):
        return value
    for key, secret in os.environ.items():
        if re.search(r'KEY|TOKEN|PASSWORD|SECRET', key) and len(secret) >= 8:
            value = value.replace(secret, '[redacted]')
    value = re.sub(r'(?i)(bearer\s+)[\w.\-/+=]+', r'\1[redacted]', value)
    value = re.sub(r'(?i)((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|token|credential)[\w-]*[\s\"\x27]*[:=][\s\"\x27]*)[^\s,;\"\x27}]+',
                   r'\1[redacted]', value)
    value = re.sub(r'(?i)(https?://)[^\s/@:]+:[^\s/@]+@', r'\1[redacted]@', value)
    return re.sub(r'\bsk-[A-Za-z0-9_-]{12,}', '[redacted]', value)


def read_object(path):
    try:
        if path.stat().st_size > 1024 * 1024:
            return {}
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def audit_tail(path):
    """Bound memory and handle a concurrent partial JSONL tail without writes."""
    try:
        with path.open('rb') as handle:
            size = handle.seek(0, 2)
            start = max(0, size - EVENT_WINDOW)
            handle.seek(start)
            if start:
                handle.readline()
            data = handle.read(EVENT_WINDOW)
    except OSError:
        return [], False
    rows = deque(maxlen=2000)
    for line in data.splitlines(keepends=True):
        if not line.endswith(b'\n'):
            continue
        try:
            record = json.loads(line)
            if record.get('actor') == 'defender' or record.get('kind') == 'lifecycle':
                rows.append(record)
        except (ValueError, UnicodeDecodeError):
            continue
    return list(rows), bool(start or len(rows) == 2000)


def public_event(row):
    # Do not return tool bodies, private SSH streams, local paths or raw logs.
    payload = row.get('payload', {})
    keys = ('request_id', 'retry_of', 'provider_request_id', 'message_id', 'message_seqs', 'board_message_seqs',
            'board_context_message_seqs', 'recipient', 'origin', 'status', 'state',
            'reason', 'trigger', 'content', 'tool_names', 'path', 'edit_id',
            'provenance_id', 'commit_status', 'source_decision_event_id',
            'pending_message_seqs', 'policy', 'poll_seconds', 'stage', 'ok')
    shown = {k: payload[k] for k in keys if k in payload}
    if row.get('kind') == 'board_post':
        shown['message_id'] = payload.get('message_id', payload.get('seq'))
    if row.get('tool') == 'write_decoy_file':
        shown['path'] = payload.get('path', payload.get('args', {}).get('path'))
    return redact({k: row.get(k) for k in ('seq', 'ts', 'event_id', 'kind', 'agent_id',
                                         'tool', 'status', 'reason', 'parent_event_id', 'refs')}
                  | {'payload': shown})


def episode_list(root, offset=0):
    # Directory names only until selection; do not load all historical episodes.
    entries = sorted((p for p in root.iterdir() if p.is_dir() and not p.is_symlink()),
                     key=lambda p: p.name, reverse=True) if root.exists() else []
    out = []
    for path in entries[offset:offset + 100]:
        manifest = read_object(path / 'manifest.json')
        if manifest:
            out.append({k: manifest.get(k) for k in ('episode_id', 'arm', 'created_at', 'cve')}
                       | {'id': path.name, 'evidence_kind': manifest.get('evidence_kind')})
    return {'episodes': redact(out), 'next_offset': offset + 100 if len(entries) > offset + 100 else None}


def snapshot(root, episode, after=0):
    path = (root / episode).resolve()
    if path.parent != root.resolve() or not path.is_dir() or (root / episode).is_symlink():
        raise ValueError('unknown episode')
    manifest = read_object(path / 'manifest.json')
    if not manifest:
        raise ValueError('episode manifest unavailable')
    episode_id = manifest.get('episode_id')
    rows, windowed = audit_tail(path / 'events.jsonl')
    # Reject mixed episode data; the GUI never crosses team namespaces.
    rows = [r for r in rows if r.get('episode_id') == episode_id]
    messages, notifications, receipts, missing = [], [], [], []
    notifications_known = receipts_known = False
    db = path / 'board.sqlite'
    if db.is_file() and not db.is_symlink():
        try:
            with sqlite3.connect(db.as_uri() + '?mode=ro', uri=True, timeout=0.2) as conn:
                conn.row_factory = sqlite3.Row
                messages = [dict(r) for r in conn.execute(
                    'SELECT seq,sender,ts,body FROM messages WHERE episode=? AND team=? AND seq>? ORDER BY seq LIMIT 100',
                    (episode_id, 'defenders', after))]
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                notifications_known = 'notifications' in tables
                receipts_known = 'context_deliveries' in tables
                for table, target in [('notifications', notifications), ('context_deliveries', receipts)]:
                    if table in tables:
                        target.extend(dict(r) for r in conn.execute(
                            f'SELECT n.* FROM {table} n JOIN messages m ON m.seq=n.message_seq '
                            'WHERE m.episode=? AND m.team=? ORDER BY n.message_seq LIMIT 1000',
                            (episode_id, 'defenders')))
                    else:
                        missing.append(f'{table}: no durable evidence in this older run')
        except sqlite3.Error:
            notifications_known = receipts_known = False
            missing.append('Board database temporarily unavailable; retrying is safe')
    else:
        missing.append('No board database recorded (expected when board is disabled)')
    budget = next((r['budget'] for r in reversed(rows) if r.get('budget')), None)
    ids = sorted({r['agent_id'] for r in rows if r.get('agent_id')})
    arm_cfg = manifest.get('config', {}).get('arms', {}).get(manifest.get('arm'), {})
    for i in range(arm_cfg.get('defenders', 0)):
        if f'defender-{i + 1}' not in ids:
            ids.append(f'defender-{i + 1}')
    cards = []
    for agent_id in sorted(ids):
        own = [r for r in rows if r.get('agent_id') == agent_id]
        status = next((r for r in reversed(own) if r.get('kind') == 'defender_status'), None)
        last = next((r for r in reversed(own) if r.get('kind') in ('llm_decision', 'decoy_edit', 'decoy_write', 'tool_call', 'llm_error')), None)
        cards.append({'id': agent_id, 'state': status['payload'].get('state', 'unknown') if status else 'unknown',
                      'state_at': status.get('ts') if status else None,
                      'pending': [n['message_seq'] for n in notifications if n['recipient'] == agent_id and n['status'] == 'queued'],
                      'pending_known': notifications_known,
                      'unread_count': None,
                      'last': public_event(last) if last else None})
    if receipts_known:
        try:
            with sqlite3.connect(db.as_uri() + '?mode=ro', uri=True, timeout=0.2) as conn:
                for card in cards:
                    card['unread_count'] = conn.execute(
                        'SELECT COUNT(*) FROM messages m LEFT JOIN context_deliveries d '
                        'ON d.message_seq=m.seq AND d.recipient=? WHERE m.episode=? AND m.team=? '
                        'AND m.sender!=? AND d.message_seq IS NULL',
                        (card['id'], episode_id, 'defenders', card['id'])).fetchone()[0]
        except sqlite3.Error:
            pass
    if not any(r.get('kind') == 'defender_status' for r in rows):
        missing.append('Defender status not recorded; current activity is unknown')
    stage = next((r.get('payload', {}).get('stage') for r in reversed(rows) if r.get('kind') == 'lifecycle'), None)
    return redact({'episode': {k: manifest.get(k) for k in ('episode_id', 'arm', 'cve', 'created_at', 'evidence_kind')},
                   'policy': manifest.get('board_notification_policy'), 'stage': stage,
                   'messages': messages, 'next_after': messages[-1]['seq'] if messages else after,
                   'has_more': len(messages) == 100, 'notifications': notifications,
                   'notification_evidence_complete': notifications_known,
                   'receipts': receipts, 'cards': cards, 'budget': budget,
                   'events': [public_event(r) for r in rows], 'missing': missing,
                   'audit_windowed': windowed})


def make_server(root: Path, port: int = 8765):
    root = root.resolve()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, code, data, content_type='application/json'):
            if content_type == 'application/json':
                data = json.dumps(data).encode()
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.headers.get('Host', '').split(':')[0] not in ('127.0.0.1', 'localhost'):
                return self.reply(403, {'error': 'Loopback host required'})
            url = urlparse(self.path)
            query = parse_qs(url.query)
            try:
                if url.path == '/api/episodes':
                    return self.reply(200, episode_list(root, max(0, int(query.get('offset', ['0'])[0]))))
                if url.path == '/api/snapshot':
                    return self.reply(200, snapshot(root, query.get('episode', [''])[0], max(0, int(query.get('after', ['0'])[0]))))
                asset = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}.get(url.path)
                if asset:
                    kind = {'index.html': 'text/html; charset=utf-8', 'app.js': 'text/javascript; charset=utf-8', 'style.css': 'text/css; charset=utf-8'}[asset]
                    return self.reply(200, (ASSETS / asset).read_bytes(), kind)
                self.reply(404, {'error': 'Not found'})
            except (ValueError, OSError):
                self.reply(404, {'error': 'Evidence unavailable'})

        def do_POST(self):
            self.reply(405, {'error': 'Read-only observer'})

    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs-dir', type=Path, default=RUNS_DIR)
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    server = make_server(args.runs_dir, args.port)
    print(f'Read-only defender board: http://127.0.0.1:{server.server_port} (runs: {args.runs_dir})', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
