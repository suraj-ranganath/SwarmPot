import hashlib
import json
import sqlite3
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from swarmpot.board_view import episode_list, make_server, snapshot
from test_notifications import make_team


def test_read_only_private_projection_and_legacy(tmp_path, monkeypatch):
    team, board, (a, b) = make_team(tmp_path / 'run', monkeypatch)
    root = tmp_path / 'run'
    (root / 'manifest.json').write_text(json.dumps({'episode_id': 'fixture', 'arm': 'E', 'config': {'arms': {'E': {'defenders': 2}}}}))
    a._execute_tool('board_post', {'body': '<script>alert(1)</script> password=unrelated-sensitive-secret', 'notify': True})
    with sqlite3.connect(board.path) as db:
        db.execute("INSERT INTO messages (episode,team,sender,ts,body) VALUES ('fixture','attackers','x','now','PRIVATE TEAM DATA')")
    def digest():
        return [(p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in root.rglob('*') if p.is_file()]
    before = digest()
    first = snapshot(tmp_path, 'run', include_fixtures=True)
    second = snapshot(tmp_path, 'run', include_fixtures=True)
    assert first == second
    assert digest() == before and board.pending(b.agent_id) == [1] and b.decisions == 0
    assert 'unrelated-sensitive-secret' not in json.dumps(first) and 'PRIVATE TEAM DATA' not in json.dumps(first)
    assert first['cards'][0]['state'] == 'unknown'
    with pytest.raises(ValueError):
        snapshot(tmp_path, '../')
    server = make_server(tmp_path, 0, include_fixtures=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}'
    try:
        assert urlopen(url + '/').status == 200
        assert json.load(urlopen(url + '/api/snapshot?episode=run')) == first
        with pytest.raises(HTTPError) as exc:
            urlopen(Request(url, data=b'{}'))
        assert exc.value.code == 405
        with pytest.raises(HTTPError) as exc:
            urlopen(Request(url, headers={'Host': 'external.example'}))
        assert exc.value.code == 403
    finally:
        server.shutdown()
        server.server_close()


def test_normal_view_excludes_fixtures_controls_and_unstarted_environments(tmp_path):
    def episode(name, **fields):
        root = tmp_path / name
        root.mkdir()
        manifest = {'episode_id': name, 'arm': 'E', 'cve': 'CVE-2024-2624', **fields}
        (root / 'manifest.json').write_text(json.dumps(manifest))
        return root
    real = episode('real-run')
    (real / 'attempt.json').write_text(json.dumps({'episode_id': 'real-run', 'attacker_started': True, 'status': 'completed'}))
    legacy = episode('legacy-real')
    (legacy / 'events.jsonl').write_text(json.dumps({'episode_id': 'legacy-real', 'actor': 'system', 'kind': 'lifecycle', 'payload': {'stage': 'attacker_started'}})+'\n')
    prepared = episode('prepared-only')
    # Real hosted defender decisions during verification do not make a run a benchmark episode.
    (prepared / 'events.jsonl').write_text(json.dumps({'episode_id': 'prepared-only', 'actor': 'defender', 'kind': 'llm_decision', 'payload': {'content': 'A hosted reply'}})+'\n')
    fixture = episode('hosted-fixture', evidence_kind='hosted controlled fixture')
    (fixture / 'attempt.json').write_text(json.dumps({'episode_id': 'hosted-fixture', 'attacker_started': True}))
    episode('standalone-smoke', cve='none — communication fixture')
    episode('unstarted-real')
    assert {r['id'] for r in episode_list(tmp_path)['episodes']} == {'real-run', 'legacy-real'}
    for excluded in ('prepared-only', 'hosted-fixture', 'standalone-smoke', 'unstarted-real'):
        with pytest.raises(ValueError):
            snapshot(tmp_path, excluded)
    assert snapshot(tmp_path, 'real-run')['attempt_status'] == 'completed'
    assert len(episode_list(tmp_path, include_fixtures=True)['episodes']) == 6
    server = make_server(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}'
    try:
        assert {r['id'] for r in json.load(urlopen(url+'/api/episodes?include_fixtures=true'))['episodes']} == {'real-run', 'legacy-real'}
        with pytest.raises(HTTPError) as exc:
            urlopen(url+'/api/snapshot?episode=hosted-fixture&include_fixtures=true')
        assert exc.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
