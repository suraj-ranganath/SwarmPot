"""Optional real-browser acceptance check (agent-browser CLI required).

SWARMPOT_BROWSER_CHECK=1 SWARMPOT_BROWSER_ARTIFACTS=docs/board-evidence pytest tests/test_board_browser.py
All agent responses in this test are explicitly deterministic stubs.
"""
import hashlib
import json
import os
import sqlite3
import subprocess
import threading
import time
from pathlib import Path

import pytest

from swarmpot.board_view import make_server
from swarmpot.notifications import notification_policy
from test_notifications import make_team, response

pytestmark = pytest.mark.skipif(os.environ.get('SWARMPOT_BROWSER_CHECK') != '1', reason='optional real-browser check')


def test_read_only_browser_live_completed_missing_and_disconnected(tmp_path, monkeypatch):
    out = Path(os.environ.get('SWARMPOT_BROWSER_ARTIFACTS', tmp_path / 'screenshots')).resolve()
    out.mkdir(parents=True, exist_ok=True)
    team, board, (a, b) = make_team(tmp_path / 'live', monkeypatch)
    board.max_messages = 40
    manifest = {'episode_id': 'fixture', 'arm': 'E', 'evidence_kind': 'deterministic browser fixture',
                'board_notification_policy': notification_policy(True), 'config': {'arms': {'E': {'defenders': 2}}}}
    (tmp_path / 'live' / 'manifest.json').write_text(json.dumps(manifest))
    legacy = tmp_path / 'legacy';legacy.mkdir()
    (legacy / 'manifest.json').write_text(json.dumps({'episode_id': 'legacy', 'arm': 'D', 'config': {'arms': {'D': {'defenders': 2}}}}))
    with sqlite3.connect(legacy / 'board.sqlite') as db:
        db.execute('CREATE TABLE messages(seq INTEGER,episode TEXT,team TEXT,sender TEXT,ts TEXT,body TEXT)')
    server = make_server(tmp_path, 0)
    serving = threading.Thread(target=server.serve_forever, daemon=True);serving.start()
    stop = threading.Event()
    running = threading.Thread(target=team.run, args=(stop,), daemon=True);running.start()
    release, entered = threading.Event(), threading.Event()
    session = 'swarmpot-board-acceptance'
    def browser(*args):
        proc = subprocess.run(['agent-browser', '--session', session, *args], text=True, capture_output=True, timeout=30)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout
    def evaluate(code):
        return json.loads(browser('eval', code))
    def wait_for(code):
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            if evaluate(code): return
            time.sleep(.15)
        raise AssertionError('Browser condition timed out: '+code)
    def select(id, value):
        evaluate(f"document.getElementById('{id}').value={json.dumps(value)};document.getElementById('{id}').dispatchEvent(new Event('change'));true")
    def hashes():
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [board.path, a.events.path]}
    try:
        browser('set', 'viewport', '1440', '1000')
        browser('open', f'http://127.0.0.1:{server.server_port}')
        wait_for("document.querySelector('#episode').value==='live' && document.querySelector('#cards').textContent.includes('waiting')")
        assert evaluate("!document.body.textContent.includes('Wake defender')")
        before = hashes()
        browser('reload')
        wait_for("document.querySelector('#cards').textContent.includes('waiting')")
        assert hashes() == before
        browser('screenshot', str(out / 'empty.png'), '--full')
        # Long passive feed fills the scroll pane without starting any request.
        for i in range(18):
            a._execute_tool('board_post', {'body': f'Passive note {i}: '+('Preserve the deployment story. ' * 7)})
        wait_for("document.querySelectorAll('.message').length===18")
        assert b.decisions == 0
        browser('click', '#pause')
        evaluate("document.querySelector('#feed').scrollTop=0;true")
        def slow(**kwargs):
            entered.set()
            assert release.wait(20)
            return response([('write_decoy_file', {'path': '/home/admin/browser.txt', 'content': 'controlled browser fixture'})])
        b.client.chat.completions.create.side_effect = slow
        post = a._execute_tool('board_post', {'body': 'Please update browser.txt with the agreed story.', 'notify': True})
        assert entered.wait(2)
        wait_for("document.querySelector('#cards').textContent.includes('running') && document.querySelectorAll('.message').length===19")
        assert evaluate("document.querySelector('#feed').scrollTop===0")
        assert evaluate("document.querySelector('#pause').getAttribute('aria-pressed')==='true'")
        browser('screenshot', str(out / 'live-paused.png'), '--full')
        select('defender', 'defender-2')
        wait_for("document.querySelector('#feed').textContent.includes('No messages from this defender')")
        select('defender', '')
        release.set()
        wait_for("document.querySelector('#feed').textContent.includes('delivered')")
        assert (tmp_path / 'live' / 'home' / 'browser.txt').exists()
        browser('find', 'role', 'button', 'click', '--name', f"Message {post['seq']} from defender-1")
        wait_for("document.querySelector('#details').textContent.includes('board_delivery')")
        assert evaluate("document.querySelector('#details').textContent.includes('decoy_write') || document.querySelector('#details').textContent.includes('decoy_edit')")
        evaluate("document.querySelector('#details details').open=true;true")
        time.sleep(1.7)
        assert evaluate("document.querySelector('#details details').open")
        stop.set();running.join(3)
        wait_for("document.querySelector('#cards').textContent.includes('stopped')")
        browser('screenshot', str(out / 'completed.png'), '--full')
        before = hashes();browser('reload')
        wait_for("document.querySelector('#cards').textContent.includes('stopped')")
        assert hashes() == before
        select('arm', 'D')
        wait_for("document.querySelector('#notice').textContent.includes('no durable evidence')")
        assert evaluate("document.querySelector('#cards').textContent.includes('unknown')")
        browser('screenshot', str(out / 'missing-evidence.png'), '--full')
        select('arm', 'A')
        wait_for("document.querySelector('#feed').textContent.includes('No recorded runs')")
        select('arm', 'E')
        wait_for("document.querySelectorAll('.message').length>0")
        browser('set', 'viewport', '390', '844')
        assert evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        browser('screenshot', str(out / 'mobile.png'), '--full')
        browser('set', 'viewport', '1440', '1000')
        heap = evaluate('performance.memory ? performance.memory.usedJSHeapSize : null')
        browser('set', 'offline', 'on')
        wait_for("document.querySelector('#connection').textContent.includes('Disconnected')")
        browser('screenshot', str(out / 'disconnected.png'), '--full')
        browser('set', 'offline', 'off')
        wait_for("document.querySelector('#connection').textContent.includes('Connected')")
        summary = {'checks': ['empty', 'waiting', 'live running', 'pending wake', 'passive no inference', 'pause retains scroll while evidence updates', 'defender filter', 'delivery and commit links', 'expanded detail survives refresh', 'completed stopped', 'reload does not mutate DB/logs/decisions', 'arm filter', 'legacy missing evidence', 'no runs', 'mobile overflow', 'disconnected and recovery'],
                   'browser_js_heap_bytes': heap, 'browser_memory_scope': 'performance.memory.usedJSHeapSize, not whole-browser RSS',
                   'evidence_kind': 'deterministic model stubs and recorded fixture data', 'screenshots': sorted(p.name for p in out.glob('*.png'))}
        (out / 'browser-check.json').write_text(json.dumps(summary, indent=2)+'\n')
    finally:
        release.set();stop.set();running.join(3)
        browser('set', 'offline', 'off');browser('close')
        server.shutdown();server.server_close()
