"""Optional browser check; fixtures live only on an isolated temporary server."""
import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from swarmpot.board_view import make_server
from test_run_inspection import setup_run

pytestmark=pytest.mark.skipif(os.environ.get('SWARMPOT_BROWSER_CHECK')!='1', reason='optional browser check')


def test_summary_phase_drilldown_and_raw_trace(tmp_path):
    episode=tmp_path/'episode';episode.mkdir()
    setup_run(episode)
    (episode/'attacker/attacker_events.jsonl').write_text(json.dumps({'ts':'2026-11-09T02:02:00Z','actor':'attacker','kind':'tool_call','agent_id':'worker-1','payload':{'command':'curl http://target:9090/','password':'must-not-appear'}})+'\n')
    server=make_server(tmp_path,0,include_fixtures=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    def browser(*args):
        p=subprocess.run(['agent-browser','--session','swarmpot-recap-check',*args],capture_output=True,text=True,timeout=30)
        assert p.returncode==0,p.stderr
        return p.stdout
    def ev(code):return json.loads(browser('eval',code))
    def wait(code):
        deadline=time.monotonic()+6
        while time.monotonic()<deadline:
            if ev(code):return
            time.sleep(.1)
        raise AssertionError(code)
    def select(id,value):ev(f"document.getElementById('{id}').value={json.dumps(value)};document.getElementById('{id}').dispatchEvent(new Event('change'));true")
    def hashes():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in episode.rglob('*') if p.is_file()}
    before=hashes()
    try:
        browser('set','viewport','1440','1000');browser('open',f'http://127.0.0.1:{server.server_port}')
        wait("document.querySelector('#feed').textContent.includes('3m 47s')")
        assert ev("document.querySelector('#feed').textContent.includes('not finish early')")
        assert ev("document.querySelector('#feed').textContent.includes('does not mean the attack succeeded')")
        browser('click','#channel-activity')
        wait("document.querySelector('#feed').textContent.includes('Attacker process exited')")
        browser('find','role','button','click','--name','Event 3: Attacker process exited')
        assert ev("document.querySelector('#details').textContent.includes('exact stop reason was not recorded')")
        browser('click','#channel-traces')
        select('phase','grading')
        wait("document.querySelectorAll('.trace-message').length===2")
        assert ev("[...document.querySelectorAll('.trace-origin')].every(e=>e.textContent.includes('grading'))")
        select('phase','attack');select('trace-source','attacker')
        wait("document.querySelector('#feed').textContent.includes('curl http://target:9090/')")
        browser('find','role','button','click','--name','Inspect trace attacker:0')
        assert ev("!document.querySelector('#details').textContent.includes('must-not-appear')")
        assert ev("document.querySelector('#details').textContent.includes('[redacted]')")
        browser('click','#close-details');browser('click','#channel-summary')
        browser('set','viewport','390','844')
        assert ev('document.documentElement.scrollWidth<=window.innerWidth')
        assert hashes()==before
    finally:
        browser('close');server.shutdown();server.server_close()
