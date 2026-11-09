"""Controlled board smoke; no Docker or attacker traffic.

python scripts/verify_board.py --out runs/board-fixture
python scripts/verify_board.py --out runs/board-hosted --hosted

The hosted variant explicitly asks the sender to notify and the receiver to
perform a permitted edit. It verifies plumbing, not spontaneous cooperation.
"""
from __future__ import annotations

import argparse
import json
import resource
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace as NS

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from swarmpot.board import Board
from swarmpot.board_view import redact
from swarmpot.cowrie_events import CowrieIndex
from swarmpot.defenders import DecoyFiles, DecoyManifest, DefenderAgent, DefenderBudget, DefenderTeam
from swarmpot.events import EventLog
from swarmpot.notifications import notification_policy
from swarmpot.pricing import Pricing
from swarmpot.util import now_iso, write_json


def fixture_response(name, args):
    return NS(usage=NS(prompt_tokens=180, completion_tokens=40), model='scripted-fixture', id='fixture-response',
              choices=[NS(finish_reason='tool_calls', message=NS(content='Controlled fixture action.', tool_calls=[
                  NS(id='fixture-call', function=NS(name=name, arguments=json.dumps(args)))]))])


def run(out, hosted):
    if out.exists():
        raise SystemExit('Choose a new output directory; existing evidence is preserved.')
    out.mkdir(parents=True)
    episode = out.name
    write_json(out / 'manifest.json', {'episode_id': episode, 'arm': 'E', 'created_at': now_iso(),
               'cve': 'none — communication fixture', 'evidence_kind': 'hosted controlled fixture' if hosted else 'deterministic model stub',
               'board_notification_policy': notification_policy(True),
               'config': {'arms': {'E': {'defenders': 2}}}})
    events = EventLog(out, episode, 'E')
    board = Board(out / 'board.sqlite', episode, 'defenders', 6)
    budget = DefenderBudget(8, 2, .10)
    index = CowrieIndex(out / 'cowrie.json', ['defender-1', 'defender-2'])
    pricing = Pricing() if hosted else NS(cost=lambda *args: 0.0001)
    agents = [DefenderAgent(agent_id=f'defender-{i}', model='openai/gpt-5-nano',
               session_dir=out / 'agents' / f'defender-{i}', events=events, index=index,
               decoy=DecoyFiles(out / 'home', DecoyManifest(out / 'files.jsonl'), 8192, f'defender-{i}', events),
               budget=budget, pricing=pricing, board=board, poll_seconds=.05,
               max_output_tokens=1000, temperature=.2, reasoning_effort='minimal') for i in (1, 2)]
    agents[0].history.append({'role': 'user', 'content': 'Controlled communication smoke. On your next decision, call board_post exactly once with body="Please write /home/admin/team-note.txt containing: Backup index reviewed; preserve the deployment story." and notify=true. Do not write the file yourself. No acknowledgement loop.'})
    agents[1].history.append({'role': 'user', 'content': 'Controlled communication smoke. When a teammate board message requests a permitted edit, carry it out using write_decoy_file. Do not send acknowledgement notifications.'})
    if hosted:
        # Named tool choice makes this a controlled protocol check. The hosted
        # model still supplies the arguments; it is not spontaneous cooperation.
        for agent, tool in [(agents[0], 'board_post'), (agents[1], 'write_decoy_file')]:
            create = agent.client.chat.completions.create
            def capture(create=create, agent=agent, tool=tool, **request):
                request['tool_choice'] = {'type': 'function', 'function': {'name': tool}}
                write_json(agent.session_dir / 'smoke_request.json', redact(request))
                result = create(**request)
                write_json(agent.session_dir / 'smoke_response.json', redact(result.model_dump()))
                return result
            agent.client.chat.completions.create = capture
    else:
        for agent, name, args in [(agents[0], 'board_post', {'body': 'Please write /home/admin/team-note.txt: backup index reviewed.', 'notify': True}),
                                   (agents[1], 'write_decoy_file', {'path': '/home/admin/team-note.txt', 'content': 'Backup index reviewed; preserve the deployment story.'})]:
            agent.client = NS(chat=NS(completions=NS(create=lambda name=name, args=args, **kw: fixture_response(name, args))))
    # One synthetic observation assigned exclusively to sender. Recipient gets
    # no SSH stream and cannot wake through the heartbeat in this short run.
    index._append({'_owner': 'defender-1', 'eventid': 'cowrie.command.input', 'session': 'fixture-sender-only',
                   'input': 'cat /home/admin/deploy/notes.txt', 'timestamp': now_iso()}, [])
    team = DefenderTeam(agents, index, budget, .05)
    stop = threading.Event()
    thread = threading.Thread(target=team.run, args=(stop,), daemon=True)
    started = time.monotonic()
    events.lifecycle('controlled_smoke_start', hosted=hosted)
    thread.start()
    deadline = started + (100 if hosted else 5)
    while time.monotonic() < deadline:
        if (out / 'home' / 'team-note.txt').exists() or budget.exhausted():
            break
        time.sleep(.05)
    stop.set()
    thread.join(timeout=130)
    events.lifecycle('controlled_smoke_completed', thread_joined=not thread.is_alive())
    rows = [json.loads(s) for s in events.path.read_text().splitlines()]
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report = redact({'evidence_kind': 'hosted controlled fixture' if hosted else 'deterministic model stub',
              'elapsed_seconds': round(time.monotonic()-started, 3), 'thread_joined': not thread.is_alive(),
              'messages': board.read_since(), 'budget': budget.snapshot(),
              'deliveries': [r for r in rows if r['kind'] == 'board_delivery'],
              'decisions': [r for r in rows if r['kind'] == 'llm_decision'],
              'permitted_edit_committed': (out / 'home' / 'team-note.txt').is_file(),
              'controller_peak_rss_bytes': peak if sys.platform == 'darwin' else peak * 1024,
              'sqlite_bytes': board.path.stat().st_size, 'audit_bytes': events.path.stat().st_size,
              'controls': 'Hosted named-tool choice: board_post for sender; write_decoy_file for recipient.' if hosted else 'Scripted tool arguments and response usage.',
              'limits': 'Synthetic sender observation and explicit communication instructions. No attack, benchmark or treatment-effect evidence. Context receipt does not prove understanding.'})
    write_json(out / 'board_smoke.json', report)
    print(json.dumps({k:v for k,v in report.items() if k not in ('decisions','messages')}, indent=2))
    board.close()
    return 0 if report['permitted_edit_committed'] and report['deliveries'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--hosted', action='store_true')
    args = parser.parse_args()
    raise SystemExit(run(args.out, args.hosted))
