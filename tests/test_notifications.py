from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

from swarmpot.board import Board
from swarmpot.cowrie_events import CowrieIndex
from swarmpot.defenders import DecoyFiles, DecoyManifest, DefenderAgent, DefenderBudget, DefenderTeam
from swarmpot.events import EventLog


def response(calls=()):
    return NS(usage=NS(prompt_tokens=100, completion_tokens=20), model='fixture', id='fixture-response',
              choices=[NS(finish_reason='stop', message=NS(content='controlled fixture', tool_calls=[
                  NS(id='call-'+str(i), function=NS(name=name, arguments=json.dumps(args)))
                  for i, (name, args) in enumerate(calls)]))])


def make_team(tmp_path, monkeypatch, board_on=True, decisions=12):
    monkeypatch.setenv('OPENROUTER_API_KEY', 'fixture-not-a-key')
    index = CowrieIndex(tmp_path / 'cowrie.json', ['defender-1', 'defender-2'])
    events = EventLog(tmp_path, 'fixture', 'E' if board_on else 'D')
    board = Board(tmp_path / 'board.sqlite', 'fixture', 'defenders', 20) if board_on else None
    budget = DefenderBudget(decisions, 2, 1.5)
    agents = [DefenderAgent(agent_id=f'defender-{i}', model='fixture', session_dir=tmp_path / f'agent-{i}',
                           events=events, index=index, decoy=DecoyFiles(tmp_path / 'home', DecoyManifest(tmp_path / 'files.jsonl'), 8192, f'defender-{i}', events),
                           budget=budget, pricing=NS(cost=lambda *args: 0.001), board=board,
                           poll_seconds=.01, max_output_tokens=128, temperature=0)
              for i in (1, 2)]
    for a in agents:
        a.client = NS(chat=NS(completions=NS(create=Mock(return_value=response()))))
    return DefenderTeam(agents, index, budget, .01), board, agents


def logs(tmp_path):
    return [json.loads(s) for s in (tmp_path / 'events.jsonl').read_text().splitlines()]


def test_idle_wake_context_budget_and_linked_action(tmp_path, monkeypatch):
    team, board, (a, b) = make_team(tmp_path, monkeypatch)
    b.client.chat.completions.create.return_value = response([('write_decoy_file', {'path': '/home/admin/team.txt', 'content': 'coherent fixture'})])
    post = a._execute_tool('board_post', {'body': 'Please update team.txt', 'notify': True})
    team.tick()  # no SSH events and no heartbeat
    assert b.decisions == 1 and a.decisions == 0
    assert board.pending(b.agent_id) == []
    assert (tmp_path / 'home' / 'team.txt').read_text() == 'coherent fixture'
    request = b.client.chat.completions.create.call_args.kwargs
    assert str(post['seq']) in request['messages'][2]['content']
    events = logs(tmp_path)
    delivery = next(e for e in events if e['kind'] == 'board_delivery')
    decision = next(e for e in events if e['kind'] == 'llm_decision')
    action = next(e for e in events if e['kind'] == 'tool_call' and e['tool'] == 'write_decoy_file')
    assert delivery['payload']['request_id'] == decision['payload']['request_id'] == action['payload']['request_id']
    team.tick()
    assert b.decisions == 1  # no ack loops, no duplicate processing


def test_passive_failed_and_cap_posts_do_not_wake(tmp_path, monkeypatch):
    team, board, (a, b) = make_team(tmp_path, monkeypatch)
    a._execute_tool('board_post', {'body': 'passive'})
    assert 'error' in a._execute_tool('board_post', {'body': 'invalid', 'notify': 'true'})
    board.max_messages = 1
    assert 'error' in a._execute_tool('board_post', {'body': 'over cap', 'notify': True})
    team.tick()
    assert b.decisions == 0 and board.count() == 1
    assert board.read_since()[0]['body'] == 'passive'


def test_busy_burst_retains_ssh_and_no_overlapping_calls(tmp_path, monkeypatch):
    team, board, (a, b) = make_team(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    def slow(**kwargs):
        entered.set()
        assert release.wait(3)
        return response()
    b.client.chat.completions.create.side_effect = slow
    team._executor = ThreadPoolExecutor(max_workers=2)
    team._dispatch(b, 'fixture', [])
    assert entered.wait(1)
    for i in range(3):
        a._execute_tool('board_post', {'body': f'burst {i}', 'notify': True})
    team.index._append({'_owner': b.agent_id, 'eventid': 'cowrie.command.input', 'input': 'ls'}, [])
    team.tick()
    assert len(board.pending(b.agent_id)) == 3 and b.decisions == 1 and b.last_seen_seq == 0
    release.set()
    team._executor.shutdown(wait=True)
    team._executor = None
    b.client.chat.completions.create.side_effect = None
    team.tick()
    assert b.decisions == 2 and b.last_seen_seq == 1
    assert board.pending(b.agent_id) == []
    assert 'burst 2' in b.client.chat.completions.create.call_args.kwargs['messages'][-3]['content']


def test_failure_retry_and_partial_batch_are_durable(tmp_path, monkeypatch):
    team, board, (a, b) = make_team(tmp_path, monkeypatch)
    for i in range(10):
        a._execute_tool('board_post', {'body': f'message {i}', 'notify': True})
    b.client.chat.completions.create.side_effect = RuntimeError('fixture failure')
    team.tick()
    assert len(board.pending(b.agent_id)) == 10
    assert b.decisions == 1
    assert team.budget.snapshot()["failed_requests"] == {b.agent_id: 1}
    assert not team.budget.snapshot()["cost_known"]
    assert next(e for e in logs(tmp_path) if e['kind'] == 'board_delivery')['payload']['status'] == 'failed'
    b.client.chat.completions.create.side_effect = None
    team.tick()
    assert len(board.pending(b.agent_id)) == 2 and b.decisions == 2
    requests = [e['payload'] for e in logs(tmp_path) if e['kind'] == 'llm_request']
    assert requests[-1]['retry_of'] == requests[0]['request_id']
    board.close()
    board = Board(tmp_path / 'board.sqlite', 'fixture', 'defenders', 20)
    assert len(board.pending(b.agent_id)) == 2
    a.board = b.board = board
    team.tick()
    assert board.pending(b.agent_id) == [] and b.decisions == 3


@pytest.mark.parametrize('mode', ['off', 'budget', 'stopped'])
def test_denied_wakes(tmp_path, monkeypatch, mode):
    team, board, (a, b) = make_team(tmp_path, monkeypatch, board_on=mode != 'off', decisions=2)
    if mode == 'off':
        assert 'error' in a._execute_tool('board_post', {'body': 'x', 'notify': True})
    else:
        a._execute_tool('board_post', {'body': 'x', 'notify': True})
        if mode == 'budget':
            assert b.budget.acquire(b.agent_id)
        else:
            b.stopped = True
    team.tick()
    assert b.client.chat.completions.create.call_count == 0
    if board:
        assert not board.pending(b.agent_id)
        assert any(e['kind'] == 'board_notification' and e['payload']['status'] == 'denied' for e in logs(tmp_path))


def test_self_wakes_suppressed_and_partial_priority(tmp_path, monkeypatch):
    team, board, (a, b) = make_team(tmp_path, monkeypatch)
    board.post(a.agent_id, 'self', notify_to=a.agent_id)
    assert not board.pending(a.agent_id)
    for i in range(9):
        a._execute_tool('board_post', {'body': f'passive {i}'})
    wake = a._execute_tool('board_post', {'body': 'wake', 'notify': True})
    batch = board.delivery_batch(b.agent_id, limit=2)
    assert wake['seq'] in [r['seq'] for r in batch]
    board.delivered(b.agent_id, [wake['seq']], 'fixture')
    assert len(board.delivery_batch(b.agent_id, limit=20)) == 10


def test_explicit_read_is_bounded_and_distinct_from_automatic_delivery(tmp_path, monkeypatch):
    team, board, (a, b) = make_team(tmp_path, monkeypatch)
    for i in range(8):
        a._execute_tool('board_post', {'body': 'x' * 1800})
    result = b._execute_tool('board_read', {})
    assert len(json.dumps(result)) < 8000
    assert 0 < len(result['messages']) < 8
    assert not any(e['kind'] == 'board_delivery' for e in logs(tmp_path))
    b.step('fixture', [])
    assert any(e['kind'] == 'board_read_context' for e in logs(tmp_path))


def test_last_admitted_decision_finishes_tools_on_budget_exit(tmp_path, monkeypatch):
    team, board, (a, b) = make_team(tmp_path, monkeypatch, decisions=2)
    a.client.chat.completions.create.return_value = response([('board_post', {'body': 'last', 'notify': True})])
    entered, release = threading.Event(), threading.Event()
    def slow(**kwargs):
        entered.set()
        assert release.wait(3)
        return response([('write_decoy_file', {'path': '/home/admin/final.txt', 'content': 'admitted'})])
    b.client.chat.completions.create.side_effect = slow
    a._execute_tool('board_post', {'body': 'start', 'notify': True})
    # Consume sender quota so recipient admission exhausts the shared budget.
    assert team.budget.acquire(a.agent_id)
    stop = threading.Event()
    thread = threading.Thread(target=team.run, args=(stop,))
    thread.start()
    assert entered.wait(1)
    release.set()
    thread.join(3)
    assert not thread.is_alive()
    assert (tmp_path / 'home' / 'final.txt').read_text() == 'admitted'


def test_stopping_busy_request_denies_late_actions_and_pending_wakes(tmp_path, monkeypatch):
    team, board, (a, b) = make_team(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    def slow(**kwargs):
        entered.set()
        assert release.wait(3)
        return response([('write_decoy_file', {'path': '/home/admin/late.txt', 'content': 'late'})])
    b.client.chat.completions.create.side_effect = slow
    a._execute_tool('board_post', {'body': 'first', 'notify': True})
    stop = threading.Event()
    thread = threading.Thread(target=team.run, args=(stop,))
    thread.start()
    assert entered.wait(1)
    a._execute_tool('board_post', {'body': 'arrived while busy', 'notify': True})
    stop.set()
    # Observe shutdown admission gate before releasing the provider response.
    assert team._stop.wait(1)
    release.set()
    thread.join(3)
    assert not (tmp_path / 'home' / 'late.txt').exists()
    assert not board.pending(b.agent_id)
    assert any(e['kind'] == 'board_notification' and e['payload'].get('reason') == 'episode_stopped' for e in logs(tmp_path))


def test_notification_policy_audit_pins_schema_timing_and_allowance():
    from swarmpot.config import load_config
    from swarmpot.notifications import notification_config_audit
    result = notification_config_audit(load_config())
    assert result['matched_allowances'] and result['matched_scheduler']
    left, right = result['conditions']['D'], result['conditions']['E']
    assert left['notification_policy']['enabled'] is False
    assert right['notification_policy']['enabled'] is True
    assert left['notification_policy']['version'] == right['notification_policy']['version'] == 'teammate-wake-v1'
    post = next(t['function'] for t in right['tool_schemas'] if t['function']['name'] == 'board_post')
    assert post['parameters']['properties']['notify']['default'] is False
