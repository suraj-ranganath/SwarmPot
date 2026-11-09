"""Small in-process scheduler; durable notifications live in the board."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

from .notifications import notification_policy


class DefenderTeam:
    def __init__(self, agents, index, budget, poll_seconds: float):
        self.agents = agents
        self.index = index
        self.budget = budget
        self.poll_seconds = poll_seconds
        self._busy: set = set()
        self._last_heartbeat = {a.agent_id: time.time() for a in agents}
        self._lock = threading.Lock()
        self._executor = None
        self._stop = threading.Event()
        for agent in agents:
            peers = [a.agent_id for a in agents if a.agent_id != agent.agent_id]
            agent.teammate_id = peers[0] if len(peers) == 1 and agent.board else None

    def _emit(self, agent, kind, **payload):
        return agent.events.emit('defender', kind, agent_id=agent.agent_id,
                                 target_class='n/a', payload=payload, budget=self.budget.snapshot())

    def _deny(self, agent, reason):
        seqs = agent.board.deny_pending(agent.agent_id, reason) if agent.board else []
        if seqs:
            self._emit(agent, 'board_notification', status='denied', reason=reason,
                       recipient=agent.agent_id, message_seqs=seqs)

    def _status(self, agent, state):
        self._emit(agent, 'defender_status', state=state,
                   pending_message_seqs=agent.board.pending(agent.agent_id) if agent.board else [],
                   last_seen_seq=agent.last_seen_seq)

    def _dispatch(self, agent, trigger: str, rows: List[Dict[str, Any]]) -> None:
        with self._lock:
            if agent.agent_id in self._busy or self._stop.is_set() or agent.stopped:
                return
            self._busy.add(agent.agent_id)
        self._status(agent, 'running')

        def work():
            try:
                # step owns admission and request-level receipts. Nothing is
                # consumed merely because the scheduler selected this agent.
                succeeded = agent.step(trigger, rows)
                if succeeded and rows:
                    agent.last_seen_seq = max(agent.last_seen_seq, rows[-1]['_seq'])
            except Exception as exc:
                self._emit(agent, 'defender_error', error=repr(exc), trigger=trigger)
                # Unexpected local errors must not produce an infinite retry loop.
                agent.stopped = True
                self._deny(agent, 'agent_error')
            finally:
                with self._lock:
                    self._busy.discard(agent.agent_id)
                self._status(agent, 'stopped' if agent.stopped or self._stop.is_set() else
                             'budget exhausted' if not self.budget.available(agent.agent_id) else
                             'pending' if agent.board and agent.board.pending(agent.agent_id) else 'waiting')

        if self._executor is None:
            work()
        else:
            self._executor.submit(work)

    def tick(self):
        self.index.poll()
        now = time.time()
        for agent in self.agents:
            if agent.stopped or not self.budget.available(agent.agent_id):
                self._deny(agent, 'stopped' if agent.stopped else 'budget_exhausted')
                continue
            with self._lock:
                if agent.agent_id in self._busy:
                    continue
            # Read from the authoritative index *after* busy finishes. Never
            # advance a cursor for rejected dispatches or omitted observations.
            rows = self.index.events_for(agent.agent_id, since_seq=agent.last_seen_seq, limit=30)
            pending = agent.board.pending(agent.agent_id) if agent.board else []
            if pending or rows:
                self._last_heartbeat[agent.agent_id] = now
                self._dispatch(agent, 'board_notification' if pending else 'session_events', rows)
            elif now - self._last_heartbeat[agent.agent_id] > 45:
                if any(self.index.owner(s) == agent.agent_id for s in self.index.session_owner):
                    self._last_heartbeat[agent.agent_id] = now
                    self._dispatch(agent, 'heartbeat', [])

    def run(self, stop_event: threading.Event) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max(1, len(self.agents)))
        for agent in self.agents:
            self._emit(agent, 'board_policy', policy=notification_policy(agent.board is not None),
                       poll_seconds=self.poll_seconds)
            self._status(agent, 'waiting')
        try:
            while not stop_event.is_set() and not self.budget.exhausted():
                self.tick()
                stop_event.wait(self.poll_seconds)
        finally:
            self._stop.set()
            # In-flight calls retain their already admitted allowance. Disable
            # tools at shutdown so late responses cannot mutate a stopped run.
            if stop_event.is_set():
                for agent in self.agents:
                    agent.stopped = True
            self._executor.shutdown(wait=True)
            for agent in self.agents:
                self._deny(agent, 'episode_stopped' if stop_event.is_set() else 'budget_exhausted')
                self._status(agent, 'stopped' if stop_event.is_set() else 'budget exhausted')
