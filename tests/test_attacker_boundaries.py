"""Run with unittest in the existing ARTEMIS image; no hosted calls needed."""
import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

HAS_ARTEMIS = importlib.util.find_spec('supervisor') is not None
if HAS_ARTEMIS:
    from swarmpot.artemis_adapter import BudgetMonitor, build_config


@unittest.skipUnless(HAS_ARTEMIS, 'run in the attacker image')
class AttackerBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_wall_clock_stops_while_supervisor_can_be_waiting(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            monitor=BudgetMonitor(root,root,80,2,2,90,1)
            monitor.started_at=time.time()-61
            monitor.scan_once=lambda:None
            monitor._ensure_team=AsyncMock()
            monitor._hard_stop=AsyncMock()
            await monitor.run()
            self.assertEqual(monitor.stop_reason,'wall_clock_budget_exhausted')
            monitor._hard_stop.assert_awaited_once()
            monitor._ensure_team.assert_not_awaited()

    async def test_source_execution_clock_is_distinct_from_scan_time(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            monitor=BudgetMonitor(root,root,80,2,0,90,8)
            monitor._handle_line('worker','[00:00:01] EXECUTING: ["sh", "-c", "echo test"]')
            record=json.loads((root/'attacker_events.jsonl').read_text())
            self.assertIn('T00:00:01',record['tool_started_at'])
            self.assertNotEqual(record['tool_started_at'],record['ts'])

    async def test_scope_covers_associated_services_without_advertising_entry(self):
        cfg=build_config({'task_prompt':'Original task','episode_id':'test','max_tool_actions':80,
                          'wall_clock_minutes':8},Path('/tmp/unused'))
        rule=cfg['rules_of_engagement'][0]
        self.assertIn('associated services',rule)
        self.assertIn('isolated episode network',rule)
        self.assertNotIn('fileserver',rule)
        self.assertNotIn('honeypot',rule)
        self.assertNotIn('SSH',rule)


if __name__=='__main__':
    unittest.main()
