"""Test gate evidence collection without Rust, hardware, or external services."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from gate_runner import execute, run_one


class GateRunnerTest(unittest.TestCase):
    def test_success_and_nonzero_and_following_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gates = (
                ('first', (sys.executable, '-c', "print('first')"), 10),
                ('second', (sys.executable, '-c', "raise SystemExit(7)"), 10),
                ('third', (sys.executable, '-c', "print('third')"), 10),
            )
            report = execute(gates, root, root/'evidence', 'fixture-sha')
            self.assertTrue(report['complete'])
            self.assertEqual(report['release_gate'], 'FAIL')
            self.assertEqual([r['status'] for r in report['gates']], ['PASS', 'FAIL', 'PASS'])
            self.assertEqual(report['gates'][1]['exit_code'], 7)
            self.assertIn('third', (root/'evidence/third.log').read_text())
            self.assertEqual(json.loads((root/'evidence/report.json').read_text()), report)
            self.assertEqual(report['commit'], 'fixture-sha')

    def test_missing_command_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_one('missing', (str(root/'does-not-exist'),), 5, root, root)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertIsNone(result['exit_code'])
            self.assertIn('Cannot launch', (root/'missing.log').read_text())

    def test_timeout_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_one('slow', (sys.executable, '-c', 'import time; time.sleep(5)'), 0.1, root, root)
            self.assertEqual(result['status'], 'FAIL')
            self.assertIn('timed out', (root/'slow.log').read_text())

    def test_all_pass_and_stale_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gates = (('ok', (sys.executable, '-c', 'pass'), 5),)
            self.assertEqual(execute(gates, root, root/'out', None)['release_gate'], 'PASS')
            with self.assertRaises(ValueError):
                execute(gates, root, root/'out', None)

    def test_empty_gate_list_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(execute((), root, root/'out', None)['release_gate'], 'FAIL')


if __name__ == '__main__':
    unittest.main(verbosity=2)
