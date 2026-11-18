"""CLI 端到端测试：python -m solution --input ... --output ... 的退出码与产物。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

try:  # 兼容 discover -s tests 的顶层导入
    from .case_loading import CASES_PATH
except ImportError:  # pragma: no cover
    from case_loading import CASES_PATH


class CliTests(unittest.TestCase):
    def setUp(self):
        self.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _run(self, input_path: str, output_path: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "solution", "--input", input_path, "--output", output_path],
            cwd=self.repo_root, capture_output=True, text=True, encoding="utf-8",
        )

    def test_end_to_end_exit_zero_and_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "result.json")
            proc = self._run(CASES_PATH, out)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertTrue(doc["offline"])
            self.assertEqual(doc["case_count"], 7)
            statuses = {r["case_id"]: r["status"] for r in doc["results"]}
            self.assertEqual(statuses["C01-basic-feasible-multi-service"], "FEASIBLE")
            self.assertEqual(statuses["C02-revoke-alone-ok-combo-fails"], "INFEASIBLE")
            self.assertEqual(statuses["C07-deadline-and-window-blocked"], "INFEASIBLE")
            # 每个可行案例都带逐步快照与覆盖检查
            for report in doc["results"]:
                self.assertIn("steps", report)
                self.assertIn("risk_propagation", report)
                self.assertIn("final_coverage_check", report)

    def test_infeasible_is_still_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            single = os.path.join(tmp, "one.json")
            with open(CASES_PATH, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            with open(single, "w", encoding="utf-8") as fh:
                json.dump(next(c for c in doc["cases"]
                               if c["case_id"].startswith("C07")), fh, ensure_ascii=False)
            out = os.path.join(tmp, "r.json")
            proc = self._run(single, out)
            self.assertEqual(proc.returncode, 0)
            with open(out, encoding="utf-8") as fh:
                result = json.load(fh)["results"][0]
            self.assertEqual(result["status"], "INFEASIBLE")
            self.assertIn("infeasibility_evidence", result)

    def test_validation_error_exit_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.json")
            with open(bad, "w", encoding="utf-8") as fh:
                json.dump({"cases": [{"case_id": "x"}]}, fh)
            out = os.path.join(tmp, "r.json")
            proc = self._run(bad, out)
            self.assertEqual(proc.returncode, 3)
            payload = json.loads(proc.stderr)
            self.assertTrue(payload["error"]["code"].startswith("E10"))
            self.assertFalse(os.path.exists(out))

    def test_missing_input_exit_five(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(os.path.join(tmp, "nope.json"), os.path.join(tmp, "r.json"))
            self.assertEqual(proc.returncode, 5)
            payload = json.loads(proc.stderr)
            self.assertEqual(payload["error"]["code"], "E5001")

    def test_missing_argument_exit_two(self):
        proc = subprocess.run(
            [sys.executable, "-m", "solution", "--input", CASES_PATH],
            cwd=self.repo_root, capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
