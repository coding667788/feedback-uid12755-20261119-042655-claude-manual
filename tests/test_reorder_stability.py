"""输入换序稳定性：打乱数组顺序不得改变最优结论（仅影响搜索遍历，不影响结果）。"""

from __future__ import annotations

import copy
import json
import unittest

try:  # 兼容 discover -s tests 的顶层导入；须先于 solution.* 以支持 python -I
    from .case_loading import load_raw_cases
except ImportError:  # pragma: no cover
    from case_loading import load_raw_cases

from solution.bruteforce import brute_force
from solution.loader import load_case
from solution.solver import solve


def _shuffle(seq: list, seed: int) -> list:
    """确定性 LCG 洗牌，避免依赖 random 模块的全局状态。"""
    out = list(seq)
    state = seed
    for i in range(len(out) - 1, 0, -1):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        j = state % (i + 1)
        out[i], out[j] = out[j], out[i]
    return out


class ReorderStabilityTests(unittest.TestCase):
    def test_permuted_inputs_keep_same_optimum(self):
        for index, raw0 in enumerate(load_raw_cases()):
            with self.subTest(case=raw0["case_id"]):
                baseline = solve(load_case(copy.deepcopy(raw0)))
                for seed in (1, 7, 42, 99):
                    raw = copy.deepcopy(raw0)
                    raw["credentials"] = _shuffle(raw["credentials"], seed)
                    raw["derivation_edges"] = _shuffle(raw["derivation_edges"], seed + 1)
                    raw["exposure_records"] = _shuffle(raw["exposure_records"], seed + 2)
                    raw["replacements"] = _shuffle(raw["replacements"], seed + 3)
                    raw["services"] = _shuffle(raw["services"], seed + 4)
                    raw["candidate_actions"] = _shuffle(raw["candidate_actions"], seed + 5)

                    case = load_case(raw)
                    result = solve(case)
                    self.assertEqual(result.feasible, baseline.feasible)
                    self.assertEqual(result.total_cost, baseline.total_cost)
                    # 动作 ID 序列定序与输入顺序无关
                    self.assertEqual(result.sequence, baseline.sequence)
                    self.assertEqual(result.best_cover, baseline.best_cover)

                    # 独立穷举在换序后给出同样的最优序列与成本
                    brute = brute_force(case)
                    self.assertEqual(brute.best_sequence, tuple(baseline.sequence))
                    self.assertEqual(brute.best_cost, baseline.total_cost)

    def test_report_byte_stable_across_runs(self):
        from solution.report import run_case
        raw = load_raw_cases()[0]
        first = json.dumps(run_case(copy.deepcopy(raw)), ensure_ascii=False, sort_keys=True)
        second = json.dumps(run_case(copy.deepcopy(raw)), ensure_ascii=False, sort_keys=True)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
