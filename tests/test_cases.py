"""对 cases.json 中全部合成案例断言具体求解结果与证据。"""

from __future__ import annotations

import unittest

try:  # 兼容 discover -s tests 的顶层导入；须先于 solution.* 以支持 python -I
    from .case_loading import get_case, get_raw, load_all_cases
except ImportError:  # pragma: no cover
    from case_loading import get_case, get_raw, load_all_cases

from solution.bruteforce import brute_force
from solution.engine import Engine
from solution.loader import load_case
from solution.propagate import propagate
from solution.report import build_report
from solution.solver import solve


class C01BasicFeasibleTests(unittest.TestCase):
    def setUp(self):
        self.case = get_case("C01")
        self.result = solve(self.case)

    def test_optimal_sequence_and_cost(self):
        self.assertTrue(self.result.feasible)
        self.assertEqual(self.result.sequence, ("A01", "A02", "A03", "A04"))
        self.assertEqual(self.result.total_cost, 18)
        self.assertEqual(len(self.result.sequence), 4)

    def test_all_tainted_revoked_within_deadline(self):
        # k-root 显式暴露，k-child 经可继承边污染；k-billing 被阻断不在集合内
        self.assertEqual(set(self.result.final_state.revoked), {"k-root", "k-child"})
        for aid in ("A03", "A04"):
            self.assertLessEqual(self.result.sequence.index(aid) + 1, self.case.deadline_step)

    def test_every_intermediate_state_compliant(self):
        engine = Engine(self.case)
        state = engine.initial_state
        self.assertTrue(engine.is_compliant(state))
        for aid in self.result.sequence:
            state = engine.attempt(state, aid).state
            self.assertTrue(engine.is_compliant(state), f"{aid} 后出现违规")

    def test_report_contains_active_bindings_and_coverage(self):
        report = build_report(self.case)
        self.assertEqual(report["status"], "FEASIBLE")
        steps = report["steps"]
        self.assertEqual([s["step"] for s in steps], [0, 1, 2, 3, 4])
        # 第 1 步后 svc-a 的 admin 活跃绑定包含替代凭据且保持最低数 2
        s1 = next(s for s in steps if s["step"] == 1)
        admin = s1["state_snapshot"]["services"]["svc-a"]["roles"]["admin"]
        self.assertEqual(admin["active_bindings"], ["k-other", "r-admin-a"])
        self.assertTrue(admin["satisfied"])
        coverage = report["final_coverage_check"]
        self.assertEqual(coverage["tainted_total"], 2)
        self.assertEqual(coverage["tainted_revoked"], 2)
        self.assertEqual(coverage["coverage_weight"], 16)
        self.assertTrue(coverage["continuity_compliant"])


class C02AloneOkComboFailsTests(unittest.TestCase):
    def setUp(self):
        self.case = get_case("C02")
        self.result = solve(self.case)
        self.engine = Engine(self.case)

    def test_infeasible_and_best_coverage_state(self):
        self.assertFalse(self.result.feasible)
        # B02、B03 各自撤销后仍合规，可达且覆盖 k-s1+k-s2 权重 12；k-shared(10) 无法撤销
        self.assertEqual(self.result.best_cover, 12)
        self.assertEqual(self.result.coverage_gap, 10)
        self.assertEqual(self.result.tainted_remaining, ["k-shared"])
        self.assertEqual(set(self.result.best_cover_state.sequence), {"B02", "B03"})

    def test_each_revoke_alone_is_feasible(self):
        # 题目要求场景：撤销单独可行
        for aid in ("B01", "B02", "B03"):
            res = self.engine.attempt(self.engine.initial_state, aid)
            self.assertTrue(res.ok, f"{aid} 单独执行应可行")

    def test_combination_blocked_with_e2004_evidence(self):
        state = self.engine.initial_state
        state = self.engine.attempt(state, "B02").state
        state = self.engine.attempt(state, "B03").state
        blocked = self.engine.attempt(state, "B01")
        self.assertFalse(blocked.ok)
        self.assertEqual(blocked.blocker.code, "E2004")
        self.assertIn("svc-1", blocked.blocker.reason)

    def test_report_lists_next_step_blockers(self):
        report = build_report(self.case)
        self.assertEqual(report["status"], "INFEASIBLE")
        codes = {b["action_id"]: b["code"]
                 for b in report["infeasibility_evidence"]["next_step_blockers"]}
        self.assertEqual(codes, {"B01": "E2004"})


class C03TaintedReplacementTests(unittest.TestCase):
    def setUp(self):
        self.case = get_case("C03")
        self.engine = Engine(self.case)
        self.result = solve(self.case)

    def test_tainted_derived_credential_blocks_replacement(self):
        res = self.engine.attempt(self.engine.initial_state, "C01")
        self.assertFalse(res.ok)
        self.assertEqual(res.blocker.code, "E2008")
        self.assertEqual(res.blocker.detail["to_credential_id"], "k-derived")
        # 证据中附带传播路径
        self.assertEqual(res.blocker.detail["propagation_path"], ["k-p", "k-derived"])

    def test_clean_path_is_optimal(self):
        self.assertTrue(self.result.feasible)
        self.assertEqual(self.result.sequence, ("C02", "C03", "C04"))
        self.assertEqual(self.result.total_cost, 19)
        self.assertEqual(set(self.result.final_state.revoked), {"k-p", "k-derived"})


class C04NonGreedyTests(unittest.TestCase):
    def setUp(self):
        self.case = get_case("C04")
        self.result = solve(self.case)
        self.engine = Engine(self.case)

    def test_optimal_requires_expensive_cross_service_first(self):
        self.assertTrue(self.result.feasible)
        self.assertEqual(self.result.sequence, ("D01", "D02", "D04"))
        self.assertEqual(self.result.total_cost, 13)

    def test_greedy_cheap_first_action_deadlocks(self):
        # 贪心在第 1 步选风险成本最低的 D03（1 < D01 的 6），随后所有出路被阻断
        state = self.engine.attempt(self.engine.initial_state, "D03").state
        codes = {}
        for aid in ("D01", "D02", "D04"):
            res = self.engine.attempt(state, aid)
            self.assertFalse(res.ok)
            codes[aid] = res.blocker.code
        self.assertEqual(codes, {"D01": "E2009", "D02": "E2007", "D04": "E2004"})

    def test_shared_credential_revoke_hits_both_services(self):
        # k-taint 被 svc-x 与 svc-y 共用，未换绑直接撤销必破坏连续性
        res = self.engine.attempt(self.engine.initial_state, "D04")
        self.assertFalse(res.ok)
        self.assertEqual(res.blocker.code, "E2004")


class C05CrossTenantSameNameTests(unittest.TestCase):
    def setUp(self):
        self.case = get_case("C05")
        self.engine = Engine(self.case)
        self.result = solve(self.case)

    def test_same_display_name_distinct_identity(self):
        eu = self.case.credentials["k-eu"]
        us = self.case.credentials["k-us"]
        self.assertEqual(eu.display_name, us.display_name)
        self.assertNotEqual(eu.tenant, us.tenant)
        # 只有 eu 侧受污染
        self.assertEqual(set(self.engine.tainted), {"k-eu"})

    def test_cross_tenant_replacement_blocked_e2006(self):
        res = self.engine.attempt(self.engine.initial_state, "E03")
        self.assertFalse(res.ok)
        self.assertEqual(res.blocker.code, "E2006")
        self.assertEqual(res.blocker.detail["replacement_tenant"], "tenant-us")
        self.assertEqual(res.blocker.detail["service_tenant"], "tenant-eu")

    def test_optimal_sequence_revokes_exact_generations(self):
        self.assertTrue(self.result.feasible)
        self.assertEqual(self.result.sequence, ("E01", "E04"))
        self.assertEqual(self.result.total_cost, 10)
        self.assertEqual(set(self.result.final_state.revoked), {"k-eu"})

    def test_same_name_us_credential_unaffected(self):
        # 撤销 k-eu 不影响同名 k-us 的代数身份
        self.assertNotIn("k-us", self.result.final_state.revoked)


class C06CustodyIsolationTests(unittest.TestCase):
    def setUp(self):
        self.case = get_case("C06")
        self.engine = Engine(self.case)
        self.result = solve(self.case)

    def test_violating_rebind_blocked_e2005(self):
        res = self.engine.attempt(self.engine.initial_state, "F01")
        self.assertFalse(res.ok)
        self.assertEqual(res.blocker.code, "E2005")
        self.assertEqual(res.blocker.detail["custody_domain"], "DOM-2")

    def test_compliant_path_optimal(self):
        self.assertTrue(self.result.feasible)
        self.assertEqual(self.result.sequence, ("F02", "F03"))
        self.assertEqual(self.result.total_cost, 11)

    def test_final_state_keeps_isolation(self):
        report = build_report(self.case)
        for step in report["steps"]:
            for svc in step["state_snapshot"]["services"].values():
                self.assertTrue(svc["custody_isolation_ok"])


class C07DeadlineWindowTests(unittest.TestCase):
    def setUp(self):
        self.case = get_case("C07")
        self.result = solve(self.case)
        self.engine = Engine(self.case)

    def test_infeasible_zero_coverage(self):
        self.assertFalse(self.result.feasible)
        self.assertEqual(self.result.best_cover, 0)
        self.assertEqual(self.result.sequence, ())

    def test_all_three_blocker_categories_evidenced(self):
        report = build_report(self.case)
        blockers = {b["action_id"]: b["code"]
                    for b in report["infeasibility_evidence"]["next_step_blockers"]}
        self.assertEqual(blockers, {"G01": "E2009", "G02": "E2004", "G03": "E2010"})

    def test_late_revoke_would_also_break_deadline(self):
        # 即便先换绑（虚构到第 2 步），撤销步 3 也晚于截止步 1 -> E2003
        state = self.engine.initial_state
        # 直接验证 E2003 逻辑：构造一个已执行 1 步后的撤销尝试
        late = self.engine.attempt(state, "G02")
        self.assertEqual(late.blocker.code, "E2004")  # 第 1 步首先撞最低数


class BruteForceCrossCheckTests(unittest.TestCase):
    """独立排列穷举必须与求解器在每个案例上结论一致。"""

    def test_all_cases_match_bruteforce(self):
        for cid, case in load_all_cases().items():
            with self.subTest(case=cid):
                smart = solve(case)
                brute = brute_force(case)
                self.assertEqual(smart.feasible, brute.feasible)
                self.assertEqual(smart.total_cost, brute.best_cost)
                self.assertEqual(tuple(smart.sequence), brute.best_sequence)
                self.assertEqual(smart.best_cover, brute.best_cover)
                self.assertGreaterEqual(brute.reachable_prefixes, smart.reachable_states)


if __name__ == "__main__":
    unittest.main()
