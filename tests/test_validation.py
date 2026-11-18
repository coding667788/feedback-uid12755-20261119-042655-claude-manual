"""输入校验错误码 E10xx 与引擎运行期阻断码 E20xx 的针对性测试。"""

from __future__ import annotations

import copy
import unittest

try:  # 兼容 discover -s tests 的顶层导入；须先于 solution.* 以支持 python -I
    from .case_loading import get_raw
except ImportError:  # pragma: no cover
    from case_loading import get_raw

from solution.engine import Engine
from solution.loader import InputError, load_case
from solution.propagate import propagate


class ValidationErrorTests(unittest.TestCase):
    def _base(self, prefix: str) -> dict:
        return copy.deepcopy(get_raw(prefix))

    def test_e1001_missing_field(self):
        raw = self._base("C01")
        del raw["credentials"]
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1001")

    def test_e1001_malformed_json_document(self):
        from solution.__main__ import _load_document
        with self.assertRaises(InputError) as ctx:
            _load_document("{not json")
        self.assertEqual(ctx.exception.code, "E1001")

    def test_e1002_duplicate_id(self):
        raw = self._base("C01")
        raw["credentials"][1]["credential_id"] = raw["credentials"][0]["credential_id"]
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1002")

    def test_e1003_unknown_reference(self):
        raw = self._base("C01")
        raw["candidate_actions"][0]["migrations"][0]["from_credential_id"] = "ghost"
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1003")

    def test_e1004_cycle_rejected(self):
        raw = self._base("C01")
        raw["derivation_edges"].append(
            {"parent_id": "k-child", "child_id": "k-root", "inherit_risk": True}
        )
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1004")

    def test_e1005_negative_weight(self):
        raw = self._base("C01")
        raw["credentials"][0]["risk_weight"] = -1
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1005")

    def test_e1006_role_fixed_use_tenant_mismatch(self):
        raw = self._base("C01")
        raw["credentials"][0]["tenant"] = "tenant-other"
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1006")

    def test_e1006_initial_min_active_violation(self):
        raw = self._base("C01")
        raw["services"][1]["initial_bindings"]["admin"] = []
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1001")  # 空列表先撞类型检查

    def test_e1007_scale_limit(self):
        raw = self._base("C01")
        extra_services = [
            {"service_id": f"svc-extra-{i}", "tenant": "tenant-alpha",
             "role_requirements": [{"role": "admin", "min_active": 1, "sensitive": False}],
             "initial_bindings": {"admin": ["k-other"]}}
            for i in range(11)
        ]
        raw["services"].extend(extra_services)  # 2 + 11 = 13 > 12
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1007")

    def test_e1008_replace_without_migrations(self):
        raw = self._base("C01")
        raw["candidate_actions"][0]["migrations"] = []
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1008")

    def test_e1008_unknown_action_kind(self):
        raw = self._base("C01")
        raw["candidate_actions"][0]["kind"] = "rotate"
        with self.assertRaises(InputError) as ctx:
            load_case(raw)
        self.assertEqual(ctx.exception.code, "E1008")


class RuntimeBlockerTests(unittest.TestCase):
    def test_e2001_duplicate_action_execution(self):
        engine = Engine(load_case(get_raw("C01")))
        state = engine.attempt(engine.initial_state, "A01").state
        again = engine.attempt(state, "A01")
        self.assertFalse(again.ok)
        self.assertEqual(again.blocker.code, "E2001")

    def test_e2003_deadline_enforced(self):
        # 端到端构造：截止步 1，先用一个合规替换动作把步推进到 2，再撤销受污染凭据
        raw = {
            "case_id": "X-e2003", "description": "d", "deadline_step": 1,
            "credentials": [
                {"credential_id": "k-a", "display_name": "a", "tenant": "t", "role": "admin",
                 "custody_domain": "d1", "generation": "g1", "risk_weight": 5},
                {"credential_id": "k-b", "display_name": "b", "tenant": "t", "role": "admin",
                 "custody_domain": "d2", "generation": "g1", "risk_weight": 1},
            ],
            "derivation_edges": [],
            "exposure_records": [{"credential_id": "k-a"}],
            "replacements": [
                {"replacement_id": "r1", "display_name": "r", "tenant": "t", "role": "admin",
                 "custody_domain": "d9", "available_from_step": 1, "available_to_step": 5},
            ],
            "services": [
                {"service_id": "svc", "tenant": "t",
                 "role_requirements": [{"role": "admin", "min_active": 1, "sensitive": False}],
                 "initial_bindings": {"admin": ["k-a", "k-b"]}},
            ],
            "candidate_actions": [
                {"action_id": "X1", "kind": "replace", "risk_cost": 1, "service_id": "svc",
                 "window_from_step": 1, "window_to_step": 5,
                 "migrations": [{"role": "admin", "from_credential_id": "k-b",
                                 "to_credential_id": "r1"}]},
                {"action_id": "X2", "kind": "revoke", "risk_cost": 5,
                 "target_credential_id": "k-a"},
            ],
        }
        engine = Engine(load_case(raw))
        state = engine.attempt(engine.initial_state, "X1").state  # 步推进到 2
        self.assertEqual(state.step, 2)
        res = engine.attempt(state, "X2")
        self.assertFalse(res.ok)
        self.assertEqual(res.blocker.code, "E2003")
        self.assertEqual(res.blocker.detail["deadline_step"], 1)
        self.assertEqual(res.blocker.detail["step"], 2)

    def test_e2009_window_and_e2010_replacement_availability(self):
        engine = Engine(load_case(get_raw("C07")))
        g01 = engine.attempt(engine.initial_state, "G01")
        self.assertEqual(g01.blocker.code, "E2009")
        g03 = engine.attempt(engine.initial_state, "G03")
        self.assertEqual(g03.blocker.code, "E2010")

    def test_e2007_unbound_source(self):
        # 内存构造：服务初始绑定 k-a，动作却要求从 k-b 迁出 -> E2007
        raw = {
            "case_id": "X-e2007", "description": "d", "deadline_step": 3,
            "credentials": [
                {"credential_id": "k-a", "display_name": "a", "tenant": "t", "role": "admin",
                 "custody_domain": "d1", "generation": "g1", "risk_weight": 1},
                {"credential_id": "k-b", "display_name": "b", "tenant": "t", "role": "admin",
                 "custody_domain": "d2", "generation": "g1", "risk_weight": 1},
            ],
            "derivation_edges": [],
            "exposure_records": [],
            "replacements": [
                {"replacement_id": "r1", "display_name": "r", "tenant": "t", "role": "admin",
                 "custody_domain": "d9", "available_from_step": 1, "available_to_step": 3},
            ],
            "services": [
                {"service_id": "svc", "tenant": "t",
                 "role_requirements": [{"role": "admin", "min_active": 1, "sensitive": False}],
                 "initial_bindings": {"admin": ["k-a"]}},
            ],
            "candidate_actions": [
                {"action_id": "X1", "kind": "replace", "risk_cost": 1, "service_id": "svc",
                 "window_from_step": 1, "window_to_step": 3,
                 "migrations": [{"role": "admin", "from_credential_id": "k-b",
                                 "to_credential_id": "r1"}]},
            ],
        }
        engine = Engine(load_case(raw))
        res = engine.attempt(engine.initial_state, "X1")
        self.assertFalse(res.ok)
        self.assertEqual(res.blocker.code, "E2007")
        self.assertEqual(res.blocker.detail["from_credential_id"], "k-b")

    def test_e2006_role_mismatch_on_real_credential_target(self):
        # 迁移目标是真实凭据但固定角色不符 -> E2006
        raw = {
            "case_id": "X-e2006", "description": "d", "deadline_step": 3,
            "credentials": [
                {"credential_id": "k-a", "display_name": "a", "tenant": "t", "role": "admin",
                 "custody_domain": "d1", "generation": "g1", "risk_weight": 1},
                {"credential_id": "k-b", "display_name": "b", "tenant": "t", "role": "billing",
                 "custody_domain": "d2", "generation": "g1", "risk_weight": 1},
            ],
            "derivation_edges": [],
            "exposure_records": [],
            "replacements": [],
            "services": [
                {"service_id": "svc", "tenant": "t",
                 "role_requirements": [{"role": "admin", "min_active": 1, "sensitive": False}],
                 "initial_bindings": {"admin": ["k-a"]}},
            ],
            "candidate_actions": [
                {"action_id": "X1", "kind": "replace", "risk_cost": 1, "service_id": "svc",
                 "window_from_step": 1, "window_to_step": 3,
                 "migrations": [{"role": "admin", "from_credential_id": "k-a",
                                 "to_credential_id": "k-b"}]},
            ],
        }
        engine = Engine(load_case(raw))
        res = engine.attempt(engine.initial_state, "X1")
        self.assertFalse(res.ok)
        self.assertEqual(res.blocker.code, "E2006")
        self.assertEqual(res.blocker.detail["credential_role"], "billing")

    def test_propagation_result_attached(self):
        case = load_case(get_raw("C03"))
        prop = propagate(case)
        self.assertEqual(prop.paths["k-derived"], ("k-p", "k-derived"))
        self.assertTrue(prop.blocked_edges == ())


if __name__ == "__main__":
    unittest.main()
