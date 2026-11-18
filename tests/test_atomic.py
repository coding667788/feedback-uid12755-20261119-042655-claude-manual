"""替换动作原子性测试：多条迁移要么全部生效，要么整体阻断且无部分迁移。"""

from __future__ import annotations

import unittest

try:  # 先引导仓库根路径以支持 python -I
    from .case_loading import CASES_PATH  # noqa: F401
except ImportError:  # pragma: no cover
    from case_loading import CASES_PATH  # noqa: F401

from solution.engine import Engine
from solution.loader import load_case


def _atomic_case(second_target: str) -> dict:
    return {
        "case_id": "X-atomic", "description": "d", "deadline_step": 4,
        "credentials": [
            {"credential_id": "k-a", "display_name": "a", "tenant": "t", "role": "admin",
             "custody_domain": "d1", "generation": "g1", "risk_weight": 5},
            {"credential_id": "k-b", "display_name": "b", "tenant": "t", "role": "billing",
             "custody_domain": "d2", "generation": "g1", "risk_weight": 1},
            {"credential_id": "k-bad", "display_name": "bad", "tenant": "t", "role": "billing",
             "custody_domain": "d3", "generation": "g2", "risk_weight": 1},
        ],
        "derivation_edges": [
            {"parent_id": "k-a", "child_id": "k-bad", "inherit_risk": True},
        ],
        "exposure_records": [{"credential_id": "k-a"}],
        "replacements": [
            {"replacement_id": "r-a", "display_name": "ra", "tenant": "t", "role": "admin",
             "custody_domain": "d9", "available_from_step": 1, "available_to_step": 4},
            {"replacement_id": "r-b", "display_name": "rb", "tenant": "t", "role": "billing",
             "custody_domain": "d8", "available_from_step": 1, "available_to_step": 4},
        ],
        "services": [
            {"service_id": "svc", "tenant": "t",
             "role_requirements": [
                 {"role": "admin", "min_active": 1, "sensitive": False},
                 {"role": "billing", "min_active": 1, "sensitive": False},
             ],
             "initial_bindings": {"admin": ["k-a"], "billing": ["k-b"]}},
        ],
        "candidate_actions": [
            {"action_id": "X1", "kind": "replace", "risk_cost": 1, "service_id": "svc",
             "window_from_step": 1, "window_to_step": 4,
             "migrations": [
                 {"role": "admin", "from_credential_id": "k-a", "to_credential_id": "r-a"},
                 {"role": "billing", "from_credential_id": "k-b", "to_credential_id": second_target},
             ]},
            {"action_id": "X2", "kind": "replace", "risk_cost": 1, "service_id": "svc",
             "window_from_step": 1, "window_to_step": 4,
             "migrations": [
                 {"role": "admin", "from_credential_id": "k-a", "to_credential_id": "r-a"},
                 {"role": "billing", "from_credential_id": "k-b", "to_credential_id": "r-b"},
             ]},
        ],
    }


class AtomicMigrationTests(unittest.TestCase):
    def test_one_bad_migration_blocks_whole_action_without_partial_effect(self):
        # 第二条迁移指向受污染衍生凭据 k-bad -> E2008，整动作原子阻断
        engine = Engine(load_case(_atomic_case("k-bad")))
        before = engine.snapshot(engine.initial_state)
        res = engine.attempt(engine.initial_state, "X1")
        self.assertFalse(res.ok)
        self.assertEqual(res.blocker.code, "E2008")
        # 状态机不产生新状态，且初始绑定一条都没变（无部分迁移）
        self.assertIsNone(res.state)
        after = engine.snapshot(engine.initial_state)
        self.assertEqual(before["services"], after["services"])
        self.assertEqual(after["revoked"], [])

    def test_all_good_migrations_apply_together(self):
        engine = Engine(load_case(_atomic_case("r-b")))
        res = engine.attempt(engine.initial_state, "X2")
        self.assertTrue(res.ok, res.blocker)
        snap = engine.snapshot(res.state)
        self.assertEqual(snap["services"]["svc"]["roles"]["admin"]["active_bindings"], ["r-a"])
        self.assertEqual(snap["services"]["svc"]["roles"]["billing"]["active_bindings"], ["r-b"])
        self.assertTrue(engine.is_compliant(res.state))


if __name__ == "__main__":
    unittest.main()
