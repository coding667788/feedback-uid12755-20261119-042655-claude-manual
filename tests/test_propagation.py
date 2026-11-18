"""风险传播规则的单元测试：有向边、阻断边、不反向传播。"""

from __future__ import annotations

import unittest

try:  # 兼容 discover -s tests 的顶层导入；须先于 solution.* 以支持 python -I
    from .case_loading import get_raw
except ImportError:  # pragma: no cover
    from case_loading import get_raw

from solution.loader import load_case
from solution.propagate import propagate


class PropagationTests(unittest.TestCase):
    def test_c01_inheritance_and_blocking_edge(self):
        case = load_case(get_raw("C01"))
        result = propagate(case)

        # k-root 显式暴露；k-child 经可继承边污染；k-billing 被 inherit_risk=False 阻断
        self.assertEqual(result.explicit, frozenset({"k-root"}))
        self.assertEqual(result.tainted, frozenset({"k-root", "k-child"}))
        self.assertNotIn("k-billing", result.tainted)

        # 传播路径严格沿有向边
        self.assertEqual(result.paths["k-root"], ("k-root",))
        self.assertEqual(result.paths["k-child"], ("k-root", "k-child"))

        # 阻断边作为证据输出
        self.assertIn(("k-child", "k-billing"), result.blocked_edges)
        self.assertNotIn(("k-billing", "k-child"), result.blocked_edges)  # 不反向

    def test_propagation_never_runs_reverse(self):
        # C02 中 k-s1/k-s2 是 k-shared 的子代；暴露子代不应污染父代
        raw = get_raw("C02")
        raw = _with_exposure(raw, "k-s1")
        case = load_case(raw)
        result = propagate(case)
        self.assertIn("k-s1", result.tainted)
        self.assertNotIn("k-shared", result.tainted)
        self.assertNotIn("k-s2", result.tainted)  # 兄弟节点之间不传播

    def test_blocked_edge_stops_whole_branch(self):
        raw = {
            "case_id": "X-block", "description": "d", "deadline_step": 3,
            "credentials": [
                _cred("a", "t", "r", "d1", 1), _cred("b", "t", "r", "d1", 1),
                _cred("c", "t", "r", "d1", 1),
            ],
            "derivation_edges": [
                {"parent_id": "a", "child_id": "b", "inherit_risk": False},
                {"parent_id": "b", "child_id": "c", "inherit_risk": True},
            ],
            "exposure_records": [{"credential_id": "a"}],
            "replacements": [],
            "services": [],
            "candidate_actions": [],
        }
        result = propagate(load_case(raw))
        self.assertEqual(result.tainted, frozenset({"a"}))
        self.assertEqual(result.blocked_edges, (("a", "b"),))


def _cred(cid: str, tenant: str, role: str, domain: str, weight: int) -> dict:
    return {
        "credential_id": cid, "display_name": cid, "tenant": tenant, "role": role,
        "custody_domain": domain, "generation": "g1", "risk_weight": weight,
    }


def _with_exposure(raw: dict, cid: str) -> dict:
    clone = json_clone(raw)
    clone["exposure_records"] = [{"credential_id": cid}]
    return clone


def json_clone(obj):
    import json
    return json.loads(json.dumps(obj, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
