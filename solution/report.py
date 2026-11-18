"""结果 JSON 组装：逐步回放求解出的序列并生成证据。

输出完全确定（不含时间戳、环境信息），保证 cases.json 可重放。
"""

from __future__ import annotations

from typing import Any

from .engine import AttemptResult, Engine
from .loader import load_case
from .model import CaseModel
from .propagate import PropagationResult, propagate
from .solver import SolveResult, solve


def run_case(raw: dict[str, Any]) -> dict[str, Any]:
    """载入单个原始案例字典并返回完整报告字典。"""
    case = load_case(raw)
    return build_report(case)


def build_report(case: CaseModel, propagation: PropagationResult | None = None) -> dict[str, Any]:
    prop = propagation or propagate(case)
    result = solve(case, prop)
    engine = Engine(case, prop)

    report: dict[str, Any] = {
        "case_id": case.case_id,
        "description": case.description,
        "status": "FEASIBLE" if result.feasible else "INFEASIBLE",
        "objective": {
            "rule": "min(total_risk_cost), then min(sequence_length), then lexicographic(action_ids)",
            "optimal_total_risk_cost": result.total_cost,
            "sequence_length": len(result.sequence),
            "action_id_sequence": list(result.sequence),
        },
        "deadline_step": case.deadline_step,
        "risk_propagation": _propagation_section(case, prop),
        "steps": _replay_steps(case, engine, result),
        "final_coverage_check": _coverage_section(case, engine, result),
        "search_stats": {
            "reachable_states": result.reachable_states,
            "transitions_attempted": result.transitions_attempted,
            "visited_executed_sets": result.visited_sets,
        },
    }
    if not result.feasible:
        report["infeasibility_evidence"] = _infeasible_section(case, engine, result)
    return report


def _propagation_section(case: CaseModel, prop: PropagationResult) -> dict[str, Any]:
    paths = []
    for cid in sorted(prop.tainted):
        chain = prop.paths[cid]
        paths.append({
            "credential_id": cid,
            "explicitly_exposed": cid in prop.explicit,
            "path": [
                {
                    "credential_id": node,
                    "display_name": case.cred(node).display_name,
                    "tenant": case.cred(node).tenant,
                    "generation": case.cred(node).generation,
                }
                for node in chain
            ],
            "path_edge_ids": [f"{chain[i]}->{chain[i + 1]}" for i in range(len(chain) - 1)],
        })
    edges_section = [
        {
            "parent_id": e.parent_id,
            "child_id": e.child_id,
            "inherit_risk": e.inherit_risk,
            "blocks_propagation": (not e.inherit_risk) and e.parent_id in prop.tainted,
        }
        for e in case.edges
    ]
    return {
        "explicitly_exposed": sorted(prop.explicit),
        "tainted_credentials": sorted(prop.tainted),
        "propagation_paths": paths,
        "derivation_edges": edges_section,
        "blocked_edges": [{"parent_id": p, "child_id": c} for p, c in prop.blocked_edges],
    }


def _replay_steps(case: CaseModel, engine: Engine, result: SolveResult) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    state = engine.initial_state
    steps.append({
        "step": 0,
        "label": "initial_state",
        "action_id": None,
        "state_snapshot": engine.snapshot(state),
    })
    for index, aid in enumerate(result.sequence, start=1):
        action = case.action(aid)
        attempt: AttemptResult = engine.attempt(state, aid)
        assert attempt.ok and attempt.state is not None, f"回放失败: {aid}"
        state = attempt.state
        entry: dict[str, Any] = {
            "step": index,
            "label": "apply",
            "action_id": aid,
            "kind": action.kind,
            "risk_cost": action.risk_cost,
            "cumulative_cost": state.cost,
            "state_snapshot": engine.snapshot(state),
        }
        if action.kind == "revoke":
            entry["revoked_credential"] = action.target_credential_id
            entry["deadline_check"] = {
                "step": index,
                "deadline_step": case.deadline_step,
                "within_deadline": index <= case.deadline_step,
                "target_tainted": action.target_credential_id in engine.tainted,
            }
        else:
            entry["service_id"] = action.service_id
            entry["config_window"] = [action.window_from_step, action.window_to_step]
            entry["window_check"] = {
                "step": index,
                "within_window": action.window_from_step <= index <= action.window_to_step,
            }
            entry["atomic_migrations"] = []
            for m in action.migrations:
                repl_obj = case.replacements.get(m.to_credential_id)
                if repl_obj is not None:
                    window = [repl_obj.available_from_step, repl_obj.available_to_step]
                    window_ok = window[0] <= index <= window[1]
                    target_kind = "replacement"
                else:
                    window = None
                    window_ok = True
                    target_kind = "real_credential"
                entry["atomic_migrations"].append({
                    "role": m.role,
                    "from_credential_id": m.from_credential_id,
                    "to_credential_id": m.to_credential_id,
                    "target_kind": target_kind,
                    "replacement_available_window": window,
                    "replacement_window_check": window_ok,
                })
        steps.append(entry)
    return steps


def _coverage_section(case: CaseModel, engine: Engine, result: SolveResult) -> dict[str, Any]:
    rows = []
    for cid in sorted(engine.tainted):
        cred = case.cred(cid)
        rows.append({
            "credential_id": cid,
            "display_name": cred.display_name,
            "tenant": cred.tenant,
            "generation": cred.generation,
            "risk_weight": cred.risk_weight,
            "revoked": cid in result.final_state.revoked,
            "propagation_path": list(engine.propagation.paths[cid]),
        })
    revoked_tainted = [r for r in rows if r["revoked"]]
    return {
        "tainted_total": len(rows),
        "tainted_revoked": len(revoked_tainted),
        "all_tainted_revoked_before_deadline": result.feasible,
        "coverage_weight": result.best_cover,
        "total_coverage_weight": result.total_cover_weight,
        "rows": rows,
        "continuity_compliant": engine.is_compliant(result.final_state),
        "violations": [
            {"code": v.code, "service_id": v.service_id, "reason": v.reason, "detail": v.detail}
            for v in engine.violations(result.final_state)
        ],
    }


def _infeasible_section(case: CaseModel, engine: Engine, result: SolveResult) -> dict[str, Any]:
    state = result.best_cover_state
    return {
        "best_reachable_state": {
            "action_id_sequence": list(state.sequence),
            "total_risk_cost": state.cost,
            "revoked": sorted(state.revoked),
            "state_snapshot": engine.snapshot(state),
        },
        "revocation_risk_coverage": {
            "covered_weight": result.best_cover,
            "total_weight": result.total_cover_weight,
            "gap_weight": result.coverage_gap,
            "tainted_remaining": result.tainted_remaining,
        },
        "next_step_blockers": [
            {
                "action_id": b.action_id,
                "code": b.code,
                "reason": b.reason,
                "detail": b.detail,
            }
            for b in result.blockers
        ],
    }
