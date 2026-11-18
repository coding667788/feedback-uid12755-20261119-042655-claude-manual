"""独立穷举核对。

与 solver 完全不同的搜索组织方式：不做记忆化、不做分支定界，
递归枚举全部动作排列，每条排列沿路径执行直到第一个被阻断的动作，
途中考察每个可达前缀。动作可行性判定复用 engine（规则只有一份实现，
避免规则分歧），搜索算法本身独立，用于交叉验证 solver 的最优性结论。

规模为 O(n!)，仅用于 n 较小的测试案例。
"""

from __future__ import annotations

from dataclasses import dataclass

from .engine import Engine, State
from .model import CaseModel
from .propagate import PropagationResult


@dataclass
class BruteResult:
    feasible: bool
    best_sequence: tuple[str, ...]
    best_cost: int
    best_cover: int
    total_cover_weight: int
    reachable_prefixes: int


def brute_force(case: CaseModel, propagation: PropagationResult | None = None) -> BruteResult:
    engine = Engine(case, propagation)
    tainted = engine.tainted
    weights = {cid: case.cred(cid).risk_weight for cid in tainted}
    total_weight = sum(weights.values())

    def cover(state: State) -> int:
        return sum(w for cid, w in weights.items() if cid in state.revoked)

    def goal(state: State) -> bool:
        return tainted.issubset(state.revoked) and engine.is_compliant(state)

    def rank(state: State) -> tuple:
        return state.cost, len(state.sequence), state.sequence

    best_goal: State | None = None
    best_cover_state: State = engine.initial_state
    counters = {"prefixes": 1}

    def walk(state: State, unused: list[str]) -> None:
        nonlocal best_goal, best_cover_state
        if goal(state):
            if best_goal is None or rank(state) < rank(best_goal):
                best_goal = state
        if cover(state) > cover(best_cover_state):
            best_cover_state = state
        for aid in tuple(unused):
            result = engine.attempt(state, aid)
            if not result.ok:
                continue  # 该排列在此处被阻断，停止延伸
            counters["prefixes"] += 1
            nxt = result.state
            rest = [x for x in unused if x != aid]
            walk(nxt, rest)

    walk(engine.initial_state, list(case.action_order))

    chosen = best_goal if best_goal is not None else best_cover_state
    return BruteResult(
        feasible=best_goal is not None,
        best_sequence=chosen.sequence,
        best_cost=chosen.cost,
        best_cover=cover(best_cover_state),
        total_cover_weight=total_weight,
        reachable_prefixes=counters["prefixes"],
    )
