"""完整序列求解器。

搜索空间为候选动作的子集排列（规模上限 18，且每动作至多执行一次）。
关键性质：状态的撤销集合、绑定与累计成本都只取决于“已执行动作集合”，
与执行顺序无关（动作是否可行则与顺序相关），因此以已执行集合作为
记忆化键做去重；分支定界按目标序
(总风险成本, 序列长度, 动作 ID 字典序) 维护最优完整序列。

无解时在全部可达状态中按
(撤销风险覆盖, 剩余缺口, 成本, 长度, ID 序列) 选出覆盖最高的可达状态，
并枚举该状态下每个未执行动作的阻断证据。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .engine import Blocker, Engine, State
from .model import CaseModel
from .propagate import PropagationResult


@dataclass
class SolveResult:
    feasible: bool
    sequence: tuple[str, ...]
    total_cost: int
    final_state: State
    best_cover_state: State
    best_cover: int
    total_cover_weight: int
    coverage_gap: int
    blockers: list[Blocker]
    reachable_states: int
    transitions_attempted: int
    visited_sets: int
    tainted_remaining: list[str] = field(default_factory=list)


def solve(case: CaseModel, propagation: PropagationResult | None = None) -> SolveResult:
    engine = Engine(case, propagation)
    tainted = engine.tainted
    weight = {cid: case.cred(cid).risk_weight for cid in tainted}
    total_cover_weight = sum(weight.values())
    rank = {aid: i for i, aid in enumerate(case.action_order)}

    def coverage(state: State) -> int:
        return sum(weight[cid] for cid in tainted if cid in state.revoked)

    def remaining_weight(state: State) -> int:
        return sum(weight[cid] for cid in tainted if cid not in state.revoked)

    def is_goal(state: State) -> bool:
        # 截止步约束在 attempt 处以 E2003 强制，到达这里的撤销均未逾期
        return tainted.issubset(state.revoked) and engine.is_compliant(state)

    def goal_tuple(state: State) -> tuple:
        return state.cost, len(state.sequence), state.sequence

    def reachable_key(state: State) -> tuple:
        # 越大越优：覆盖高 → 缺口小 → 成本低 → 短 → ID 序列字典序小
        neg_seq = tuple(-rank[aid] for aid in state.sequence)
        return (coverage(state), -remaining_weight(state), -state.cost,
                -len(state.sequence), neg_seq)

    initial = engine.initial_state
    best_goal: State | None = None
    best_reachable: State = initial
    best_reachable_key: tuple = reachable_key(initial)
    visited: set[frozenset[str]] = set()
    stats = {"reachable": 1, "attempts": 0}

    def dfs(state: State) -> State | None:
        nonlocal best_goal, best_reachable, best_reachable_key

        rkey = reachable_key(state)
        if rkey > best_reachable_key:
            best_reachable, best_reachable_key = state, rkey

        if is_goal(state):
            if best_goal is None or goal_tuple(state) < goal_tuple(best_goal):
                best_goal = state
            return state

        # 同一已执行集合必然给出同一状态（成本与结果均由集合确定）
        if state.executed in visited:
            return None
        visited.add(state.executed)

        local_best: State | None = None
        for aid in case.action_order:
            if aid in state.executed:
                continue
            stats["attempts"] += 1
            result = engine.attempt(state, aid)
            if not result.ok:
                continue
            nxt = result.state
            stats["reachable"] += 1
            # 分支定界：成本严格超过已知最优目标，后续动作成本非负，不可能反超
            if best_goal is not None and nxt.cost > best_goal.cost:
                continue
            sub = dfs(nxt)
            if sub is not None and (local_best is None or goal_tuple(sub) < goal_tuple(local_best)):
                local_best = sub
        return local_best

    found = dfs(initial)
    final = found if found is not None else best_reachable

    blockers: list[Blocker] = []
    tainted_remaining: list[str] = []
    gap = 0
    if found is None:
        blockers = _collect_blockers(engine, best_reachable)
        tainted_remaining = sorted(cid for cid in tainted if cid not in best_reachable.revoked)
        gap = total_cover_weight - coverage(best_reachable)

    return SolveResult(
        feasible=found is not None,
        sequence=final.sequence,
        total_cost=final.cost,
        final_state=final,
        best_cover_state=best_reachable,
        best_cover=coverage(best_reachable),
        total_cover_weight=total_cover_weight,
        coverage_gap=gap,
        blockers=blockers,
        reachable_states=stats["reachable"],
        transitions_attempted=stats["attempts"],
        visited_sets=len(visited),
        tainted_remaining=tainted_remaining,
    )


def _collect_blockers(engine: Engine, state: State) -> list[Blocker]:
    """对最佳可达状态枚举每个未执行动作的下一步证据。"""
    out: list[Blocker] = []
    for aid in engine.case.action_order:
        if aid in state.executed:
            continue
        result = engine.attempt(state, aid)
        if result.ok:
            out.append(Blocker(
                "OK", aid,
                f"动作 {aid} 在该状态可执行，但其所有延伸都无法在截止步前完成全部撤销",
                {"step": state.step},
            ))
        else:
            out.append(result.blocker)  # type: ignore[arg-type]
    return out
