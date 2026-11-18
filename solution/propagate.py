"""暴露风险的有向传播。

规则（对应题目约束）：
1. 明确暴露记录中的凭据直接成为受污染（tainted）凭据；
2. 仅沿衍生边的方向 parent -> child 传播，不反向；
3. 边上 inherit_risk=False 时传播在该边处阻断，父代受污染不代表子代受污染；
4. 被阻断的边作为证据一并输出，说明风险为何没有继续扩散。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .model import CaseModel


@dataclass(frozen=True)
class PropagationResult:
    tainted: frozenset[str]
    explicit: frozenset[str]
    # 每个受污染凭据的一条最短传播路径（节点 id 序列，显式暴露节点路径长度为 1）
    paths: dict[str, tuple[str, ...]]
    # 被阻断的边：(parent_id, child_id)，父代已污染但 inherit_risk=False
    blocked_edges: tuple[tuple[str, str], ...]
    # 邻接表（仅保留可继承边），供报告与测试复用
    inheritable_adj: dict[str, tuple[str, ...]]


def propagate(case: CaseModel) -> PropagationResult:
    adj_all: dict[str, list[tuple[str, bool]]] = {cid: [] for cid in case.credentials}
    adj_ok: dict[str, list[str]] = {cid: [] for cid in case.credentials}
    for edge in case.edges:
        adj_all[edge.parent_id].append((edge.child_id, edge.inherit_risk))
        if edge.inherit_risk:
            adj_ok[edge.parent_id].append(edge.child_id)

    explicit = frozenset(case.exposure_records)
    paths: dict[str, tuple[str, ...]] = {cid: (cid,) for cid in explicit}
    blocked: list[tuple[str, str]] = []
    queue: deque[str] = deque(sorted(explicit))
    seen: set[str] = set(explicit)

    while queue:
        node = queue.popleft()
        for child, inherit in sorted(adj_all[node]):
            if not inherit:
                # 父代已污染才构成一次“被阻断的传播尝试”
                blocked.append((node, child))
                continue
            if child not in seen:
                seen.add(child)
                paths[child] = paths[node] + (child,)
                queue.append(child)

    return PropagationResult(
        tainted=frozenset(seen),
        explicit=explicit,
        paths=dict(sorted(paths.items())),
        blocked_edges=tuple(blocked),
        inheritable_adj={k: tuple(sorted(v)) for k, v in adj_ok.items()},
    )
