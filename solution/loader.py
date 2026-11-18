"""JSON 载入与输入校验。

错误码（输入侧，CLI 以退出码 3 返回）：
  E1001 顶层结构/字段类型错误
  E1002 id 重复
  E1003 引用了不存在的凭据/替代凭据/服务/动作
  E1004 衍生关系自环或成环（必须为 DAG）
  E1005 数值非法（权重、成本、步区间、截止步等）
  E1006 服务初始绑定不合规（租户/角色固定、保管域隔离、最低数量）
  E1007 规模超限（服务 > 12 或候选动作 > 18）
  E1008 候选动作结构非法
"""

from __future__ import annotations

from typing import Any

from .model import (
    CandidateAction,
    CaseModel,
    Credential,
    DerivationEdge,
    InputError,
    Migration,
    Replacement,
    RoleRequirement,
    Service,
)

MAX_SERVICES = 12
MAX_ACTIONS = 18
_KINDS = ("revoke", "replace")


def _require(obj: Any, key: str, typ: type | tuple[type, ...], ctx: str) -> Any:
    if not isinstance(obj, dict) or key not in obj:
        raise InputError("E1001", f"{ctx} 缺少字段 {key!r}")
    val = obj[key]
    if not isinstance(val, typ):
        name = typ.__name__ if isinstance(typ, type) else "/".join(t.__name__ for t in typ)
        raise InputError("E1001", f"{ctx}.{key} 类型应为 {name}")
    return val


def _as_int(val: Any, ctx: str, minimum: int | None = None) -> int:
    if not isinstance(val, int) or isinstance(val, bool):
        raise InputError("E1005", f"{ctx} 必须为整数")
    if minimum is not None and val < minimum:
        raise InputError("E1005", f"{ctx} 必须 >= {minimum}")
    return val


def load_case(raw: dict[str, Any]) -> CaseModel:
    """把已 json.load 的字典构建为 CaseModel，并完成全部静态校验。"""

    if not isinstance(raw, dict):
        raise InputError("E1001", "案例顶层必须为对象")
    case_id = _require(raw, "case_id", str, "case")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise InputError("E1001", "case.description 必须为字符串")
    deadline_step = _as_int(_require(raw, "deadline_step", int, "case"), "deadline_step", 1)

    credentials = _load_credentials(_require(raw, "credentials", list, "case"))
    cred_ids = set(credentials)

    edges = _load_edges(_require(raw, "derivation_edges", list, "case"), cred_ids)
    _ensure_dag(edges, cred_ids)

    exposure_records = tuple(
        _require(rec, "credential_id", str, "exposure_records[]")
        for rec in _require(raw, "exposure_records", list, "case")
    )
    for cid in exposure_records:
        if cid not in cred_ids:
            raise InputError("E1003", f"暴露记录引用未知凭据 {cid}")
    # 显式暴露标记回填到凭据上
    for cid in exposure_records:
        object.__setattr__(credentials[cid], "exposed", True)

    replacements = _load_replacements(_require(raw, "replacements", list, "case"), cred_ids)
    services = _load_services(_require(raw, "services", list, "case"), credentials)
    if len(services) > MAX_SERVICES:
        raise InputError("E1007", f"服务数 {len(services)} 超过上限 {MAX_SERVICES}")

    actions, action_order = _load_actions(
        _require(raw, "candidate_actions", list, "case"),
        cred_ids, set(replacements), set(services),
    )
    if len(actions) > MAX_ACTIONS:
        raise InputError("E1007", f"候选动作数 {len(actions)} 超过上限 {MAX_ACTIONS}")

    return CaseModel(
        case_id=case_id,
        description=description,
        deadline_step=deadline_step,
        credentials=credentials,
        edges=edges,
        replacements=replacements,
        services=services,
        actions=actions,
        action_order=action_order,
        exposure_records=exposure_records,
    )


def _load_credentials(raw_list: list[Any]) -> dict[str, Credential]:
    out: dict[str, Credential] = {}
    for item in raw_list:
        cid = _require(item, "credential_id", str, "credentials[]")
        if cid in out:
            raise InputError("E1002", f"凭据 id 重复: {cid}")
        tenant = _require(item, "tenant", str, f"credentials[{cid}]")
        role = _require(item, "role", str, f"credentials[{cid}]")
        domain = _require(item, "custody_domain", str, f"credentials[{cid}]")
        generation = _require(item, "generation", str, f"credentials[{cid}]")
        weight = _as_int(
            _require(item, "risk_weight", int, f"credentials[{cid}]"),
            f"credentials[{cid}].risk_weight", 0,
        )
        out[cid] = Credential(
            cid,
            _require(item, "display_name", str, f"credentials[{cid}]"),
            tenant, role, domain, generation, weight,
        )
    return out


def _load_edges(raw_list: list[Any], cred_ids: set[str]) -> tuple[DerivationEdge, ...]:
    edges: list[DerivationEdge] = []
    for item in raw_list:
        parent = _require(item, "parent_id", str, "derivation_edges[]")
        child = _require(item, "child_id", str, "derivation_edges[]")
        if parent not in cred_ids or child not in cred_ids:
            raise InputError("E1003", f"衍生边引用未知凭据: {parent} -> {child}")
        if parent == child:
            raise InputError("E1004", f"衍生边不允许自环: {parent}")
        if not isinstance(item.get("inherit_risk"), bool):
            raise InputError("E1001", "derivation_edges[].inherit_risk 必须为布尔值")
        edges.append(DerivationEdge(parent, child, item["inherit_risk"]))
    return tuple(edges)


def _ensure_dag(edges: tuple[DerivationEdge, ...], cred_ids: set[str]) -> None:
    """Kahn 拓扑排序检测成环。"""
    adj: dict[str, list[str]] = {cid: [] for cid in cred_ids}
    indeg: dict[str, int] = {cid: 0 for cid in cred_ids}
    for edge in edges:
        adj[edge.parent_id].append(edge.child_id)
        indeg[edge.child_id] += 1
    queue = sorted(cid for cid, d in indeg.items() if d == 0)
    visited = 0
    while queue:
        node = queue.pop(0)
        visited += 1
        for nxt in adj[node]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                queue.append(nxt)
        queue.sort()
    if visited != len(cred_ids):
        raise InputError("E1004", "衍生关系存在环，风险传播要求其为 DAG")


def _load_replacements(raw_list: list[Any], cred_ids: set[str]) -> dict[str, Replacement]:
    out: dict[str, Replacement] = {}
    for item in raw_list:
        rid = _require(item, "replacement_id", str, "replacements[]")
        if rid in out:
            raise InputError("E1002", f"替代凭据 id 重复: {rid}")
        if rid in cred_ids:
            raise InputError("E1002", f"替代凭据 id 与真实凭据冲突: {rid}")
        lo = _as_int(_require(item, "available_from_step", int, f"replacements[{rid}]"),
                     f"replacements[{rid}].available_from_step", 1)
        hi = _as_int(_require(item, "available_to_step", int, f"replacements[{rid}]"),
                     f"replacements[{rid}].available_to_step", 1)
        if lo > hi:
            raise InputError("E1005", f"replacements[{rid}] 可用区间倒置")
        out[rid] = Replacement(
            rid,
            _require(item, "display_name", str, f"replacements[{rid}]"),
            _require(item, "tenant", str, f"replacements[{rid}]"),
            _require(item, "role", str, f"replacements[{rid}]"),
            _require(item, "custody_domain", str, f"replacements[{rid}]"),
            lo, hi,
        )
    return out


def _load_services(
    raw_list: list[Any], credentials: dict[str, Credential]
) -> dict[str, Service]:
    out: dict[str, Service] = {}
    for item in raw_list:
        sid = _require(item, "service_id", str, "services[]")
        if sid in out:
            raise InputError("E1002", f"服务 id 重复: {sid}")
        tenant = _require(item, "tenant", str, f"services[{sid}]")
        reqs = _load_requirements(_require(item, "role_requirements", list, f"services[{sid}]"), sid)
        raw_binding = _require(item, "initial_bindings", dict, f"services[{sid}]")
        bindings: dict[str, tuple[str, ...]] = {}
        req_map = {r.role: r for r in reqs}
        sensitive_domains: list[tuple[str, str]] = []
        for role, cid_list in raw_binding.items():
            if role not in req_map:
                raise InputError("E1006", f"services[{sid}] 绑定了未声明角色 {role}")
            if not isinstance(cid_list, list) or not cid_list:
                raise InputError("E1001", f"services[{sid}].initial_bindings[{role}] 必须为非空列表")
            bound: list[str] = []
            for cid in cid_list:
                if not isinstance(cid, str):
                    raise InputError("E1001", f"services[{sid}] 绑定项必须为字符串")
                if cid not in credentials:
                    raise InputError("E1003", f"services[{sid}] 绑定未知凭据 {cid}")
                if cid in bound:
                    raise InputError("E1006", f"services[{sid}] 角色 {role} 重复绑定 {cid}")
                cred = credentials[cid]
                if cred.tenant != tenant:
                    raise InputError(
                        "E1006",
                        f"services[{sid}] 凭据 {cid} 租户 {cred.tenant} 与服务租户 {tenant} 不符（用途固定）",
                    )
                if cred.role != role:
                    raise InputError(
                        "E1006",
                        f"services[{sid}] 凭据 {cid} 固定角色 {cred.role} 不能绑定到角色 {role}",
                    )
                bound.append(cid)
            bindings[role] = tuple(bound)
            if req_map[role].sensitive:
                for cid in bound:
                    sensitive_domains.append((role, credentials[cid].custody_domain))
        for role, req in req_map.items():
            active = len(bindings.get(role, ()))
            if active < req.min_active:
                raise InputError(
                    "E1006",
                    f"services[{sid}] 角色 {role} 初始活跃数 {active} < 最低要求 {req.min_active}",
                )
        _check_custody(sensitive_domains, f"services[{sid}] 初始绑定")
        out[sid] = Service(sid, tenant, reqs, bindings)
    return out


def _load_requirements(raw_list: list[Any], sid: str) -> tuple[RoleRequirement, ...]:
    reqs: list[RoleRequirement] = []
    seen: set[str] = set()
    for item in raw_list:
        role = _require(item, "role", str, f"services[{sid}].role_requirements[]")
        if role in seen:
            raise InputError("E1002", f"services[{sid}] 角色要求重复: {role}")
        seen.add(role)
        minimum = _as_int(_require(item, "min_active", int, f"services[{sid}].{role}"),
                          f"services[{sid}].{role}.min_active", 1)
        if not isinstance(item.get("sensitive"), bool):
            raise InputError("E1001", f"services[{sid}].{role}.sensitive 必须为布尔值")
        reqs.append(RoleRequirement(role, minimum, item["sensitive"]))
    return tuple(reqs)


def _check_custody(pairs: list[tuple[str, str]], ctx: str) -> None:
    """同一服务的两个敏感角色不得落在同一保管域。"""
    domain_roles: dict[str, set[str]] = {}
    for role, domain in pairs:
        domain_roles.setdefault(domain, set()).add(role)
    for domain, roles in domain_roles.items():
        if len(roles) > 1:
            raise InputError("E1006", f"{ctx} 保管域 {domain} 被多个敏感角色共用: {sorted(roles)}")


def _load_actions(
    raw_list: list[Any],
    cred_ids: set[str],
    repl_ids: set[str],
    service_ids: set[str],
) -> tuple[dict[str, CandidateAction], tuple[str, ...]]:
    out: dict[str, CandidateAction] = {}
    order: list[str] = []
    for item in raw_list:
        aid = _require(item, "action_id", str, "candidate_actions[]")
        if aid in out:
            raise InputError("E1002", f"动作 id 重复: {aid}")
        kind = _require(item, "kind", str, f"candidate_actions[{aid}]")
        if kind not in _KINDS:
            raise InputError("E1008", f"candidate_actions[{aid}] 未知 kind: {kind}")
        cost = _as_int(_require(item, "risk_cost", int, f"candidate_actions[{aid}]"),
                       f"candidate_actions[{aid}].risk_cost", 0)
        if kind == "revoke":
            target = _require(item, "target_credential_id", str, f"candidate_actions[{aid}]")
            if target not in cred_ids:
                raise InputError("E1003", f"动作 {aid} 撤销未知凭据 {target}")
            out[aid] = CandidateAction(aid, "revoke", cost, target_credential_id=target)
        else:
            sid = _require(item, "service_id", str, f"candidate_actions[{aid}]")
            if sid not in service_ids:
                raise InputError("E1003", f"动作 {aid} 引用未知服务 {sid}")
            lo = _as_int(_require(item, "window_from_step", int, f"candidate_actions[{aid}]"),
                         f"candidate_actions[{aid}].window_from_step", 1)
            hi = _as_int(_require(item, "window_to_step", int, f"candidate_actions[{aid}]"),
                         f"candidate_actions[{aid}].window_to_step", 1)
            if lo > hi:
                raise InputError("E1005", f"candidate_actions[{aid}] 配置步区间倒置")
            raw_migs = _require(item, "migrations", list, f"candidate_actions[{aid}]")
            if not raw_migs:
                raise InputError("E1008", f"替换动作 {aid} 至少包含一条迁移")
            migs: list[Migration] = []
            mig_roles: set[str] = set()
            for mig in raw_migs:
                role = _require(mig, "role", str, f"candidate_actions[{aid}].migrations[]")
                if role in mig_roles:
                    raise InputError("E1008", f"动作 {aid} 对角色 {role} 存在多条迁移（须原子合并为一条）")
                mig_roles.add(role)
                src = _require(mig, "from_credential_id", str, f"candidate_actions[{aid}].{role}")
                dst = _require(mig, "to_credential_id", str, f"candidate_actions[{aid}].{role}")
                if src not in cred_ids:
                    raise InputError("E1003", f"动作 {aid} 迁移源未知凭据 {src}")
                # 目标允许是干净的替代凭据，或另一项真实凭据代数
                # （后者用于“试图换绑到已暴露衍生凭据”这类运行期阻断场景）
                if dst not in repl_ids and dst not in cred_ids:
                    raise InputError("E1003", f"动作 {aid} 迁移目标未知凭据/替代凭据 {dst}")
                if src == dst:
                    raise InputError("E1008", f"动作 {aid} 迁移源与目标相同: {src}")
                migs.append(Migration(role, src, dst))
            out[aid] = CandidateAction(
                aid, "replace", cost, lo, hi, service_id=sid, migrations=tuple(migs),
            )
        order.append(aid)
    # 平局定序按动作 ID 字典序，与输入数组排列无关（输入换序稳定）
    return out, tuple(sorted(order))
