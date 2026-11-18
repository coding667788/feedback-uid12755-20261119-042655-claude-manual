"""轮换状态机：候选动作的可行性与每一步的业务连续性约束。

阻断码（运行侧，写在结果 JSON 中，不属于输入错误）：
  E2001 动作已执行
  E2002 撤销目标已被撤销
  E2003 受污染凭据的撤销步晚于截止步
  E2004 迁移/撤销后某角色活跃凭据数低于最低要求
  E2005 迁移后两个敏感角色落到同一保管域
  E2006 替代/真实凭据的租户/角色与迁移目标固定用途不符
  E2007 迁移源当前未绑定在该角色上（或目标已绑定/已撤销）
  E2008 迁移目标处于被污染集合（已暴露的衍生凭据不可作为替代）
  E2009 执行步不在动作配置步区间内
  E2010 执行步不在替代凭据自身可用区间内
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .model import CandidateAction, CaseModel, Replacement, Service
from .propagate import PropagationResult, propagate


@dataclass(frozen=True)
class State:
    """某个中间状态。

    revoked:  已撤销的确切凭据代数 id
    bindings: service -> role -> 当前绑定（含已撤销项，活跃性另行判断）
    executed: 已执行动作 id（frozenset，作为求解器记忆化键）
    sequence: 到达该状态的动作 id 有序序列
    cost:     累计风险成本
    """

    revoked: frozenset[str]
    bindings: dict[str, dict[str, tuple[str, ...]]]
    executed: frozenset[str]
    sequence: tuple[str, ...]
    cost: int

    @property
    def step(self) -> int:
        """下一个动作将占据的步号（1 起）。"""
        return len(self.sequence) + 1


@dataclass(frozen=True)
class Blocker:
    code: str
    action_id: str
    reason: str
    detail: dict[str, Any]


@dataclass(frozen=True)
class AttemptResult:
    ok: bool
    state: State | None
    blocker: Blocker | None


@dataclass(frozen=True)
class Violation:
    code: str
    service_id: str
    reason: str
    detail: dict[str, Any]


class Engine:
    """封装案例、传播结果与初始状态。"""

    def __init__(self, case: CaseModel, propagation: PropagationResult | None = None):
        self.case = case
        self.propagation = propagation or propagate(case)
        self.tainted = self.propagation.tainted
        self.initial_state = self._initial_state()

    def _initial_state(self) -> State:
        bindings = {
            sid: {role: tuple(cids) for role, cids in svc.initial_bindings.items()}
            for sid, svc in self.case.services.items()
        }
        return State(frozenset(), bindings, frozenset(), (), 0)

    # ------------------------------------------------------------------
    # 合规检查
    # ------------------------------------------------------------------
    def active_bindings(self, state: State, service_id: str, role: str) -> list[str]:
        bound = state.bindings[service_id].get(role, ())
        return [cid for cid in bound if cid not in state.revoked]

    def custody_of(self, bound_id: str) -> str:
        """绑定项可能是真实凭据或替代凭据，分别在两个命名空间查保管域。"""
        if bound_id in self.case.replacements:
            return self.case.replacements[bound_id].custody_domain
        return self.case.cred(bound_id).custody_domain

    def violations(self, state: State) -> list[Violation]:
        """列出状态下全部业务连续性违规；空列表表示合规。"""
        out: list[Violation] = []
        for sid, svc in self.case.services.items():
            req_map = {r.role: r for r in svc.requirements}
            # 角色最低可用数
            for role, req in req_map.items():
                active = self.active_bindings(state, sid, role)
                if len(active) < req.min_active:
                    revoked_here = [
                        cid for cid in state.bindings[sid].get(role, ()) if cid in state.revoked
                    ]
                    out.append(Violation(
                        "E2004", sid,
                        f"服务 {sid} 角色 {role} 活跃 {len(active)} < 最低 {req.min_active}",
                        {"role": role, "active": active, "min_active": req.min_active,
                         "revoked_in_binding": revoked_here},
                    ))
            # 保管域隔离：同一服务的两个敏感角色不得共用保管域
            domain_roles: dict[str, set[str]] = {}
            for role, req in req_map.items():
                if not req.sensitive:
                    continue
                for cid in self.active_bindings(state, sid, role):
                    domain = self.custody_of(cid)
                    domain_roles.setdefault(domain, set()).add(role)
            for domain, roles in sorted(domain_roles.items()):
                if len(roles) > 1:
                    out.append(Violation(
                        "E2005", sid,
                        f"服务 {sid} 保管域 {domain} 被敏感角色 {sorted(roles)} 共用",
                        {"custody_domain": domain, "roles": sorted(roles)},
                    ))
        return out

    def is_compliant(self, state: State) -> bool:
        return not self.violations(state)

    # ------------------------------------------------------------------
    # 动作尝试
    # ------------------------------------------------------------------
    def attempt(self, state: State, action_id: str) -> AttemptResult:
        action = self.case.action(action_id)
        if action_id in state.executed:
            return AttemptResult(
                False, None,
                Blocker("E2001", action_id, f"动作 {action_id} 已执行，候选动作不可重复执行",
                        {"already_executed": True}),
            )
        if action.kind == "revoke":
            return self._attempt_revoke(state, action)
        return self._attempt_replace(state, action)

    def _attempt_revoke(self, state: State, action: CandidateAction) -> AttemptResult:
        target = action.target_credential_id
        assert target is not None
        if target in state.revoked:
            return AttemptResult(False, None, Blocker(
                "E2002", action.action_id,
                f"凭据代数 {target} 已被撤销，撤销仅使确切代数失效",
                {"target_credential_id": target},
            ))
        if target in self.tainted and state.step > self.case.deadline_step:
            return AttemptResult(False, None, Blocker(
                "E2003", action.action_id,
                f"受污染凭据 {target} 的撤销步 {state.step} 晚于截止步 {self.case.deadline_step}",
                {"target_credential_id": target, "step": state.step,
                 "deadline_step": self.case.deadline_step},
            ))
        new_revoked = set(state.revoked)
        new_revoked.add(target)
        new_state = State(
            frozenset(new_revoked),
            {sid: dict(roles) for sid, roles in state.bindings.items()},
            frozenset(state.executed | {action.action_id}),
            state.sequence + (action.action_id,),
            state.cost + action.risk_cost,
        )
        bad = self.violations(new_state)
        if bad:
            v = bad[0]
            return AttemptResult(False, None, Blocker(
                v.code, action.action_id, f"撤销 {target} 破坏连续性: {v.reason}", v.detail))
        return AttemptResult(True, new_state, None)

    def _attempt_replace(self, state: State, action: CandidateAction) -> AttemptResult:
        aid = action.action_id
        step = state.step
        svc = self.case.service(action.service_id)  # type: ignore[arg-type]

        # 配置步窗口
        if not (action.window_from_step <= step <= action.window_to_step):
            return AttemptResult(False, None, Blocker(
                "E2009", aid,
                f"执行步 {step} 不在动作配置步区间 "
                f"[{action.window_from_step}, {action.window_to_step}]",
                {"step": step, "window_from_step": action.window_from_step,
                 "window_to_step": action.window_to_step},
            ))

        # 逐条迁移做静态前置检查；任一失败则整个原子动作阻断（不产生部分迁移）
        for mig in action.migrations:
            blocker = self._check_migration(state, action, svc, step, mig)
            if blocker is not None:
                return AttemptResult(False, None, blocker)

        # 全部通过：原子换绑
        new_bindings = {sid: dict(roles) for sid, roles in state.bindings.items()}
        svc_bindings = dict(new_bindings[svc.service_id])
        for mig in action.migrations:
            current = list(svc_bindings.get(mig.role, ()))
            current.remove(mig.from_credential_id)
            current.append(mig.to_credential_id)
            svc_bindings[mig.role] = tuple(current)
        new_bindings[svc.service_id] = svc_bindings
        new_state = State(
            state.revoked,
            new_bindings,
            frozenset(state.executed | {aid}),
            state.sequence + (aid,),
            state.cost + action.risk_cost,
        )
        # 迁移后再做整服务合规复核（最低数 + 保管域）
        bad = self.violations(new_state)
        if bad:
            v = bad[0]
            return AttemptResult(False, None, Blocker(
                v.code, aid, f"换绑破坏连续性: {v.reason}", v.detail))
        return AttemptResult(True, new_state, None)

    def _check_migration(
        self,
        state: State,
        action: CandidateAction,
        svc: Service,
        step: int,
        mig: Any,
    ) -> Blocker | None:
        aid = action.action_id
        req_roles = {r.role for r in svc.requirements}
        if mig.role not in req_roles:
            return Blocker("E2006", aid,
                           f"服务 {svc.service_id} 未声明角色 {mig.role}（用途固定）",
                           {"role": mig.role})
        current = state.bindings[svc.service_id].get(mig.role, ())
        if mig.from_credential_id not in current:
            return Blocker(
                "E2007", aid,
                f"迁移源 {mig.from_credential_id} 当前未绑定在服务 {svc.service_id} 角色 {mig.role}",
                {"role": mig.role, "from_credential_id": mig.from_credential_id,
                 "current_binding": list(current)},
            )
        if mig.to_credential_id in current:
            return Blocker(
                "E2007", aid,
                f"迁移目标 {mig.to_credential_id} 已绑定在角色 {mig.role}，迁移为空操作",
                {"role": mig.role, "to_credential_id": mig.to_credential_id},
            )
        if mig.to_credential_id in self.tainted:
            return Blocker(
                "E2008", aid,
                f"迁移目标 {mig.to_credential_id} 处于暴露传播集合，"
                "已暴露的衍生凭据不可作为替代",
                {"to_credential_id": mig.to_credential_id,
                 "propagation_path": list(self.propagation.paths.get(mig.to_credential_id, ()))},
            )
        repl = self.case.replacements.get(mig.to_credential_id)
        if repl is None:
            # 目标为真实凭据代数：固定用途按真实凭据校验，且不能已撤销
            real = self.case.credentials.get(mig.to_credential_id)
            if real is None:
                return Blocker("E2006", aid,
                               f"{mig.to_credential_id} 既非替代凭据也非真实凭据代数",
                               {"to_credential_id": mig.to_credential_id})
            if mig.to_credential_id in state.revoked:
                return Blocker(
                    "E2007", aid,
                    f"真实凭据代数 {mig.to_credential_id} 已撤销，不能再绑定",
                    {"to_credential_id": mig.to_credential_id},
                )
            if real.tenant != svc.tenant or real.role != mig.role:
                return Blocker(
                    "E2006", aid,
                    f"真实凭据 {real.credential_id} 固定用途 "
                    f"{real.tenant}/{real.role} 与目标 {svc.tenant}/{mig.role} 不符",
                    {"credential_tenant": real.tenant, "service_tenant": svc.tenant,
                     "credential_role": real.role, "target_role": mig.role},
                )
            return None
        # 固定用途：租户与角色必须与服务/迁移角色一致
        if repl.tenant != svc.tenant or repl.role != mig.role:
            return Blocker(
                "E2006", aid,
                f"替代凭据 {repl.replacement_id} 固定用途 "
                f"{repl.tenant}/{repl.role} 与目标 {svc.tenant}/{mig.role} 不符",
                {"replacement_tenant": repl.tenant, "service_tenant": svc.tenant,
                 "replacement_role": repl.role, "target_role": mig.role},
            )
        # 替代凭据自身可用区间
        if not (repl.available_from_step <= step <= repl.available_to_step):
            return Blocker(
                "E2010", aid,
                f"替代凭据 {repl.replacement_id} 在步 {step} 不可用，其可用区间 "
                f"[{repl.available_from_step}, {repl.available_to_step}]",
                {"step": step, "replacement_id": repl.replacement_id,
                 "available_from_step": repl.available_from_step,
                 "available_to_step": repl.available_to_step},
            )
        # 迁移后保管域预判（与迁移后整服务复核互为双保险，这里给出针对单迁移的证据）
        domain_conflict = self._custody_preview(state, svc, mig, repl)
        if domain_conflict is not None:
            return Blocker("E2005", aid, domain_conflict[0], domain_conflict[1])
        return None

    def _custody_preview(
        self, state: State, svc: Service, mig: Any, repl: Replacement | None
    ) -> tuple[str, dict[str, Any]] | None:
        """预览换绑后敏感角色保管域是否冲突。"""
        sensitive = {r.role for r in svc.requirements if r.sensitive}
        if mig.role not in sensitive:
            return None
        # 预览该角色换绑后的保管域集合
        preview_roles = list(state.bindings[svc.service_id].get(mig.role, ()))
        preview_roles.remove(mig.from_credential_id)
        preview_roles.append(mig.to_credential_id)
        domain_roles: dict[str, set[str]] = {}
        for role in sensitive:
            cids = preview_roles if role == mig.role else state.bindings[svc.service_id].get(role, ())
            for cid in cids:
                if cid in state.revoked:
                    continue
                if cid == mig.to_credential_id:
                    if repl is not None:
                        domain = repl.custody_domain
                    else:
                        domain = self.case.cred(cid).custody_domain
                else:
                    domain = self.custody_of(cid)
                domain_roles.setdefault(domain, set()).add(role)
        for domain, roles in sorted(domain_roles.items()):
            if len(roles) > 1:
                return (
                    f"换绑将使保管域 {domain} 被敏感角色 {sorted(roles)} 共用",
                    {"custody_domain": domain, "roles": sorted(roles),
                     "role": mig.role, "to_credential_id": mig.to_credential_id},
                )
        return None

    # ------------------------------------------------------------------
    # 状态快照（报告用）
    # ------------------------------------------------------------------
    def snapshot(self, state: State) -> dict[str, Any]:
        services_out: dict[str, Any] = {}
        for sid, svc in self.case.services.items():
            roles_out: dict[str, Any] = {}
            for req in svc.requirements:
                bound = list(state.bindings[sid].get(req.role, ()))
                active = [cid for cid in bound if cid not in state.revoked]
                roles_out[req.role] = {
                    "active_bindings": active,
                    "revoked_bindings": [cid for cid in bound if cid in state.revoked],
                    "min_active": req.min_active,
                    "sensitive": req.sensitive,
                    "satisfied": len(active) >= req.min_active,
                }
            bad_here = [v for v in self.violations(state) if v.service_id == sid]
            services_out[sid] = {
                "tenant": svc.tenant,
                "roles": roles_out,
                "custody_isolation_ok": not any(v.code == "E2005" for v in bad_here),
            }
        return {
            "step": state.step - 1,  # 已完成的动作数
            "revoked": sorted(state.revoked),
            "services": services_out,
            "violations": [
                {"code": v.code, "service_id": v.service_id, "reason": v.reason, "detail": v.detail}
                for v in self.violations(state)
            ],
        }
