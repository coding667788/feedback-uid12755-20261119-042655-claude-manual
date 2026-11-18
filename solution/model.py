"""输入数据的不可变数据模型。

全部为合成数据。凭据身份由 ``credential_id`` 唯一确定；不同租户允许
出现相同的凭据名（display_name 相同但 id 不同），id 才是代数与撤销
操作的作用对象。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Credential:
    """一项真实凭据代数。"""

    credential_id: str
    display_name: str
    tenant: str
    role: str               # 凭据用途固定到的角色
    custody_domain: str     # 独立保管域
    generation: str         # 代数标识，撤销仅使确切代数失效
    risk_weight: int        # 该代数被撤销时贡献的风险覆盖权重
    exposed: bool = False   # 是否存在明确暴露记录


@dataclass(frozen=True)
class DerivationEdge:
    """有向衍生边 parent -> child。

    inherit_risk=True 时，父代数被暴露的风险沿该边传播给子代；
    为 False 时该边阻断传播（子代仍可被自身暴露记录标记）。
    """

    parent_id: str
    child_id: str
    inherit_risk: bool


@dataclass(frozen=True)
class Replacement:
    """可用替代凭据（初始未绑定到任何服务）。"""

    replacement_id: str
    display_name: str
    tenant: str
    role: str
    custody_domain: str
    available_from_step: int   # 替代凭据自身可用区间（含端点）
    available_to_step: int


@dataclass(frozen=True)
class RoleRequirement:
    """服务内某角色的最低可用凭据数与敏感标记。"""

    role: str
    min_active: int
    sensitive: bool


@dataclass(frozen=True)
class Service:
    """服务使用清单条目：租户、角色要求与初始绑定。"""

    service_id: str
    tenant: str
    requirements: tuple[RoleRequirement, ...]
    initial_bindings: dict[str, tuple[str, ...]]  # role -> credential_id 元组


@dataclass(frozen=True)
class Migration:
    """替换动作内的单条原子迁移：某角色的 from_cred -> to_cred。"""

    role: str
    from_credential_id: str
    to_credential_id: str


@dataclass(frozen=True)
class CandidateAction:
    """候选动作。

    kind == "revoke":  撤销 target_credential_id 的确切代数。
    kind == "replace": 在 service_id 上原子执行 migrations 中的全部换绑，
                       只能在配置步区间 [window_from_step, window_to_step]
                       （含端点）内执行。
    """

    action_id: str
    kind: str
    risk_cost: int
    window_from_step: int | None = None
    window_to_step: int | None = None
    target_credential_id: str | None = None
    service_id: str | None = None
    migrations: tuple[Migration, ...] = ()


@dataclass
class CaseModel:
    """单个合成案例的完整模型（附带索引便于查询）。"""

    case_id: str
    description: str
    deadline_step: int
    credentials: dict[str, Credential]
    edges: tuple[DerivationEdge, ...]
    replacements: dict[str, Replacement]
    services: dict[str, Service]
    actions: dict[str, CandidateAction]
    action_order: tuple[str, ...]
    exposure_records: tuple[str, ...] = field(default_factory=tuple)

    def cred(self, credential_id: str) -> Credential:
        return self.credentials[credential_id]

    def action(self, action_id: str) -> CandidateAction:
        return self.actions[action_id]

    def service(self, service_id: str) -> Service:
        return self.services[service_id]


class InputError(ValueError):
    """输入校验失败，携带稳定错误码（见 README 错误码表）。"""

    def __init__(self, code: str, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
