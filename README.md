# 泄露凭据轮换计划验证器（离线 / 纯标准库）

面向本地安全响应的**合成**凭据轮换计划验证器。它不连接任何服务、不读取任何真实
凭据，只对给定的合成输入计算“撤销 + 替换”的完整动作序列及其证据，**不执行任何
实际改动**。

- 运行环境：Windows 原生 Python 3.12（开发实测 3.12.8），仅标准库，CPU 离线。
- 规模约束：最多 12 个服务、18 项候选动作。
- 交付物：`solution/` 源码、`tests/` 自动化测试、`cases.json` 可重放合成案例、
  本 README、运行产物 `result.json`。

---

## 1. 业务规则（题目约束的形式化）

### 1.1 凭据身份与固定用途

- 身份由 `credential_id` 唯一确定。不同租户允许出现相同的凭据名
  （`display_name` 相同但 id 不同），**风险传播与撤销只作用于匹配 id 的代数**。
- 每项真实凭据代数固定到 `(tenant, role)`，只能绑定到同租户、同角色的服务角色；
  撤销操作仅使**确切代数**失效，不影响同名其他代数。
- 多服务可以共用同一项凭据（同一 id 出现在多个服务的绑定中）。

### 1.2 暴露风险的有向传播

- 明确暴露记录中的凭据直接进入受污染（tainted）集合。
- 传播严格沿衍生边方向 `parent -> child`，**不反向、不在兄弟节点间跳转**。
- 边上 `inherit_risk=false` 时传播在该边处**阻断**；被阻断的边会作为证据输出。
- 每个受污染凭据给出一条最短传播路径。

### 1.3 两类候选动作

| kind | 语义 | 关键约束 |
|---|---|---|
| `revoke` | 撤销 `target_credential_id` 的确切代数，全局生效（影响所有共用服务） | 受污染凭据必须在 `deadline_step`（含）之前撤销，否则阻断 `E2003` |
| `replace` | 在一个服务上**原子**迁移若干角色绑定（全成功或全不发生） | 执行步必须落在动作配置步区间 `[window_from_step, window_to_step]`（含端点） |

替代凭据还有自己的可用区间 `[available_from_step, available_to_step]`，执行步必须
落在其中（`E2010`）。已暴露的衍生凭据（处于受污染集合）**不可作为替代**（`E2008`）。

### 1.4 任意中间状态必须满足的连续性约束

1. **最低可用数**：每个服务的每个角色，活跃绑定（未撤销）数量 `>= min_active`，
   否则 `E2004`。
2. **独立保管域隔离**：同一服务的任意两个*敏感*角色，活跃绑定不得落在同一
   `custody_domain`，否则 `E2005`。
3. 初始状态在加载时即校验，不合规输入以 `E1006` 拒绝。

### 1.5 优化目标与定序

完整序列要求：所有受污染的真实凭据代数在截止步前撤销，且每一步（含初始态与
终态）都满足 1.4 的全部约束。

在所有完整序列中按以下目标序取最优（后者仅用于平局）：

1. 总风险成本 `sum(risk_cost)` 最小；
2. 序列长度最短；
3. 动作 ID 序列字典序最小（**按 ID 排序，与输入数组排列无关**）。

无解时，在全部可达状态中按
`(撤销风险覆盖权重, 剩余缺口, 成本, 长度, ID 序列)` 选出**撤销风险覆盖最高的可达
状态**，并枚举该状态下每个未执行动作的下一步阻断证据（可执行但无法延伸到目标的
动作标记为 `OK` 并附说明）。

---

## 2. 目录结构

```
.
├── solution/
│   ├── __init__.py
│   ├── __main__.py      # CLI：python -m solution
│   ├── model.py         # 不可变数据模型 + InputError
│   ├── loader.py        # JSON 载入与静态校验（E10xx）
│   ├── propagate.py     # 有向风险传播（BFS，阻断边证据）
│   ├── engine.py        # 状态机、动作可行性、连续性违规（E20xx）
│   ├── solver.py        # 子集记忆化 + 分支定界求解
│   ├── bruteforce.py    # 独立排列穷举（交叉核对，不做记忆化/剪枝）
│   └── report.py        # 逐步回放与结果 JSON 组装
├── tests/
│   ├── case_loading.py
│   ├── test_propagation.py
│   ├── test_cases.py
│   ├── test_atomic.py
│   ├── test_reorder_stability.py
│   ├── test_validation.py
│   └── test_cli.py
├── cases.json           # 7 个可重放合成案例
├── result.json          # 一次运行的完整产物
└── README.md
```

求解器以“已执行动作集合”为记忆化键（状态结果只取决于该集合），配合成本分支定界；
穷举器则用完全不同的 O(n!) 排列递归、无记忆化、无剪枝，两者在每个案例上交叉核对
最优序列、成本与覆盖。

---

## 3. 输入格式（cases.json）

顶层为 `{"cases": [ ... ]}`（也接受裸数组或单个案例对象）。单个案例字段：

- `case_id`, `description`, `deadline_step`
- `credentials[]`：`credential_id, display_name, tenant, role, custody_domain,
  generation, risk_weight`
- `derivation_edges[]`：`parent_id, child_id, inherit_risk`
- `exposure_records[]`：`credential_id`（+ 任意说明字段）
- `replacements[]`：`replacement_id, display_name, tenant, role, custody_domain,
  available_from_step, available_to_step`
- `services[]`：`service_id, tenant, role_requirements[]（role, min_active,
  sensitive）, initial_bindings{role: [credential_id, ...]}`
- `candidate_actions[]`：
  - 撤销：`{action_id, kind:"revoke", risk_cost, target_credential_id}`
  - 替换：`{action_id, kind:"replace", risk_cost, service_id, window_from_step,
    window_to_step, migrations:[{role, from_credential_id, to_credential_id}, ...]}`

迁移目标通常是替代凭据 id；也允许是另一项**未受污染、未撤销且租户/角色匹配**的
真实凭据代数（用于构造“试图换绑到已暴露衍生凭据”的 `E2008` 场景）。

---

## 4. 输出格式（result.json）

`results[]` 中每个案例包含：

- `status`：`FEASIBLE` / `INFEASIBLE`（无解是有效结论，CLI 仍返回 0）
- `objective`：最优总成本、序列长度、动作 ID 序列及定序规则说明
- `risk_propagation`：显式暴露集、受污染集、每个凭据的传播路径、衍生边及阻断边
- `steps[]`：步 0 初始态 + 每步的动作、累计成本、窗口/截止步检查，以及该步的
  **活跃服务绑定快照**（各角色活跃/已撤销绑定、最低数是否满足、保管域是否隔离）
- `final_coverage_check`：逐受污染凭据的撤销覆盖（权重、传播路径）与终态违规列表
- `search_stats`：可达状态数、尝试转移数、记忆化集合数
- 无解时额外给出 `infeasibility_evidence`：覆盖最高的可达状态快照、覆盖权重/缺口、
  每个未执行动作的 `next_step_blockers`（错误码 + 原因 + 结构化 detail）

输出不含时间戳与环境信息，同一输入逐字节可重放。

---

## 5. 错误码

### 5.1 输入校验错误（CLI 退出码 3，`error.code`）

| 码 | 含义 |
|---|---|
| E1001 | 顶层结构/字段缺失或类型错误、JSON 解析失败 |
| E1002 | 凭据/替代/服务/动作 id 重复，或替代 id 与真实凭据冲突 |
| E1003 | 引用了不存在的凭据、替代凭据、服务 |
| E1004 | 衍生关系自环或成环（必须为 DAG） |
| E1005 | 数值非法：负权重/成本、倒置的步区间、截止步 < 1 |
| E1006 | 初始绑定不合规：租户/角色固定用途不符、重复绑定、敏感角色保管域冲突、最低数不足 |
| E1007 | 规模超限：服务 > 12 或候选动作 > 18 |
| E1008 | 候选动作结构非法：未知 kind、空 migrations、同角色多条迁移、源目标相同 |

### 5.2 运行期阻断码（写在结果 JSON 的证据中，不是进程错误）

| 码 | 含义 |
|---|---|
| E2001 | 动作已执行，候选动作不可重复执行 |
| E2002 | 撤销目标代数已被撤销 |
| E2003 | 受污染凭据的撤销步晚于截止步 |
| E2004 | 撤销/换绑后某角色活跃凭据数低于最低要求 |
| E2005 | 换绑后同一服务两个敏感角色落到同一保管域 |
| E2006 | 凭据/替代凭据的租户或角色与目标固定用途不符（含跨租户同名） |
| E2007 | 迁移源未绑定在该角色、目标已绑定（空操作）或目标代数已撤销 |
| E2008 | 迁移目标处于受污染集合（已暴露衍生凭据不可作为替代） |
| E2009 | 执行步不在替换动作的配置步区间内 |
| E2010 | 执行步不在替代凭据自身的可用区间内 |

### 5.3 进程退出码

| 退出码 | 含义 |
|---|---|
| 0 | 成功，包括求解结论为 `INFEASIBLE` |
| 2 | 命令行参数/用法错误（argparse） |
| 3 | 输入校验错误（E10xx） |
| 5 | 文件读取 E5001 / 写入 E5002 失败 |

---

## 6. 使用方法

```bash
# 求解并写出完整证据
python -m solution --input cases.json --output result.json

# 自动化测试（53 个用例）
python -m unittest discover -s tests -v
```

---

## 7. 合成案例与实测结果

环境：Windows 11 Pro + Python 3.12.8，纯标准库，离线 CPU。
实测命令与输出：

```
$ python -m solution --input cases.json --output result.json
[C01-basic-feasible-multi-service]            FEASIBLE   cost=18 len=4 seq=['A01','A02','A03','A04']
[C02-revoke-alone-ok-combo-fails]             INFEASIBLE cost=6  len=2 seq=['B02','B03']
[C03-tainted-derived-replacement-forbidden]   FEASIBLE   cost=19 len=3 seq=['C02','C03','C04']
[C04-non-greedy-cross-service-rebind]         FEASIBLE   cost=13 len=3 seq=['D01','D02','D04']
[C05-same-name-cross-tenant]                  FEASIBLE   cost=10 len=2 seq=['E01','E04']
[C06-custody-domain-isolation]                FEASIBLE   cost=11 len=2 seq=['F02','F03']
[C07-deadline-and-window-blocked]             INFEASIBLE cost=0  len=0 seq=[]

$ python -m unittest discover -s tests
Ran 53 tests in 0.6s — OK
```

| 案例 | 覆盖的题目要点 | 结论与关键证据 |
|---|---|---|
| C01 | 多服务共用、可继承/阻断衍生边、先换绑后撤销 | 可行，成本 18 / 4 步；`k-billing` 被 `inherit_risk=false` 阻断不受污染 |
| C02 | **撤销单独可行却无法组合** | 无解；B01/B02/B03 单独执行均合规，组合撤销 `k-shared` 撞 E2004；最佳覆盖 12/22，缺口 10 |
| C03 | **已暴露衍生凭据不可作为替代** | 换绑到 `k-derived` 撞 E2008（附传播路径）；干净替代路径可行，成本 19 |
| C04 | **非贪心的跨服务换绑** | 贪心第 1 步选廉价 D03 后分别撞 E2009/E2007/E2004 死锁；最优须先做较贵的 D01，成本 13 |
| C05 | **跨租户同凭据名** | 同名 `deploy-token` 仅 eu 侧受污染；跨租户替代 E03 撞 E2006；撤销只影响 `k-eu` |
| C06 | 独立保管域隔离 | 换到 DOM-2 的 F01 撞 E2005；合规路径成本 11，每步快照隔离均为 ok |
| C07 | 截止步 + 双层窗口阻断 | 无解，覆盖 0；G01=E2009、G03=E2010、G02=E2004，逾期撤销另由 E2003 覆盖测试 |

测试同时断言：独立排列穷举与求解器在**每个**案例上的可行性、成本、序列、覆盖完全
一致；对凭据/边/暴露/替代/服务/动作六个数组做多种确定性洗牌后，最优结论与 ID 序列
保持不变（输入换序稳定）；报告两次运行逐字节一致。

---

## 8. 安全性说明

- 全程零网络调用、零子进程外联（测试中的 subprocess 仅在本机再次调用本模块）。
- 不读取任何真实凭据，所有数据均为 `cases.json` 中的合成字符串。
- 工具只产出计划与证据，不提供也不执行任何撤销/换绑的实际副作用。
