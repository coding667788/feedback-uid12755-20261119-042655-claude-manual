"""泄露凭据轮换计划验证器（纯离线、纯标准库）。

模块划分：
- model      输入数据的不可变数据模型
- loader     JSON 载入与输入校验（错误码 E10xx）
- propagate  沿有向衍生边的暴露风险传播
- engine     中间状态、动作可行性、合规检查（阻断码 E20xx）
- solver     子集记忆化穷举求解，无解时给出覆盖最高的可达状态
- bruteforce 独立排列穷举，用于交叉核对 solver
- report     结果 JSON 组装与逐步回放
"""

__version__ = "1.0.0"
