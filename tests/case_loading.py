"""测试辅助：从仓库根的 cases.json 载入合成案例。

同时兼容 ``python -m unittest discover -s tests``（顶层模块导入）与
``python -m unittest tests.test_xxx``（包内相对导入）两种运行方式。
"""

from __future__ import annotations

import json
import os
import sys

# 以顶层模块方式运行时，把仓库根加入 sys.path 以便 import solution
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from solution.loader import load_case  # noqa: E402
from solution.model import CaseModel  # noqa: E402

CASES_PATH = os.path.join(_ROOT, "cases.json")


def load_raw_cases() -> list[dict]:
    with open(CASES_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def load_all_cases() -> dict[str, CaseModel]:
    return {raw["case_id"]: load_case(raw) for raw in load_raw_cases()}


def get_case(prefix: str) -> CaseModel:
    for raw in load_raw_cases():
        if raw["case_id"].startswith(prefix):
            return load_case(raw)
    raise KeyError(prefix)


def get_raw(prefix: str) -> dict:
    for raw in load_raw_cases():
        if raw["case_id"].startswith(prefix):
            return raw
    raise KeyError(prefix)
