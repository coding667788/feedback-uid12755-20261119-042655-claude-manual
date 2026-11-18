"""命令行入口：python -m solution --input cases.json --output result.json

退出码：
  0  成功（包含求解结论为 INFEASIBLE 的情况——无解是有效结论而非运行错误）
  2  参数/用法错误（argparse）
  3  输入校验错误（载荷 error.code 为 E10xx，详见 README）
  5  文件读取 E5001 / 写入 E5002 错误
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .loader import InputError
from .report import run_case


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="泄露凭据撤销/替换轮换计划的离线验证器（不连接任何服务）",
    )
    parser.add_argument("--input", required=True, help="合成案例 JSON 路径（单个案例或 cases 数组）")
    parser.add_argument("--output", required=True, help="结果 JSON 写出路径")
    return parser


def _load_document(text: str) -> list[dict[str, Any]]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError("E1001", f"JSON 解析失败: {exc.msg} (line {exc.lineno}, col {exc.colno})")
    if isinstance(doc, dict) and "cases" in doc:
        cases = doc["cases"]
    elif isinstance(doc, list):
        cases = doc
    elif isinstance(doc, dict):
        cases = [doc]
    else:
        raise InputError("E1001", "顶层必须为案例对象、案例数组，或含 cases 数组的对象")
    if not isinstance(cases, list) or not cases:
        raise InputError("E1001", "cases 必须为非空数组")
    for item in cases:
        if not isinstance(item, dict):
            raise InputError("E1001", "cases 中每个元素必须为对象")
    return cases


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print(json.dumps({"error": {"code": "E5001", "message": f"无法读取输入文件: {exc}"}},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 5

    try:
        cases = _load_document(text)
        reports = [run_case(raw) for raw in cases]
    except InputError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": exc.message}},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 3

    payload: dict[str, Any] = {
        "tool": "leaked-credential-rotation-validator",
        "offline": True,
        "case_count": len(reports),
        "results": [
            {k: v for k, v in report.items()}
            for report in reports
        ],
    }
    try:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    except OSError as exc:
        print(json.dumps({"error": {"code": "E5002", "message": f"无法写出结果文件: {exc}"}},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 5

    for report in reports:
        print(f"[{report['case_id']}] {report['status']} "
              f"cost={report['objective']['optimal_total_risk_cost']} "
              f"len={report['objective']['sequence_length']} "
              f"seq={report['objective']['action_id_sequence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
