"""CodeSentry 统一分析引擎。

整合三大自研分析能力：
  1. 规则引擎（RuleEngine）— 基于 AST 的模式检测
  2. 污点分析（TaintAnalyzer）— 数据流追踪
  3. 控制流分析（CFGAnalyzer）— 不可达代码 + 异常缺陷

v2: 改进评分算法（对数衰减），移除 raw_code 冗余字段。
"""

import ast
import math

from .models import Issue, ScanResult, Severity
from .rules import RuleEngine
from .taint import TaintAnalyzer
from .cfg import CFGAnalyzer


def analyze_code(code: str, filename: str = "<input>") -> ScanResult:
    """运行全部自研分析引擎，返回综合结果。"""
    result = ScanResult(filename=filename)

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        result.issues.append(Issue(
            file=filename, line=e.lineno or 0,
            severity=Severity.HIGH, category="syntax",
            message=f"语法错误: {e.msg}",
            source="parser",
        ))
        result.maintainability_score = 0.0
        return result

    # ===== 引擎 1: 规则检测 =====
    rule_engine = RuleEngine()
    rule_issues = rule_engine.analyze(code, tree, filename)
    result.issues.extend(rule_issues)
    if rule_issues:
        result.scanners_used.append("rule_engine")

    # ===== 引擎 2: 污点分析 =====
    taint = TaintAnalyzer()
    taint_paths = taint.analyze(tree)
    for path in taint_paths:
        result.issues.append(Issue(
            file=filename,
            line=path.sink_line,
            severity=Severity.HIGH,
            category="taint",
            message=(
                f"[污点分析] {path.sink_desc}\n"
                f"  数据来源: {path.source_desc} (行{path.source_line})\n"
                f"  危险汇聚: 行{path.sink_line}\n"
                f"  置信度: {path.confidence:.0%}"
            ),
            source="taint_engine",
            rule_id="taint-flow",
        ))
    if taint_paths:
        result.scanners_used.append("taint_engine")

    # ===== 引擎 3: 控制流分析 =====
    cfg = CFGAnalyzer()
    cfg_result = cfg.analyze(tree)

    for line in cfg_result.unreachable_lines:
        result.issues.append(Issue(
            file=filename, line=line,
            severity=Severity.MEDIUM, category="dead_code",
            message="不可达代码（前面的 return/raise 使得此行永远不会执行）",
            source="cfg_engine",
            rule_id="unreachable",
        ))

    for warn in cfg_result.warnings:
        result.issues.append(Issue(
            file=filename, line=warn["line"],
            severity=Severity(warn["severity"]),
            category=warn["type"],
            message=warn["message"],
            source="cfg_engine",
            rule_id=warn["type"],
        ))

    if cfg_result.unreachable_lines or cfg_result.warnings:
        result.scanners_used.append("cfg_engine")

    # ===== 去重 + 评分 =====
    result.deduplicate()
    result.maintainability_score = _calc_score(result)
    return result


def _calc_score(result: ScanResult) -> float:
    """基于风险的对数衰减评分。

    扣分递减：同类问题越多，每个新问题的边际扣分越小。
    这样 10 个 HIGH 和 200 个 HIGH 的分数有明显区分。
    """
    score = 100.0

    # 按严重度分组计数
    severity_weights = {Severity.HIGH: 15, Severity.MEDIUM: 5, Severity.LOW: 2}
    counts = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}

    for issue in result.issues:
        counts[issue.severity] += 1

    # 对数衰减扣分
    for sev, weight in severity_weights.items():
        n = counts[sev]
        if n > 0:
            # 前 3 个全扣，之后递减
            total_deduction = 0
            for i in range(n):
                factor = 1.0 / (1.0 + max(0, i - 2) * 0.15)
                total_deduction += weight * factor
            score -= total_deduction

    return max(0.0, min(100.0, score))
