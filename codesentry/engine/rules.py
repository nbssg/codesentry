"""自定义规则引擎（Rule Engine）。

改进 v3:
  - 合并 11 次 ast.walk 为单次遍历（UnifiedRuleVisitor）
  - 修复 _calc_nesting 未递归 orelse/handlers/finalbody
  - 修复 _detect_weak_hash 遗漏 `from hashlib import md5` 模式
  - 修复 _detect_hardcoded_network 未校验 IP 八位组 0-255 及版本号误报
  - 移除 S004 裸except（由 CFG 引擎专门处理，更深入）
  - 使用公共 get_call_name()
"""

import ast
import re
from dataclasses import dataclass

from .models import Issue, Severity
from .utils import get_call_name


@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    description: str
    category: str
    detector: str


BUILTIN_RULES = [
    Rule("S001", "硬编码密码", Severity.HIGH, "密码/密钥直接赋值给变量", "security", "hardcoded_secret"),
    Rule("S002", "eval()使用", Severity.HIGH, "使用eval()执行动态代码", "security", "eval_usage"),
    Rule("S003", "exec()使用", Severity.HIGH, "使用exec()执行动态代码", "security", "exec_usage"),
    # S004 已移除：裸except由CFG引擎检测（更精确）
    Rule("S005", "弱哈希算法", Severity.MEDIUM, "使用MD5/SHA1等不安全哈希", "security", "weak_hash"),
    Rule("S006", "随机数用于安全场景", Severity.LOW, "使用random模块生成安全相关数值", "security", "weak_random"),
    Rule("S007", "未使用with打开文件", Severity.LOW, "手动open未使用with语句管理", "quality", "file_no_context"),
    Rule("S008", "过长函数", Severity.MEDIUM, "函数超过50行，建议拆分", "quality", "long_function"),
    Rule("S009", "过深嵌套", Severity.MEDIUM, "if嵌套超过4层", "quality", "deep_nesting"),
    Rule("S010", "全局可变状态", Severity.LOW, "模块级别定义可变对象", "quality", "global_mutable"),
    Rule("S011", "assert用于数据验证", Severity.LOW, "assert在-O模式下会被跳过", "security", "assert_validation"),
    Rule("S012", "硬编码IP/端口", Severity.LOW, "IP地址或端口号直接写在代码中", "quality", "hardcoded_network"),
]

IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
SECRET_KEYWORDS = ("password", "secret", "token", "api_key", "apikey", "access_key", "private_key")
EXCLUDE_IPS = {"127.0.0.1", "0.0.0.0", "localhost"}
_VERSION_LIKE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
_WEAK_RANDOM_FUNCS = frozenset({
    "random.randint", "random.random", "random.choice", "random.randrange",
})
_WEAK_HASH_ALGOS = frozenset({"hashlib.md5", "hashlib.sha1"})
_WEAK_HASH_BARE = frozenset({"md5", "sha1"})

# detector name -> (rule_id, category) 预计算映射
_DETECTOR_META = {r.detector: (r.id, r.category) for r in BUILTIN_RULES}


class UnifiedRuleVisitor(ast.NodeVisitor):
    """单次遍历完成所有规则检测的 AST 访问器。"""

    def __init__(self, filename):
        self.filename = filename
        self.issues = []  # type: list[Issue]
        self.with_lines = set()
        self.module_level_lines = set()

    # ---------- 公共辅助 ----------

    def _add(self, line, severity, category, message, detector):
        """创建 Issue 并自动填充 rule_id / category。"""
        rule_id, cat = _DETECTOR_META.get(detector, ("", category))
        self.issues.append(Issue(
            file=self.filename, line=line,
            severity=severity, category=cat,
            message=message, source="rule_engine",
            rule_id=rule_id,
        ))

    # ---------- visit_* 分发入口 ----------

    def visit_Assign(self, node):
        self._check_hardcoded_secret(node)
        self._check_file_no_context(node)
        self._check_global_mutable(node)
        self.generic_visit(node)

    def visit_Call(self, node):
        self._check_dangerous_call(node)
        self._check_weak_hash(node)
        self._check_weak_random(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._check_long_function(node)
        self._check_deep_nesting(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_With(self, node):
        # 收集此 With 块内所有后代的行号（供 file_no_context 使用）
        for child in ast.walk(node):
            if child is not node and hasattr(child, "lineno"):
                self.with_lines.add(child.lineno)
        self.generic_visit(node)

    def visit_Constant(self, node):
        self._check_hardcoded_network(node)
        self.generic_visit(node)

    def visit_Assert(self, node):
        self._add(
            node.lineno, Severity.LOW, "security",
            "assert 在 python -O 模式下会被跳过，不应用于数据验证",
            "assert_validation",
        )
        self.generic_visit(node)

    # ---------- 各检测器 ----------

    def _check_hardcoded_secret(self, node):
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if any(kw in target.id.lower() for kw in SECRET_KEYWORDS):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    if val and val not in ("", '""', "''", "xxx", "your-key"):
                        self._add(
                            node.lineno, Severity.HIGH, "security",
                            f"变量 '{target.id}' 硬编码了敏感信息，应从环境变量读取",
                            "hardcoded_secret",
                        )

    def _check_dangerous_call(self, node):
        name = get_call_name(node)
        if name == "eval":
            self._add(
                node.lineno, Severity.HIGH, "security",
                "使用了 eval()，存在代码注入风险，应替换为安全方案",
                "eval_usage",
            )
        elif name == "exec":
            self._add(
                node.lineno, Severity.HIGH, "security",
                "使用了 exec()，存在代码注入风险，应替换为安全方案",
                "exec_usage",
            )

    def _check_weak_hash(self, node):
        name = get_call_name(node)
        algo = None
        if name in _WEAK_HASH_ALGOS:
            algo = name.split(".")[-1]
        elif isinstance(node.func, ast.Name) and node.func.id in _WEAK_HASH_BARE:
            algo = node.func.id
        if algo is not None:
            self._add(
                node.lineno, Severity.MEDIUM, "security",
                f"使用了弱哈希算法 {algo}，建议使用 SHA-256 或更强算法",
                "weak_hash",
            )

    def _check_weak_random(self, node):
        name = get_call_name(node)
        if name in _WEAK_RANDOM_FUNCS:
            self._add(
                node.lineno, Severity.LOW, "security",
                f"使用了 {name}（伪随机），安全场景应使用 secrets 模块",
                "weak_random",
            )

    def _check_file_no_context(self, node):
        """检测 open() 赋值给变量且不在 with 块内的情况。"""
        if isinstance(node.value, ast.Call) and get_call_name(node.value) == "open":
            if node.lineno not in self.with_lines:
                self._add(
                    node.lineno, Severity.LOW, "quality",
                    "使用 open() 赋值给变量且不在 with 块中，建议使用 with 语句确保文件关闭",
                    "file_no_context",
                )

    def _check_long_function(self, node):
        if hasattr(node, "end_lineno") and node.end_lineno:
            length = node.end_lineno - node.lineno
            if length > 50:
                self._add(
                    node.lineno, Severity.MEDIUM, "quality",
                    f"函数 {node.name} 共 {length} 行，超过50行建议拆分",
                    "long_function",
                )

    def _check_deep_nesting(self, node):
        depth = self._calc_nesting(node.body, 0)
        if depth > 4:
            self._add(
                node.lineno, Severity.MEDIUM, "quality",
                f"函数 {node.name} 最大嵌套深度 {depth} 层，建议降低到4层以下",
                "deep_nesting",
            )

    def _check_global_mutable(self, node):
        if node.lineno in self.module_level_lines:
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, (ast.List, ast.Dict, ast.Set)):
                    self._add(
                        node.lineno, Severity.LOW, "quality",
                        f"模块级可变对象 '{target.id}' 可能被意外修改",
                        "global_mutable",
                    )

    def _check_hardcoded_network(self, node):
        if not isinstance(node.value, str):
            return
        m = IP_PATTERN.search(node.value)
        if not m:
            return
        ip = m.group()
        if ip in EXCLUDE_IPS:
            return
        # 校验八位组 0-255
        octets = ip.split(".")
        if any(not o.isdigit() or int(o) > 255 for o in octets):
            return
        # 排除版本号风格的字符串（如 "1.0.0.0"）
        if _VERSION_LIKE.match(node.value.strip()):
            return
        self._add(
            node.lineno, Severity.LOW, "quality",
            f"硬编码IP地址 '{node.value}'，建议移到配置文件",
            "hardcoded_network",
        )

    # ---------- 辅助 ----------

    @staticmethod
    def _calc_nesting(stmts, current):
        """递归计算最大嵌套深度，覆盖 body / orelse / handlers / finalbody。"""
        mx = current
        for s in stmts:
            if isinstance(s, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                mx = max(mx, UnifiedRuleVisitor._calc_nesting(getattr(s, "body", []), current + 1))
                if getattr(s, "orelse", None):
                    mx = max(mx, UnifiedRuleVisitor._calc_nesting(s.orelse, current + 1))
                if getattr(s, "handlers", None):
                    mx = max(mx, UnifiedRuleVisitor._calc_nesting(s.handlers, current + 1))
                if getattr(s, "finalbody", None):
                    mx = max(mx, UnifiedRuleVisitor._calc_nesting(s.finalbody, current + 1))
        return mx


class RuleEngine:
    """基于 AST 的规则检测引擎。"""

    def __init__(self):
        self.rules = {r.id: r for r in BUILTIN_RULES}

    def analyze(self, code, tree, filename):
        # type: (str, ast.Module, str) -> list[Issue]
        visitor = UnifiedRuleVisitor(filename)
        # 预计算：模块级别直接子节点的行号（用于 global_mutable）
        visitor.module_level_lines = {
            node.lineno
            for node in ast.iter_child_nodes(tree)
            if isinstance(node, ast.Assign) and hasattr(node, "lineno")
        }
        visitor.visit(tree)
        return visitor.issues
