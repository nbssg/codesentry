"""控制流图分析引擎（Control Flow Graph Analysis）。

v2 改进：
  - 去除 bare_except + dangerous_except_pass 重复告警
  - 合并为单次 ast.walk 遍历
  - _check_bare_return_paths 避免进入嵌套函数
"""

import ast
from dataclasses import dataclass, field


@dataclass
class CFGNode:
    """控制流图节点。"""
    line: int
    node_type: str
    label: str = ""


@dataclass
class CFGEdge:
    """控制流图边。"""
    from_line: int
    to_line: int
    edge_type: str


@dataclass
class CFGResult:
    """控制流图分析结果。"""
    nodes: list[CFGNode] = field(default_factory=list)
    edges: list[CFGEdge] = field(default_factory=list)
    unreachable_lines: list[int] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)


class CFGAnalyzer:
    """基于 AST 构建控制流图并分析。单次遍历完成所有检查。"""

    def analyze(self, tree: ast.Module) -> CFGResult:
        result = CFGResult()

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(node, result)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._analyze_function(item, result)

        return result

    def _analyze_function(self, func, result: CFGResult):
        """分析单个函数：不可达代码 + 异常处理 + 返回值一致性。单次遍历。"""
        result.nodes.append(CFGNode(
            line=func.lineno, node_type="entry", label=f"def {func.name}()"
        ))

        # 1. 不可达代码
        unreachable = self._find_unreachable(func.body)
        result.unreachable_lines.extend(unreachable)

        # 2. 单次遍历检查异常处理 + 返回值（不进入嵌套函数）
        self._walk_function_body(func, result)

    def _walk_function_body(self, func, result: CFGResult):
        """单次遍历函数体，检查异常处理和返回值。不进入嵌套函数。"""
        # 用栈代替 ast.walk，遇到嵌套 FunctionDef 时跳过
        stack = list(func.body)
        has_return_with_value = False
        has_return_none = False
        has_type_annotation = func.returns is not None

        # 记录已处理的 try 节点（避免重复检查）
        seen_try: set[int] = set()

        while stack:
            node = stack.pop()

            # 跳过嵌套函数
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # 检查 Try 节点
            if isinstance(node, ast.Try) and id(node) not in seen_try:
                seen_try.add(id(node))
                self._check_exception_handlers(node, result)

            # 检查返回值（仅当前函数级别）
            if isinstance(node, ast.Return):
                if node.value is None or (
                    isinstance(node.value, ast.Constant) and node.value.value is None
                ):
                    has_return_none = True
                else:
                    has_return_with_value = True

            # 展开子节点（不进入嵌套函数）
            for child in ast.iter_child_nodes(node):
                if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    stack.append(child)

        # 返回值一致性检查
        if has_type_annotation and has_return_with_value and has_return_none:
            result.warnings.append({
                "line": func.lineno,
                "type": "inconsistent_return",
                "message": f"函数 {func.name} 有的路径返回值，有的路径返回 None",
                "severity": "low",
            })

    def _find_unreachable(self, stmts: list) -> list[int]:
        """检测不可达代码：return/break/continue 之后的代码。"""
        unreachable = []
        found_terminator = False

        for stmt in stmts:
            if found_terminator:
                if isinstance(stmt, (ast.FunctionDef, ast.ClassDef)):
                    continue
                unreachable.append(stmt.lineno)

            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                found_terminator = True
            elif isinstance(stmt, ast.If):
                if self._all_paths_return(stmt):
                    found_terminator = True

        return unreachable

    def _all_paths_return(self, if_node: ast.If) -> bool:
        """检查 if-else 的所有分支是否都以 return 结尾。"""
        body_returns = self._block_ends_with_return(if_node.body)
        orelse_returns = self._block_ends_with_return(if_node.orelse) if if_node.orelse else False
        return body_returns and orelse_returns

    def _block_ends_with_return(self, stmts: list) -> bool:
        if not stmts:
            return False
        last = stmts[-1]
        if isinstance(last, (ast.Return, ast.Raise)):
            return True
        if isinstance(last, ast.If):
            return self._all_paths_return(last)
        return False

    def _check_exception_handlers(self, node: ast.Try, result: CFGResult):
        """检测异常处理缺陷。bare_except + pass 只产生一条 dangerous_except_pass。"""
        for handler in node.handlers:
            is_bare = handler.type is None
            is_pass = len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)

            if is_bare and is_pass:
                # 最危险的组合：只产生 dangerous_except_pass（不重复产生 bare_except）
                result.warnings.append({
                    "line": handler.lineno,
                    "type": "dangerous_except_pass",
                    "message": "裸 except + pass：所有异常被静默忽略，严重安全隐患",
                    "severity": "high",
                })
            elif is_bare:
                result.warnings.append({
                    "line": handler.lineno,
                    "type": "bare_except",
                    "message": "裸 except 会捕获所有异常（包括 KeyboardInterrupt、SystemExit），建议指定具体异常类型",
                    "severity": "medium",
                })
            elif (isinstance(handler.type, ast.Name) and handler.type.id == "Exception"
                  and is_pass):
                result.warnings.append({
                    "line": handler.lineno,
                    "type": "swallowed_exception",
                    "message": "异常被完全吞没（except Exception: pass），调试时无法发现错误",
                    "severity": "medium",
                })
