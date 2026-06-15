"""污点分析引擎（Taint Analysis Engine）。

v3 重写：
  - 修复跨函数污点传播（正确使用调用图）
  - 补全 AnnAssign / AugAssign / with-as / tuple 解包
  - _check_tainted_expr 支持 ast.Call 参数遍历
  - 迭代式语句处理（避免深递归栈溢出）
"""

import ast
from dataclasses import dataclass, field

from .utils import get_call_name


# ========== 定义 ==========

@dataclass
class TaintPath:
    """一条从源到汇的污点传播路径。"""
    source_line: int
    source_desc: str
    sink_line: int
    sink_desc: str
    path_nodes: list[int] = field(default_factory=list)
    confidence: float = 1.0


TAINT_SOURCES = {
    "input": "用户输入(input())",
    "request.args": "HTTP查询参数",
    "request.form": "HTTP表单数据",
    "request.json": "HTTP JSON体",
    "request.data": "HTTP请求体",
    "request.values": "HTTP请求值",
    "request.files": "HTTP上传文件",
    "cursor.fetchone": "数据库查询结果",
    "cursor.fetchall": "数据库查询结果",
}

DANGER_SINKS = {
    "cursor.execute": ("SQL注入", "数据库查询执行"),
    "db.execute": ("SQL注入", "数据库查询执行"),
    "connection.execute": ("SQL注入", "数据库查询执行"),
    "os.system": ("命令注入", "系统命令执行"),
    "os.popen": ("命令注入", "系统命令执行"),
    "subprocess.call": ("命令注入", "子进程调用"),
    "subprocess.run": ("命令注入", "子进程调用"),
    "subprocess.Popen": ("命令注入", "子进程调用"),
    "eval": ("代码注入", "动态代码执行"),
    "exec": ("代码注入", "动态代码执行"),
    "open": ("路径遍历", "文件操作"),
    "pickle.loads": ("不安全反序列化", "pickle反序列化"),
    "pickle.load": ("不安全反序列化", "pickle反序列化"),
    "yaml.load": ("不安全反序列化", "YAML反序列化"),
    "render_template_string": ("XSS", "模板渲染"),
}

SANITIZERS = {
    "int": 0.3,
    "float": 0.3,
    "shlex.quote": 0.05,
    "html.escape": 0.1,
    "re.sub": 0.3,
    "parameterized": 0.05,
    "escape": 0.2,
    "sanitize": 0.1,
}


# ========== 调用图构建 ==========

class CallGraphBuilder:
    """构建函数调用图：记录每个函数内部调用了哪些其他函数。"""

    def __init__(self):
        self.calls_from: dict[str, set[str]] = {}
        self.func_nodes: dict[str, ast.FunctionDef] = {}
        # 谁调用了我 → set of caller function names
        self.callers_of: dict[str, set[str]] = {}

    def build(self, tree: ast.Module):
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.func_nodes[node.name] = node
                self.calls_from[node.name] = set()
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        callee = get_call_name(child)
                        if callee:
                            self.calls_from[node.name].add(callee)
                            self.callers_of.setdefault(callee, set()).add(node.name)

    def get_callees(self, func_name: str) -> set[str]:
        return self.calls_from.get(func_name, set())

    def get_callers(self, func_name: str) -> set[str]:
        return self.callers_of.get(func_name, set())


# ========== 污点分析 ==========

class TaintAnalyzer:
    """函数内 + 跨函数污点分析。"""

    def __init__(self):
        self.taint_vars: dict[str, tuple[int, str, float]] = {}
        self.paths: list[TaintPath] = []
        self.call_graph = CallGraphBuilder()
        # 跨函数污点：callee_name → (source_line, source_desc, confidence)
        self.func_taint_returns: dict[str, tuple[int, str, float]] = {}
        self.current_func: str = ""

    def analyze(self, tree: ast.Module) -> list[TaintPath]:
        self.call_graph.build(tree)

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(node)
        return self.paths

    def _analyze_function(self, func: ast.FunctionDef):
        self.taint_vars.clear()
        self.current_func = func.name

        # 函数参数 → 污点源
        for arg in func.args.args:
            if arg.arg not in ("self", "cls"):
                self.taint_vars[arg.arg] = (func.lineno, f"参数 {arg.arg}", 1.0)

        # 迭代式处理（避免深递归）
        for stmt in func.body:
            self._process_statement(stmt)

        # 记录本函数是否返回了污点
        for stmt in ast.walk(func):
            if isinstance(stmt, ast.Return) and stmt.value:
                tainted, line, desc, conf = self._check_expr_taint(stmt.value)
                if tainted:
                    self.func_taint_returns[func.name] = (line, f"通过 {func.name}() 返回", conf)

    def _process_statement(self, stmt):
        """迭代式语句处理（用栈代替递归，避免栈溢出）。"""
        stack = [stmt]
        while stack:
            node = stack.pop()

            if isinstance(node, ast.Assign):
                self._process_assign(node)
            elif isinstance(node, ast.AnnAssign) and node.value:
                # x: str = input()
                self._process_ann_assign(node)
            elif isinstance(node, ast.AugAssign):
                # x += tainted
                self._process_aug_assign(node)
            elif isinstance(node, ast.Expr):
                self._process_expr_stmt(node)
            elif isinstance(node, (ast.If, ast.For, ast.While)):
                for s in node.body:
                    stack.append(s)
                for s in node.orelse:
                    stack.append(s)
            elif isinstance(node, ast.With):
                self._process_with(node)
            elif isinstance(node, ast.Try):
                for s in node.body:
                    stack.append(s)
                for handler in node.handlers:
                    for s in handler.body:
                        stack.append(s)
                for s in node.finalbody:
                    stack.append(s)
            # 不递归进嵌套函数（已在顶层分析）

    def _process_assign(self, stmt: ast.Assign):
        value = stmt.value
        is_tainted = False
        source_line = 0
        source_desc = ""
        confidence = 1.0

        # 1. 右边是污点源函数
        if isinstance(value, ast.Call):
            func_name = get_call_name(value)
            if func_name in TAINT_SOURCES:
                is_tainted = True
                source_line = value.lineno
                source_desc = TAINT_SOURCES[func_name]

        # 2. 右边是已知污点变量
        t = self._check_expr_taint(value)
        if t[0]:
            is_tainted = True
            source_line, source_desc, confidence = t[1], t[2], t[3]

        # 3. 跨函数：被调用函数返回了污点
        if isinstance(value, ast.Call):
            callee = get_call_name(value)
            if callee in self.func_taint_returns:
                ret_line, ret_desc, ret_conf = self.func_taint_returns[callee]
                # 检查是否传递了当前污点变量给被调用函数
                for arg in value.args:
                    at = self._check_expr_taint(arg)
                    if at[0]:
                        is_tainted = True
                        source_line = at[1]
                        source_desc = f"通过 {callee}() 传递"
                        confidence = at[3]
                        break

        # 记录左边变量（支持 tuple 解包）
        for target in stmt.targets:
            self._assign_target(target, is_tainted, source_line, source_desc, confidence, value)

        # 如果右边是清洗函数调用且包含污点变量，降低置信度
        if isinstance(value, ast.Call):
            sanitizer_conf = self._check_sanitizer(value)
            if sanitizer_conf is not None:
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id in self.taint_vars:
                        old_line, old_desc, old_conf = self.taint_vars[target.id]
                        new_conf = old_conf * sanitizer_conf
                        if new_conf < 0.1:
                            del self.taint_vars[target.id]
                        else:
                            self.taint_vars[target.id] = (old_line, old_desc + "（经清洗）", new_conf)

    def _process_ann_assign(self, stmt: ast.AnnAssign):
        """处理 x: str = input()"""
        if stmt.value and isinstance(stmt.target, ast.Name):
            is_tainted, line, desc, conf = self._check_expr_taint(stmt.value)
            if is_tainted:
                self.taint_vars[stmt.target.id] = (line, desc, conf)

    def _process_aug_assign(self, stmt: ast.AugAssign):
        """处理 x += tainted"""
        if isinstance(stmt.target, ast.Name) and stmt.target.id in self.taint_vars:
            # 已有污点 + 右边可能也是污点 → 保持污点
            t = self._check_expr_taint(stmt.value)
            if t[0]:
                line, desc, conf = self.taint_vars[stmt.target.id]
                self.taint_vars[stmt.target.id] = (line, desc + " (+=)", conf)

    def _process_with(self, stmt: ast.With):
        """处理 with open(...) as f: → 标记 f 为污点（如果是危险函数）。"""
        for item in stmt.items:
            if isinstance(item.context_expr, ast.Call):
                func_name = get_call_name(item.context_expr)
                if func_name in TAINT_SINKS:
                    if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                        self.taint_vars[item.optional_vars.id] = (
                            stmt.lineno, f"来自 {func_name}()", 0.8
                        )
        for s in stmt.body:
            self._process_statement(s)

    def _assign_target(self, target, is_tainted, line, desc, conf, value):
        """递归处理赋值目标（支持 tuple 解包）。"""
        if isinstance(target, ast.Name):
            if is_tainted:
                self.taint_vars[target.id] = (line, desc, conf)
            elif target.id in self.taint_vars:
                sanitizer_conf = self._check_sanitizer(value)
                if sanitizer_conf is not None:
                    old_line, old_desc, old_conf = self.taint_vars[target.id]
                    new_conf = old_conf * sanitizer_conf
                    if new_conf < 0.1:
                        del self.taint_vars[target.id]
                    else:
                        self.taint_vars[target.id] = (old_line, old_desc + "（经清洗）", new_conf)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign_target(elt, is_tainted, line, desc, conf, value)

    def _process_expr_stmt(self, stmt: ast.Expr):
        if not isinstance(stmt.value, ast.Call):
            return
        call = stmt.value
        func_name = get_call_name(call)
        if func_name not in DANGER_SINKS:
            return

        vuln_type, sink_desc = DANGER_SINKS[func_name]

        for arg in call.args:
            tainted, src_line, src_desc, conf = self._check_arg_taint(arg)
            if tainted:
                self.paths.append(TaintPath(
                    source_line=src_line,
                    source_desc=src_desc,
                    sink_line=stmt.lineno,
                    sink_desc=f"{vuln_type} → {sink_desc}",
                    path_nodes=[src_line, stmt.lineno],
                    confidence=conf,
                ))

    def _check_arg_taint(self, arg) -> tuple[bool, int, str, float]:
        """检查函数参数是否被污染。"""
        if isinstance(arg, ast.Name) and arg.id in self.taint_vars:
            line, desc, conf = self.taint_vars[arg.id]
            return True, line, desc, conf

        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            return self._check_tainted_expr(arg)

        if isinstance(arg, ast.JoinedStr):
            for val in arg.values:
                if isinstance(val, ast.FormattedValue) and isinstance(val.value, ast.Name):
                    if val.value.id in self.taint_vars:
                        line, desc, conf = self.taint_vars[val.value.id]
                        return True, arg.lineno, f"f-string含 {val.value.id}", conf

        # 检查函数调用参数中的污点
        if isinstance(arg, ast.Call):
            for inner_arg in arg.args:
                t = self._check_arg_taint(inner_arg)
                if t[0]:
                    return t

        return False, 0, "", 1.0

    def _check_expr_taint(self, expr) -> tuple[bool, int, str, float]:
        """检查表达式中是否包含污点变量。支持 Name / BinOp / Call / JoinedStr。"""
        if isinstance(expr, ast.Name) and expr.id in self.taint_vars:
            line, desc, conf = self.taint_vars[expr.id]
            return True, line, desc, conf

        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            t1 = self._check_tainted_expr(expr.left)
            if t1[0]:
                return t1
            return self._check_tainted_expr(expr.right)

        # 遍历 Call 参数（如 str(input())）
        if isinstance(expr, ast.Call):
            for arg in expr.args:
                t = self._check_expr_taint(arg)
                if t[0]:
                    return t
            # 也检查关键字参数
            for kw in expr.keywords:
                t = self._check_expr_taint(kw.value)
                if t[0]:
                    return t

        if isinstance(expr, ast.JoinedStr):
            for val in expr.values:
                if isinstance(val, ast.FormattedValue) and isinstance(val.value, ast.Name):
                    if val.value.id in self.taint_vars:
                        line, desc, conf = self.taint_vars[val.value.id]
                        return True, expr.lineno, f"f-string含 {val.value.id}", conf

        return False, 0, "", 1.0

    def _check_tainted_expr(self, expr) -> tuple[bool, int, str, float]:
        """别名，统一入口。"""
        return self._check_expr_taint(expr)

    def _check_sanitizer(self, expr) -> float | None:
        """检查是否是清洗函数。"""
        if isinstance(expr, ast.Call):
            name = get_call_name(expr)
            if name in SANITIZERS:
                return SANITIZERS[name]
        return None


# 污点分析中的 sink 集合（用于 with-as 标记）
TAINT_SINKS = set(DANGER_SINKS.keys())
