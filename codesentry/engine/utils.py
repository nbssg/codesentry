"""AST 工具函数（公共模块）。"""

import ast


def get_call_name(node: ast.Call) -> str:
    """提取函数调用的完整名称。

    示例：
      os.system(...)          → "os.system"
      cursor.execute(...)     → "cursor.execute"
      open(...)               → "open"
      obj.method().func(...)  → "func" (只取最外层)
    """
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""
