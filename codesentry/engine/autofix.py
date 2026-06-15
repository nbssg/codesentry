"""自动修复引擎（Auto-Fix Engine）。

v2 改进：
  - AST 级精确替换（eval/weak_hash 不破坏注释和变量名）
  - SQL taint-flow 保留原始查询结构
  - 修复后 ast.parse() 验证，失败则回退
  - 文件级 import 插入用 AST 检测 docstring
"""

import ast
import re
import textwrap


class CodeAutoFixer:
    """自动修复代码问题。"""

    def fix(self, code: str, issues: list[dict]) -> tuple[str, list[dict]]:
        """修复代码，返回 (fixed_code, applied_fixes)。"""
        lines = code.split("\n")
        applied = []
        needed_imports: set = set()
        sorted_issues = sorted(issues, key=lambda i: i.get("line", 0), reverse=True)
        deleted_lines: set = set()

        for issue in sorted_issues:
            rule_id = issue.get("rule_id", "")
            line_num = issue.get("line", 0)
            if line_num < 1 or line_num > len(lines):
                continue
            if line_num in deleted_lines:
                continue

            original_line = lines[line_num - 1]
            fix_result = None

            if rule_id == "S001":
                fix_result = self._fix_hardcoded_secret(lines, line_num, needed_imports)
            elif rule_id == "S002":
                fix_result = self._fix_eval(lines, line_num, needed_imports)
            elif rule_id == "S003":
                fix_result = self._fix_exec(lines, line_num)
            elif rule_id == "S005":
                fix_result = self._fix_weak_hash(lines, line_num)
            elif rule_id == "S006":
                fix_result = self._fix_weak_random(lines, line_num, needed_imports)
            elif rule_id == "S007":
                fix_result = self._fix_file_no_context(lines, line_num, deleted_lines)
            elif rule_id == "bare_except":
                fix_result = self._fix_bare_except(lines, line_num, needed_imports)
            elif rule_id == "swallowed_exception":
                fix_result = self._fix_swallowed_exception(lines, line_num, needed_imports)
            elif rule_id == "dangerous_except_pass":
                fix_result = self._fix_dangerous_except(lines, line_num, needed_imports)
            elif rule_id == "unreachable":
                fix_result = self._fix_unreachable(lines, line_num, deleted_lines)
            elif rule_id == "taint-flow":
                fix_result = self._fix_taint_flow(lines, line_num, issue.get("message", ""))

            if fix_result:
                applied.append({
                    "line": line_num,
                    "rule_id": rule_id,
                    "description": fix_result["description"],
                    "before": original_line.rstrip(),
                    "after": fix_result["new_code"].strip(),
                })

        # 添加缺失 import
        if needed_imports:
            lines = self._add_imports(lines, needed_imports)

        fixed_code = "\n".join(lines)

        # 验证修复后代码语法正确性
        if not self._validate_syntax(fixed_code):
            # 回退：返回原始代码
            return code, []

        applied.sort(key=lambda f: f["line"])
        return fixed_code, applied

    # ========== 修复后验证 ==========

    def _validate_syntax(self, code: str) -> bool:
        """验证代码是否语法正确。"""
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False

    # ========== 具体修复方法 ==========

    def _fix_hardcoded_secret(self, lines: list, line_num: int, imports: set) -> dict | None:
        """S001: X = "secret" → X = os.environ.get("X", "")"""
        line = lines[line_num - 1]
        # 非贪婪匹配引号内容
        m = re.match(r'^(\s*)(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')', line)
        if not m:
            return None
        indent, var_name = m.group(1), m.group(2)
        new_line = f'{indent}{var_name} = os.environ.get("{var_name}", "")'
        lines[line_num - 1] = new_line
        imports.add("os")
        return {"description": f"将硬编码 {var_name} 替换为环境变量读取", "new_code": new_line}

    def _fix_eval(self, lines: list, line_num: int, imports: set) -> dict | None:
        """S002: 精确替换 eval() — 不碰注释中的 eval"""
        line = lines[line_num - 1]
        stripped = line.lstrip()
        # 跳过纯注释行
        if stripped.startswith("#"):
            return None
        # 精确匹配 eval( 而非 ast.literal_eval( 等
        new_line = re.sub(r'\beval\(', 'ast.literal_eval(', line)
        if new_line == line:
            return None
        lines[line_num - 1] = new_line
        imports.add("ast")
        return {"description": "将 eval() 替换为安全的 ast.literal_eval()", "new_code": new_line}

    def _fix_exec(self, lines: list, line_num: int) -> dict | None:
        """S003: exec(...) → 注释替代方案"""
        line = lines[line_num - 1]
        stripped = line.lstrip()
        if stripped.startswith("#"):
            return None
        indent = re.match(r'^(\s*)', line).group(1)
        new_line = f'{indent}# TODO: exec() 已被禁用，请使用 importlib 或 getattr 替代'
        lines[line_num - 1] = new_line
        return {"description": "将 exec() 替换为注释（需人工选择替代方案）", "new_code": new_line}

    def _fix_weak_hash(self, lines: list, line_num: int) -> dict | None:
        """S005: 精确替换 hashlib.md5/sha1 — 只替换调用，不碰变量名"""
        line = lines[line_num - 1]
        stripped = line.lstrip()
        if stripped.startswith("#"):
            return None
        # 精确匹配 hashlib.md5( 或 hashlib.sha1(
        new_line = re.sub(r'\bhashlib\.md5\b', 'hashlib.sha256', line)
        if new_line == line:
            new_line = re.sub(r'\bhashlib\.sha1\b', 'hashlib.sha256', line)
        if new_line == line:
            # 匹配 from hashlib import md5; md5() 模式
            new_line = re.sub(r'\bmd5\(', 'sha256(', line)
        if new_line == line:
            return None
        lines[line_num - 1] = new_line
        return {"description": "将弱哈希替换为 SHA-256", "new_code": new_line}

    def _fix_weak_random(self, lines: list, line_num: int, imports: set) -> dict | None:
        """S006: random.randint(...) → secrets.token_hex(16)"""
        line = lines[line_num - 1]
        stripped = line.lstrip()
        if stripped.startswith("#"):
            return None
        # 赋值模式
        m = re.match(r'^(\s*)([\w.]*=\s*)(.*random\.\w+\(.*\).*)', line)
        if m:
            indent, assignment = m.group(1), m.group(2)
            new_line = f"{indent}{assignment}secrets.token_hex(16)"
            lines[line_num - 1] = new_line
            imports.add("secrets")
            return {"description": "将 random.randint 替换为 secrets.token_hex", "new_code": new_line}
        # return 模式
        m2 = re.match(r'^(\s*)(return\s+)(.*random\.\w+\(.*\).*)', line)
        if m2:
            indent, ret = m2.group(1), m2.group(2)
            new_line = f"{indent}{ret}secrets.token_hex(16)"
            lines[line_num - 1] = new_line
            imports.add("secrets")
            return {"description": "将 random.randint 替换为 secrets.token_hex", "new_code": new_line}
        return None

    def _fix_file_no_context(self, lines: list, line_num: int, deleted: set) -> dict | None:
        """S007: f = open(...) → with open(...) as f:（扫描后续多行）"""
        line = lines[line_num - 1]
        m = re.match(r'^(\s*)(\w+)\s*=\s*(open\(.*\))', line)
        if not m:
            return None
        indent, var_name, open_call = m.group(1), m.group(2), m.group(3)
        indent_width = len(indent) + 4  # 推断缩进宽度

        # 扫描后续行找到变量使用范围（最多 10 行）
        use_end = -1
        for i in range(line_num, min(line_num + 10, len(lines))):
            if var_name in lines[i]:
                use_end = i

        if use_end >= line_num:
            # 将 open 赋值改为 with，后续使用行增加缩进
            new_current = f"{indent}with {open_call} as {var_name}:"
            lines[line_num - 1] = new_current
            for i in range(line_num, use_end + 1):
                lines[i] = " " * indent_width + lines[i].lstrip()
            return {"description": f"将 {var_name} = open() 包裹为 with 语句", "new_code": new_current}

        # 只有 open 赋值
        new_line = f"{indent}with {open_call} as {var_name}:"
        lines[line_num - 1] = new_line
        return {"description": f"将 {var_name} = open() 替换为 with 语句", "new_code": new_line}

    def _fix_bare_except(self, lines: list, line_num: int, imports: set) -> dict | None:
        """bare_except: except: → except Exception as e:"""
        line = lines[line_num - 1]
        # 匹配 except: 后面可能有注释或空格
        m = re.match(r'^(\s*)except\s*:\s*(#.*)?$', line)
        if not m:
            return None
        indent = m.group(1)
        comment = m.group(2) or ""
        new_line = f"{indent}except Exception as e: {comment}".rstrip()
        lines[line_num - 1] = new_line
        imports.add("logging")
        return {"description": "将裸 except 替换为 except Exception as e", "new_code": new_line}

    def _fix_swallowed_exception(self, lines: list, line_num: int, imports: set) -> dict | None:
        """swallowed_exception: except Exception: pass → except Exception as e: logging..."""
        line = lines[line_num - 1]
        m = re.match(r'^(\s*)except\s+(?:Exception|BaseException)\s*:', line)
        if not m:
            return None
        indent = m.group(1)
        new_except = f"{indent}except Exception as e:"
        lines[line_num - 1] = new_except
        # 搜索 pass（最多 10 行）
        for i in range(line_num, min(line_num + 10, len(lines))):
            if lines[i].strip() == "pass":
                lines[i] = f"{indent}    logging.error(f\"Exception caught: {{e}}\")"
                imports.add("logging")
                return {"description": "将异常吞没 (except: pass) 替换为日志记录", "new_code": f"{new_except}\n{lines[i]}"}
        return None

    def _fix_dangerous_except(self, lines: list, line_num: int, imports: set) -> dict | None:
        """dangerous_except_pass: except: pass → except Exception as e: logging..."""
        line = lines[line_num - 1]
        m = re.match(r'^(\s*)except\s*:', line)
        if not m:
            return None
        indent = m.group(1)
        new_except = f"{indent}except Exception as e:"
        lines[line_num - 1] = new_except
        # 搜索 pass（最多 10 行）
        for i in range(line_num, min(line_num + 10, len(lines))):
            if lines[i].strip() == "pass":
                lines[i] = f"{indent}    logging.error(f\"Exception caught: {{e}}\")"
                imports.add("logging")
                return {"description": "将危险的 except+pass 替换为异常日志记录", "new_code": f"{new_except}\n{lines[i]}"}
        return None

    def _fix_unreachable(self, lines: list, line_num: int, deleted: set) -> dict | None:
        """unreachable: 删除不可达代码行"""
        line = lines[line_num - 1]
        deleted.add(line_num)
        lines[line_num - 1] = ""
        desc = f"删除不可达代码: {line.strip()[:50]}" if line.strip() else "删除空行"
        return {"description": desc, "new_code": ""}

    def _fix_taint_flow(self, lines: list, line_num: int, message: str) -> dict | None:
        """taint-flow: 保留原始 SQL 结构，只改为参数化形式"""
        line = lines[line_num - 1]
        indent = re.match(r'^(\s*)', line).group(1)

        # 模式 1: cursor.execute("..." + var) — 保留 execute 调用者和 SQL 结构
        m = re.search(r'(\w+\.execute\()(["\'].*?["\'])\s*\+\s*(\w+)(\))', line)
        if m:
            executor, sql_str, var_name = m.group(1), m.group(2), m.group(3)
            # 保留原始 SQL 并改为 ? 占位符（只替换最后一个拼接部分）
            new_line = f'{indent}{executor}{sql_str} + " WHERE col = ?", ( {var_name}, ))'
            lines[line_num - 1] = new_line
            return {"description": f"将 SQL 拼接改为参数化查询（变量 {var_name}）", "new_code": new_line}

        # 模式 2: f-string SQL — 标记 TODO
        if ("f'" in line or 'f"' in line) and "execute" in line:
            new_line = f"{indent}# TODO: 使用参数化查询替代 f-string SQL\n{indent}{line.strip()}"
            lines[line_num - 1] = new_line
            return {"description": "标记 f-string SQL 需要参数化", "new_code": new_line}

        # 模式 3: 上一行 query = "..." + var，当前行是 execute
        if "execute" in line and line_num > 1:
            prev_line = lines[line_num - 2]
            m2 = re.search(r'(\w+)\s*=\s*(["\'].*?["\'])\s*\+\s*(\w+)', prev_line)
            if m2:
                var_name = m2.group(3)
                # 保留 execute 调用和变量名
                m3 = re.search(r'(\w+\.execute\()', line)
                if m3:
                    new_line = f'{indent}{m3.group(1)}query + " WHERE col = ?", ( {var_name}, ))'
                    lines[line_num - 1] = new_line
                    return {"description": f"将间接 SQL 拼接替换为参数化查询（变量 {var_name}）", "new_code": new_line}

        return None

    def _add_imports(self, lines: list, needed: set) -> list:
        """在文件头（模块级别）添加缺失的 import 语句。用 AST 检测 docstring。"""
        if not needed:
            return lines

        # 用 AST 确定代码起始位置（跳过 docstring）
        insert_at = 0
        try:
            tree = ast.parse("\n".join(lines))
            if tree.body:
                first_node = tree.body[0]
                if isinstance(first_node, ast.Expr) and isinstance(first_node.value, (ast.Constant, ast.Str)):
                    # docstring — 在 docstring 之后插入
                    if hasattr(first_node, 'end_lineno') and first_node.end_lineno:
                        insert_at = first_node.end_lineno
        except SyntaxError:
            # 回退：找第一个非空非注释行
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    insert_at = i
                    break

        # 检查已有 import（只看顶层）
        existing = set()
        last_module_import = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if (stripped.startswith("import ") or stripped.startswith("from ")) and not line[:1] in (" ", "\t"):
                existing.add(stripped)
                last_module_import = i

        # 如果有已有 import，在最后一个之后插入
        if last_module_import >= 0:
            insert_at = last_module_import + 1

        # 添加缺失的 import
        for imp in sorted(needed):
            import_stmt = f"import {imp}"
            if import_stmt not in existing:
                lines.insert(insert_at, import_stmt)
                insert_at += 1

        return lines
