"""规则引擎单元测试。"""

import ast
from engine.rules import RuleEngine


def scan(code: str):
    tree = ast.parse(code)
    e = RuleEngine()
    return e.analyze(code, tree, "<test>")


class TestHardcodedSecret:
    def test_detects_password(self):
        issues = scan('PASSWORD = "admin123"')
        assert any(i.rule_id == "S001" for i in issues)

    def test_ignores_empty_string(self):
        issues = scan('PASSWORD = ""')
        assert not any(i.rule_id == "S001" for i in issues)

    def test_ignores_non_secret_names(self):
        issues = scan('username = "admin"')
        assert not any(i.rule_id == "S001" for i in issues)


class TestDangerousCall:
    def test_detects_eval(self):
        issues = scan('eval(user_input)')
        assert any(i.rule_id == "S002" for i in issues)

    def test_detects_exec(self):
        issues = scan('exec(code)')
        assert any(i.rule_id == "S003" for i in issues)


class TestWeakHash:
    def test_detects_md5(self):
        issues = scan('hashlib.md5(data)')
        assert any(i.rule_id == "S005" for i in issues)

    def test_ignores_sha256(self):
        issues = scan('hashlib.sha256(data)')
        assert not any(i.rule_id == "S005" for i in issues)


class TestFileNoContext:
    def test_detects_open_not_in_with(self):
        issues = scan('f = open("data.txt")')
        assert any(i.rule_id == "S007" for i in issues)

    def test_ignores_open_in_with(self):
        issues = scan("""
with open("data.txt") as f:
    data = f.read()
""")
        assert not any(i.rule_id == "S007" for i in issues)


class TestDeepNesting:
    def test_detects_deep_if(self):
        code = """
def f(x):
    if x > 0:
        if x > 10:
            if x > 20:
                if x > 30:
                    if x > 40:
                        return True
"""
        issues = scan(code)
        assert any(i.rule_id == "S009" for i in issues)


class TestLongFunction:
    def test_detects_long_function(self):
        body = "\n".join(f"    x_{i} = {i}" for i in range(60))
        code = f"def long_func():\n{body}"
        issues = scan(code)
        assert any(i.rule_id == "S008" for i in issues)
