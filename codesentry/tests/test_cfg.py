"""控制流分析引擎单元测试。"""

import ast
from engine.cfg import CFGAnalyzer


def analyze(code: str):
    tree = ast.parse(code)
    a = CFGAnalyzer()
    return a.analyze(tree)


class TestUnreachable:
    def test_code_after_return(self):
        r = analyze("""
def f():
    return 1
    x = 2  # unreachable
""")
        assert any(w["type"] == "unreachable" for w in r.warnings) or len(r.unreachable_lines) > 0

    def test_no_unreachable_simple(self):
        r = analyze("""
def f():
    x = 1
    return x
""")
        assert len(r.unreachable_lines) == 0


class TestBareExcept:
    def test_detects_bare_except(self):
        # bare except without pass → bare_except warning
        r = analyze("""
def f():
    try:
        pass
    except:
        x = 1
""")
        assert any(w["type"] == "bare_except" for w in r.warnings)

    def test_bare_except_pass_is_dangerous(self):
        # bare except + pass → dangerous_except_pass (not bare_except)
        r = analyze("""
def f():
    try:
        pass
    except:
        pass
""")
        assert any(w["type"] == "dangerous_except_pass" for w in r.warnings)
        assert not any(w["type"] == "bare_except" for w in r.warnings)

    def test_no_bare_except(self):
        r = analyze("""
def f():
    try:
        pass
    except ValueError:
        pass
""")
        assert not any(w["type"] == "bare_except" for w in r.warnings)


class TestSwallowedException:
    def test_detects_except_pass(self):
        r = analyze("""
def f():
    try:
        pass
    except Exception:
        pass
""")
        assert any(w["type"] == "swallowed_exception" for w in r.warnings)


class TestDangerousExceptPass:
    def test_detects(self):
        r = analyze("""
def f():
    try:
        pass
    except:
        pass
""")
        assert any(w["type"] == "dangerous_except_pass" for w in r.warnings)


class TestInconsistentReturn:
    def test_detects(self):
        r = analyze("""
def f() -> int:
    if True:
        return 1
    return None
""")
        assert any(w["type"] == "inconsistent_return" for w in r.warnings)
