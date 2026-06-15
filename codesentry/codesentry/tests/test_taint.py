"""污点分析引擎单元测试。"""

import ast
from engine.taint import TaintAnalyzer, SANITIZERS


def analyze(code: str):
    tree = ast.parse(code)
    a = TaintAnalyzer()
    return a.analyze(tree)


class TestTaintSource:
    def test_function_param_to_sink(self):
        paths = analyze("""
def get_user(name):
    cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
""")
        assert len(paths) >= 1
        assert paths[0].sink_desc.startswith("SQL注入")
        assert paths[0].confidence == 1.0

    def test_input_to_os_system(self):
        paths = analyze("""
def run_cmd(cmd):
    os.system(cmd)
""")
        assert len(paths) >= 1
        assert "命令注入" in paths[0].sink_desc

    def test_no_taint_when_no_sink(self):
        paths = analyze("""
def process(x):
    y = x + 1
    return y
""")
        assert len(paths) == 0

    def test_fstring_taint(self):
        paths = analyze("""
def greet(name):
    query = f"SELECT * FROM users WHERE name='{name}'"
    cursor.execute(query)
""")
        assert len(paths) >= 1

    def test_sanitizer_reduces_confidence(self):
        paths = analyze("""
def safe(cmd):
    clean = shlex.quote(cmd)
    os.system(clean)
""")
        # shlex.quote confidence = 0.05, so if sanitizer is detected, path should have low confidence
        if paths:
            assert paths[0].confidence < 1.0


class TestCallGraph:
    def test_builds_call_graph(self):
        tree = ast.parse("""
def a():
    b()

def b():
    cursor.execute(x)
""")
        a = TaintAnalyzer()
        a.call_graph.build(tree)
        assert "b" in a.call_graph.get_callees("a")


class TestCrossFunction:
    def test_param_passed_to_dangerous_func(self):
        paths = analyze("""
def query_db(sql):
    cursor.execute(sql)

def get_data(user_input):
    query_db(user_input)
""")
        # user_input flows into query_db's sql param, which hits cursor.execute
        assert len(paths) >= 1
