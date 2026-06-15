"""统一分析引擎集成测试。"""

from engine.analyzer import analyze_code


class TestAnalyzeCode:
    def test_syntax_error(self):
        r = analyze_code("def f(:\n  pass")
        assert r.maintainability_score == 0.0
        assert any(i.category == "syntax" for i in r.issues)

    def test_clean_code(self):
        r = analyze_code("x = 1\ny = 2\n")
        assert r.maintainability_score == 100.0
        assert len(r.issues) == 0

    def test_engines_used(self):
        r = analyze_code("""
def get_user(name):
    cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
""")
        assert "taint_engine" in r.scanners_used

    def test_dedup(self):
        # bare except: pass → cfg_engine produces dangerous_except_pass (not bare_except)
        r = analyze_code("""
def f():
    try:
        pass
    except:
        pass
""")
        # should have dangerous_except_pass from cfg_engine
        dangerous = [i for i in r.issues if "except" in i.rule_id]
        assert len(dangerous) >= 1

    def test_to_dict(self):
        r = analyze_code('x = 1')
        d = r.to_dict()
        assert "maintainability_score" in d
        assert "engines_used" in d
        assert isinstance(d["issues"], list)

    def test_real_vulnerability_sample(self):
        code = open("samples/vulnerable.py", encoding="utf-8").read()
        r = analyze_code(code, "vulnerable.py")
        assert r.maintainability_score < 50
        d = r.to_dict()
        assert d["high"] >= 3
        assert "taint_engine" in r.scanners_used
        assert "rule_engine" in r.scanners_used
