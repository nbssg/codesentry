"""CodeSentry FastAPI 后端。

三层架构：
  Layer 1: 自研分析引擎（规则引擎 + 污点分析 + 控制流分析）
  Layer 2: 智能修复建议（基于规则的代码修复，不依赖外部大模型）
  Layer 3: 开发者体验（一键修复、审计报告）

所有分析能力完全自研，不依赖 bandit、semgrep 等第三方工具。
"""

import os

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from engine.analyzer import analyze_code
from engine.autofix import CodeAutoFixer

app = FastAPI(title="CodeSentry", version="1.1.0")

# CORS: 开发环境允许全部，生产环境限制来源
ALLOWED_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:8501,http://localhost:3000,http://127.0.0.1:8501",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0", "engines": ["rule_engine", "taint_engine", "cfg_engine"]}


@app.post("/scan")
async def scan_code(file: UploadFile = File(...)):
    code = (await file.read()).decode("utf-8")
    return analyze_code(code, filename=file.filename).to_dict()


@app.post("/scan-text")
async def scan_text(payload: dict):
    code = payload.get("code", "")
    filename = payload.get("filename", "<pasted_code>")
    return analyze_code(code, filename=filename).to_dict()


@app.post("/fix-suggestions")
async def fix_suggestions(payload: dict):
    """根据检测到的问题，生成基于规则的修复建议。"""
    issues = payload.get("issues", [])
    code = payload.get("code", "")
    suggestions = []
    for issue in issues:
        suggestion = _generate_fix_suggestion(issue, code)
        if suggestion:
            suggestions.append(suggestion)
    return {"suggestions": suggestions}


@app.post("/report")
async def report(payload: dict):
    """生成结构化的审计报告（纯算法，不依赖大模型）。"""
    issues = payload.get("issues", [])
    score = payload.get("score", 0)
    engines = payload.get("engines_used", [])

    high = [i for i in issues if i.get("severity") == "high"]
    medium = [i for i in issues if i.get("severity") == "medium"]
    low = [i for i in issues if i.get("severity") == "low"]

    # 按来源引擎分组
    by_engine = {}
    for i in issues:
        src = i.get("source", "unknown")
        by_engine.setdefault(src, []).append(i)

    # 按类别分组
    by_category = {}
    for i in issues:
        cat = i.get("category", "other")
        by_category.setdefault(cat, []).append(i)

    # 风险类别分析
    risk_categories = _analyze_risk_categories(issues)

    # 详细修复建议
    fix_priorities = _prioritize_fixes(issues)

    report_data = {
        "summary": {
            "score": score,
            "total_issues": len(issues),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "engines_used": engines,
            "security_issues": len([i for i in issues if i.get("category") == "security"]),
            "quality_issues": len([i for i in issues if i.get("category") == "quality"]),
            "dead_code_issues": len([i for i in issues if i.get("category") == "dead_code"]),
            "taint_issues": len([i for i in issues if i.get("category") == "taint"]),
        },
        "risk_level": _risk_level(score),
        "top_issues": [
            {"line": i.get("line"), "message": i.get("message", "")[:120], "severity": i.get("severity", ""), "rule_id": i.get("rule_id", "")}
            for i in high[:5]
        ],
        "by_engine": {
            engine: {"count": len(engine_issues), "high": len([i for i in engine_issues if i.get("severity") == "high"])}
            for engine, engine_issues in by_engine.items()
        },
        "by_category": {
            cat: len(cat_issues)
            for cat, cat_issues in by_category.items()
        },
        "risk_categories": risk_categories,
        "fix_priorities": fix_priorities,
        "recommendations": _generate_recommendations(issues),
        "executive_summary": _executive_summary(score, issues, engines),
    }
    return report_data


@app.post("/auto-fix")
async def auto_fix(payload: dict):
    """一键修复代码中的所有可自动修复的问题。"""
    code = payload.get("code", "")
    issues = payload.get("issues", [])
    fixer = CodeAutoFixer()
    fixed_code, applied_fixes = fixer.fix(code, issues)
    return {"fixed_code": fixed_code, "applied_fixes": applied_fixes}


def _risk_level(score: float) -> str:
    if score >= 80:
        return "低风险"
    elif score >= 50:
        return "中风险"
    elif score >= 20:
        return "高风险"
    return "极高风险"


def _generate_fix_suggestion(issue: dict, code: str) -> dict | None:
    """基于规则的修复建议生成。"""
    rule_id = issue.get("rule_id", "")
    line = issue.get("line", 0)
    severity = issue.get("severity", "")
    message = issue.get("message", "")
    category = issue.get("category", "")

    # rule_id (S001/S002/...) → fix_map key 的映射
    RULE_TO_FIX = {
        "S001": "hardcoded_secret",
        "S002": "eval_usage",
        "S003": "exec_usage",
        "S005": "weak_hash",
        "S006": "weak_random",
        "S007": "file_no_context",
        "S008": "long_function",
        "S009": "deep_nesting",
        "S010": "mutable_global",
        "S011": "file_no_context",
        "S012": "file_no_context",
    }

    # 根据 rule_id + category 匹配修复模板
    fix_map = {
        "hardcoded_secret": {
            "title": "使用环境变量替代硬编码",
            "before": 'API_KEY = "your-key-here"',
            "after": 'import os\nAPI_KEY = os.environ.get("API_KEY", "")',
            "explanation": "将敏感信息移到环境变量中，代码中不再包含明文密钥。",
        },
        "eval_usage": {
            "title": "使用 ast.literal_eval 替代 eval()",
            "before": "result = eval(user_input)",
            "after": "import ast\nresult = ast.literal_eval(user_input)",
            "explanation": "ast.literal_eval 只解析 Python 字面量（字符串、数字、元组、列表、字典、布尔值、None），不会执行任意代码，从根本上消除代码注入风险。",
        },
        "exec_usage": {
            "title": "避免使用 exec()，改用安全替代方案",
            "before": "exec(dynamic_code)",
            "after": "# 根据具体需求选择安全替代方案：\n# 1. 动态导入：importlib.import_module(module_name)\n# 2. 函数映射：getattr(handler, method_name)()\n# 3. 安全沙箱：RestrictedPython",
            "explanation": "exec() 可以执行任意 Python 代码，攻击者可借此获得完整的程序控制权。应根据实际场景选择类型安全的替代方案。",
        },
        "bare_except": {
            "title": "指定具体异常类型并记录日志",
            "before": "try:\n    ...\nexcept:\n    pass",
            "after": "import logging\ntry:\n    ...\nexcept ValueError as e:\n    logging.error(f'Value error: {e}')\nexcept TypeError as e:\n    logging.error(f'Type error: {e}')",
            "explanation": "裸 except 会捕获所有异常（包括 KeyboardInterrupt、SystemExit），导致程序无法正常终止。指定具体异常类型 + 记录日志是最佳实践。",
        },
        "weak_hash": {
            "title": "使用安全哈希算法替代 MD5/SHA1",
            "before": "hashlib.md5(data).hexdigest()",
            "after": "import hashlib\nhashlib.sha256(data).hexdigest()\n\n# 如需密码哈希，使用专用算法：\n# from passlib.hash import bcrypt\n# bcrypt.hash(password)",
            "explanation": "MD5 和 SHA1 已被证明存在碰撞攻击（2^18 次即可制造碰撞）。SHA-256 是最低安全要求；密码存储应使用 bcrypt/scrypt/argon2 等慢哈希算法。",
        },
        "deep_nesting": {
            "title": "提取子函数降低嵌套深度",
            "before": "def process(a, b, c):\n    if a:\n        if b:\n            if c:\n                do_something()\n            else:\n                do_other()\n        else:\n            handle_b_missing()",
            "after": "def validate_inputs(a, b, c):\n    return a and b and c\n\ndef process(a, b, c):\n    if not validate_inputs(a, b, c):\n        handle_missing()\n        return\n    do_something()",
            "explanation": "嵌套超过 4 层会使代码难以理解和测试。通过提前返回（Guard Clause）和提取子函数，可以将嵌套控制在 2 层以内，显著提升可读性和可维护性。",
        },
        "long_function": {
            "title": "拆分为多个职责单一的小函数",
            "before": "def process_order(...):\n    # 超过 50 行的大函数\n    ...\n    # 职责：验证 + 计算 + 保存 + 通知",
            "after": "def validate_order(...):\n    \"\"\"验证订单参数\"\"\"\n    ...\n\ndef calculate_total(...):\n    \"\"\"计算订单金额\"\"\"\n    ...\n\ndef save_order(...):\n    \"\"\"保存订单\"\"\"\n    ...\n\ndef process_order(...):\n    validate_order(...)\n    total = calculate_total(...)\n    save_order(...)",
            "explanation": "单一职责原则（SRP）：每个函数只做一件事。长函数难以测试、理解和复用。拆分后每个函数可以独立测试，bug 定位也更快。",
        },
        "shell_true": {
            "title": "使用参数列表替代 shell=True",
            "before": 'subprocess.call("ping -c 1 " + hostname, shell=True)',
            "after": "import subprocess\nsubprocess.call(['ping', '-c', '1', hostname])",
            "explanation": "shell=True 会将命令字符串传递给系统 shell 解析，攻击者可以通过注入 ; rm -rf / 等 shell 元字符执行任意命令。使用参数列表形式可以避免 shell 解析。",
        },
        "weak_random": {
            "title": "使用密码学安全随机数",
            "before": "token = str(random.randint(100000, 999999))",
            "after": "import secrets\ntoken = secrets.token_hex(16)  # 32位随机字符串",
            "explanation": "random 模块使用确定性伪随机算法（梅森旋转），输出可被预测。安全令牌、密码重置码等场景必须使用 secrets 模块（底层为 CSPRNG）。",
        },
        "mutable_global": {
            "title": "避免可变全局状态",
            "before": "CACHE = {}\ncounter = 0",
            "after": "# 方案1：使用函数属性\ndef get_cache():\n    if not hasattr(get_cache, 'data'):\n        get_cache.data = {}\n    return get_cache.data\n\n# 方案2：使用类封装状态\nclass State:\n    def __init__(self):\n        self.counter = 0",
            "explanation": "可变全局变量会导致竞态条件和难以追踪的 bug。在多线程/异步环境下尤其危险。应使用类封装状态或使用线程安全的数据结构。",
        },
        "file_no_context": {
            "title": "使用 with 语句管理文件资源",
            "before": "f = open('data.txt', 'r')\ndata = f.read()",
            "after": "with open('data.txt', 'r') as f:\n    data = f.read()",
            "explanation": "不使用 with 语句时，如果在 read() 和 close() 之间发生异常，文件句柄会泄露。with 语句保证在退出时自动调用 close()，即使发生异常。",
        },
        "taint-flow": {
            "title": "对用户输入进行验证和参数化处理",
            "before": "query = \"SELECT * FROM users WHERE name='\" + username + \"'\"",
            "after": "# 使用参数化查询（最安全）\ncursor.execute('SELECT * FROM users WHERE name = ?', (username,))\n\n# 或使用 ORM（推荐）\nUser.objects.filter(name=username).first()",
            "explanation": "字符串拼接 SQL 是 SQL 注入的根本原因。参数化查询将用户输入作为数据参数传递，数据库驱动会自动转义，使注入攻击无法成功。",
        },
        "unreachable_code": {
            "title": "删除不可达代码",
            "before": "return result\nx = do_something()  # 永远不会执行",
            "after": "return result",
            "explanation": "不可达代码是死代码，不会被任何执行路径触及。它会误导开发者认为代码有实际功能，增加维护成本，降低代码可读性。",
        },
        "inconsistent_return": {
            "title": "确保所有路径返回一致的类型",
            "before": "def process(x):\n    if x > 0:\n        return x\n    # 隐式返回 None",
            "after": "def process(x):\n    if x > 0:\n        return x\n    return None  # 显式返回，类型一致",
            "explanation": "有些分支 return 值、有些隐式返回 None，调用者容易在未检查 None 的情况下触发 TypeError。应显式返回所有可能的值，保持类型一致。",
        },
        "swallowed_exception": {
            "title": "记录异常日志，不要静默吞没",
            "before": "try:\n    dangerous_operation()\nexcept:\n    pass",
            "after": "import logging\ntry:\n    dangerous_operation()\nexcept Exception as e:\n    logging.error(f'Operation failed: {e}')",
            "explanation": "异常被静默吞没后，bug 会变得极难定位。至少应记录日志；对于关键操作还应考虑通知监控系统或进行重试。",
        },
        "dangerous_except_pass": {
            "title": "在危险操作的异常处理中添加日志和告警",
            "before": "try:\n    subprocess.call(user_cmd)\nexcept:\n    pass",
            "after": "import logging\ntry:\n    subprocess.call(user_cmd)\nexcept subprocess.CalledProcessError as e:\n    logging.error(f'Command failed with code {e.returncode}: {e}')\nexcept OSError as e:\n    logging.error(f'OS error: {e}')",
            "explanation": "对危险操作（命令执行、网络请求等）的异常静默处理会隐藏安全事件和运行故障。应至少记录完整异常信息，关键路径应触发告警。",
        },
    }

    # 先通过映射表转换 rule_id，再查找 fix_map
    fix_key = RULE_TO_FIX.get(rule_id, rule_id)
    suggestion = fix_map.get(fix_key)
    if suggestion:
        # 根据 code 提取实际的 before 片段
        suggestion = _enrich_with_actual_code(suggestion, issue, code)
        suggestion["line"] = line
        suggestion["severity"] = severity
        suggestion["rule_id"] = rule_id
        return suggestion

    # 按 category 兜底
    category_fallback = {
        "security": {
            "title": f"安全问题: {issue.get('message', '').split(chr(10))[0][:60]}",
            "before": "# 请参见原代码对应行",
            "after": "# 建议：使用经过验证的安全库和安全编码实践",
            "explanation": "检测到安全类问题，请根据具体上下文选择适当的修复方案。",
        },
        "quality": {
            "title": f"代码质量: {issue.get('message', '').split(chr(10))[0][:60]}",
            "before": "# 请参见原代码对应行",
            "after": "# 建议：重构代码以提升可读性和可维护性",
            "explanation": "检测到代码质量问题，建议进行针对性重构。",
        },
        "dead_code": {
            "title": f"死代码: {issue.get('message', '').split(chr(10))[0][:60]}",
            "before": "# 请参见原代码对应行",
            "after": "# 删除不可达代码",
            "explanation": "检测到不可达或无用代码，建议清理以降低维护成本。",
        },
    }

    suggestion = category_fallback.get(category)
    if suggestion:
        suggestion = _enrich_with_actual_code(suggestion, issue, code)
        suggestion["line"] = line
        suggestion["severity"] = severity
        suggestion["rule_id"] = rule_id
        return suggestion

    return None


def _enrich_with_actual_code(suggestion: dict, issue: dict, code: str) -> dict:
    """尝试从源代码中提取实际的 before 片段，替换模板中的通用示例。"""
    line = issue.get("line", 0)
    if not line or not code:
        return suggestion

    lines = code.split("\n")
    if line <= len(lines):
        actual_line = lines[line - 1].rstrip()
        if actual_line.strip():
            suggestion["before"] = actual_line
    return suggestion


def _generate_recommendations(issues: list[dict]) -> list[str]:
    """根据问题分布生成改进建议。"""
    recs = []
    categories = set(i.get("category", "") for i in issues)
    rule_ids = set(i.get("rule_id", "") for i in issues)

    # 安全类建议
    if "taint" in categories:
        recs.append("【数据流安全】发现污点传播路径：建议建立统一的输入验证层，所有外部输入必须经过清洗再使用。SQL 查询必须使用参数化查询，命令执行必须使用参数列表形式。")
    if "hardcoded_secret" in rule_ids:
        recs.append("【密钥管理】发现硬编码密钥：建议使用环境变量或密钥管理服务（如 Vault、KMS）管理敏感信息，禁止将密钥直接写入代码。")
    if "eval_usage" in rule_ids or "exec_usage" in rule_ids:
        recs.append("【代码注入】发现动态代码执行：eval()/exec() 可被攻击者利用执行任意代码。应使用 ast.literal_eval() 或类型安全的替代方案。")
    if "weak_hash" in rule_ids:
        recs.append("【密码学安全】发现弱哈希算法：MD5/SHA1 存在碰撞攻击风险。文件校验应使用 SHA-256+，密码存储应使用 bcrypt/scrypt/argon2。")
    if "shell_true" in rule_ids:
        recs.append("【命令注入】发现 shell=True 调用：应使用参数列表形式避免 shell 解析，防止命令注入攻击。")

    # 代码质量建议
    if "deep_nesting" in rule_ids:
        recs.append("【可读性】发现深层嵌套（>4层）：建议使用 Guard Clause（提前返回）和提取子函数降低嵌套深度，目标控制在 2 层以内。")
    if "long_function" in rule_ids:
        recs.append("【可维护性】发现过长函数：建议按单一职责原则拆分，每个函数不超过 30 行。拆分后可独立测试，bug 定位也更快。")
    if "mutable_global" in rule_ids:
        recs.append("【并发安全】发现可变全局状态：多线程/异步环境下可能导致竞态条件。应使用类封装状态或线程安全的数据结构。")

    # 代码结构建议
    if "bare_except" in rule_ids:
        recs.append("【异常处理】发现裸 except：应指定具体异常类型，避免捕获 KeyboardInterrupt/SystemExit。异常处理中应记录日志，便于问题追踪。")
    if "unreachable_code" in rule_ids:
        recs.append("【死代码】发现不可达代码：建议立即删除。不可达代码会误导开发者，增加维护成本，可能隐藏逻辑错误。")
    if "inconsistent_return" in rule_ids:
        recs.append("【返回值一致性】同一函数不同分支返回类型不一致：应确保所有路径返回一致的类型，避免调用者未处理 None 而触发 TypeError。")

    # 按严重程度的综合建议
    high_count = len([i for i in issues if i.get("severity") == "high"])
    if high_count >= 3:
        recs.append(f"【紧急】发现 {high_count} 个高危问题：建议立即修复所有高危问题后再进行功能开发，安全问题不应留到上线后处理。")

    if not recs:
        recs.append("代码质量良好，建议保持现有编码规范。可考虑添加单元测试和类型注解进一步提升代码质量。")

    return recs


def _analyze_risk_categories(issues: list[dict]) -> list[dict]:
    """分析风险类别，返回每个类别的详细信息。"""
    risk_map = {
        "taint": {
            "name": "数据流安全",
            "description": "检测到用户输入未经清洗直接传入危险函数",
            "impact": "可能导致 SQL 注入、命令注入、代码注入等严重安全漏洞",
            "priority": "critical",
        },
        "security": {
            "name": "一般安全",
            "description": "检测到硬编码密钥、弱哈希、不安全函数调用等安全问题",
            "impact": "可能导致敏感信息泄露、身份伪造、数据篡改",
            "priority": "high",
        },
        "quality": {
            "name": "代码质量",
            "description": "检测到深层嵌套、过长函数、可变全局状态等质量问题",
            "impact": "增加维护成本、降低可读性、引入潜在 bug",
            "priority": "medium",
        },
        "dead_code": {
            "name": "代码结构",
            "description": "检测到不可达代码、返回值不一致等结构性问题",
            "impact": "误导开发者、隐藏逻辑错误、降低代码可维护性",
            "priority": "low",
        },
    }

    result = []
    by_category = {}
    for i in issues:
        cat = i.get("category", "other")
        by_category.setdefault(cat, []).append(i)

    for cat, cat_issues in by_category.items():
        info = risk_map.get(cat, {"name": cat, "description": "", "impact": "", "priority": "medium"})
        result.append({
            "category": cat,
            "name": info["name"],
            "description": info["description"],
            "impact": info["impact"],
            "priority": info["priority"],
            "count": len(cat_issues),
            "high": len([i for i in cat_issues if i.get("severity") == "high"]),
            "rule_ids": list(set(i.get("rule_id", "") for i in cat_issues)),
        })

    return result


def _prioritize_fixes(issues: list[dict]) -> list[dict]:
    """按修复优先级排序问题，返回带优先级说明的列表。"""
    severity_order = {"high": 0, "medium": 1, "low": 2}
    priority_labels = {0: "P0 - 立即修复", 1: "P1 - 尽快修复", 2: "P2 - 计划修复"}

    sorted_issues = sorted(issues, key=lambda i: severity_order.get(i.get("severity", ""), 3))

    result = []
    for i, issue in enumerate(sorted_issues):
        sev = issue.get("severity", "")
        priority = severity_order.get(sev, 3)
        result.append({
            "line": issue.get("line", 0),
            "severity": sev,
            "rule_id": issue.get("rule_id", ""),
            "category": issue.get("category", ""),
            "message": issue.get("message", "").split("\n")[0][:100],
            "priority": priority_labels.get(priority, f"P{priority} - 修复"),
            "source": issue.get("source", ""),
        })
    return result


def _executive_summary(score: float, issues: list[dict], engines: list[str]) -> str:
    """生成一句话总结摘要。"""
    high = len([i for i in issues if i.get("severity") == "high"])
    medium = len([i for i in issues if i.get("severity") == "medium"])
    low = len([i for i in issues if i.get("severity") == "low"])
    total = len(issues)

    if total == 0:
        return f"代码质量评分 {score:.0f}/100，未发现明显安全和质量问题。建议保持现有编码规范。"

    risk = _risk_level(score)
    engines_str = "、".join(engines) if engines else "未知"

    parts = [f"代码质量评分 {score:.0f}/100（{risk}），"]
    parts.append(f"共发现 {total} 个问题")
    parts.append(f"（高危 {high}、中危 {medium}、低危 {low}）。")
    parts.append(f"通过 {engines_str} {len(engines)} 个分析引擎检测。")

    if high > 0:
        parts.append(f"存在 {high} 个高危安全问题，建议立即修复。")
    elif medium > 0:
        parts.append(f"存在 {medium} 个中等问题，建议尽快修复。")
    else:
        parts.append("整体代码质量良好。")

    return "".join(parts)
