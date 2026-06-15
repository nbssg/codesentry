"""
CodeSentry — 代码安全分析引擎（单进程版）
所有分析能力完全自研，不依赖 bandit、semgrep 等第三方工具。
"""

import streamlit as st

st.set_page_config(page_title="CodeSentry", page_icon="🛡️", layout="wide")

# ── 引擎导入（直接调用，无需后端） ──
from engine.analyzer import analyze_code
from engine.autofix import CodeAutoFixer

# ========== 全局暗色主题样式 ==========
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── 全局 ── */
.stApp {
    background: linear-gradient(135deg, #0a0e1a 0%, #111827 50%, #0f172a 100%);
}
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0f172a 0%, #1e1b4b 100%) !important;
}

/* ── 隐藏默认元素 ── */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 2rem !important; }

/* ── 标题区 ── */
.hero-title {
    font-family: 'Inter', sans-serif;
    font-size: 2.8rem;
    font-weight: 800;
    background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 40%, #f472b6 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0;
    letter-spacing: -0.02em;
}
.hero-sub {
    font-family: 'Inter', sans-serif;
    font-size: 0.95rem;
    color: #94a3b8;
    font-weight: 400;
    margin-top: 0.3rem;
    letter-spacing: 0.02em;
}
.hero-badge {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    background: linear-gradient(135deg, rgba(96,165,250,0.15), rgba(167,139,250,0.15));
    color: #93c5fd;
    border: 1px solid rgba(96,165,250,0.2);
}

/* ── 卡片 ── */
.glass-card {
    background: rgba(30, 41, 59, 0.6);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid rgba(148, 163, 184, 0.08);
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 16px;
    transition: all 0.3s ease;
}
.glass-card:hover {
    border-color: rgba(96, 165, 250, 0.2);
    box-shadow: 0 0 30px rgba(96, 165, 250, 0.05);
}

/* ── 评分区 ── */
.score-ring {
    width: 120px; height: 120px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Inter', sans-serif;
    font-size: 2.2rem; font-weight: 800;
    margin: 0 auto 8px;
    position: relative;
}
.score-ring::before {
    content: '';
    position: absolute;
    inset: -3px;
    border-radius: 50%;
    padding: 3px;
    background: conic-gradient(from 0deg, var(--ring-color) 0%, transparent 100%);
    -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
}
.score-good { --ring-color: #34d399; color: #34d399; background: rgba(52,211,153,0.08); }
.score-mid  { --ring-color: #fbbf24; color: #fbbf24; background: rgba(251,191,36,0.08); }
.score-bad  { --ring-color: #f87171; color: #f87171; background: rgba(248,113,113,0.08); }

.stat-card {
    text-align: center;
    padding: 20px 12px;
    border-radius: 14px;
    background: rgba(30, 41, 59, 0.5);
    border: 1px solid rgba(148, 163, 184, 0.06);
    transition: transform 0.2s;
}
.stat-card:hover { transform: translateY(-2px); }
.stat-num {
    font-family: 'Inter', sans-serif;
    font-size: 2rem; font-weight: 700;
    line-height: 1.2;
}
.stat-label {
    font-family: 'Inter', sans-serif;
    font-size: 0.75rem; font-weight: 500;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 4px;
}

/* ── 引擎标签 ── */
.engine-tag {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 5px 14px; border-radius: 20px;
    font-family: 'Inter', sans-serif;
    font-size: 0.75rem; font-weight: 600;
    letter-spacing: 0.02em;
    margin: 3px;
}
.engine-tag::before {
    content: '';
    width: 6px; height: 6px;
    border-radius: 50%;
    background: currentColor;
}
.tag-rule   { background: rgba(52,211,153,0.1); color: #34d399; border: 1px solid rgba(52,211,153,0.2); }
.tag-taint  { background: rgba(251,146,60,0.1); color: #fb923c; border: 1px solid rgba(251,146,60,0.2); }
.tag-cfg    { background: rgba(167,139,250,0.1); color: #a78bfa; border: 1px solid rgba(167,139,250,0.2); }

/* ── 问题卡片 ── */
.issue-card {
    background: rgba(30, 41, 59, 0.4);
    border: 1px solid rgba(148, 163, 184, 0.06);
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 10px;
    border-left: 3px solid var(--sev-color, #64748b);
    transition: all 0.2s;
}
.issue-card:hover {
    background: rgba(30, 41, 59, 0.6);
    border-color: rgba(148, 163, 184, 0.12);
}
.sev-high   { --sev-color: #f87171; }
.sev-medium { --sev-color: #fbbf24; }
.sev-low    { --sev-color: #34d399; }

.sev-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 6px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}
.sev-badge-high   { background: rgba(248,113,113,0.15); color: #f87171; }
.sev-badge-medium { background: rgba(251,191,36,0.15); color: #fbbf24; }
.sev-badge-low    { background: rgba(52,211,153,0.15); color: #34d399; }

.issue-line {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: #64748b;
}
.issue-msg {
    font-family: 'Inter', sans-serif;
    font-size: 0.9rem;
    color: #e2e8f0;
    margin: 6px 0;
    line-height: 1.5;
}

/* ── 按钮 ── */
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%) !important;
    border: none !important;
    border-radius: 10px !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 700 !important;
    font-size: 1.05rem !important;
    color: #ffffff !important;
    letter-spacing: 0.03em;
    padding: 12px 30px !important;
    transition: all 0.3s !important;
    box-shadow: 0 4px 15px rgba(59,130,246,0.25) !important;
    text-shadow: 0 1px 2px rgba(0,0,0,0.2) !important;
}
.stButton > button[kind="primary"]:hover {
    box-shadow: 0 6px 25px rgba(59,130,246,0.4) !important;
    transform: translateY(-1px);
    filter: brightness(1.1) !important;
}
.stButton > button[kind="secondary"] {
    background: rgba(51, 65, 85, 0.6) !important;
    border: 1px solid rgba(148, 163, 184, 0.2) !important;
    border-radius: 10px !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    font-size: 1.02rem !important;
    color: #f1f5f9 !important;
    letter-spacing: 0.02em;
}
.stButton > button[kind="secondary"]:hover {
    background: rgba(71, 85, 105, 0.6) !important;
    border-color: rgba(148, 163, 184, 0.35) !important;
    color: #ffffff !important;
}

/* ── Tab 样式 ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    background: rgba(30, 41, 59, 0.5);
    border-radius: 12px;
    padding: 4px;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 10px;
    font-family: 'Inter', sans-serif;
    font-weight: 500;
    font-size: 0.85rem;
    padding: 8px 20px;
}
.stTabs [aria-selected="true"] {
    background: rgba(96, 165, 250, 0.12) !important;
    color: #60a5fa !important;
    border-bottom: none !important;
}

/* ── 审计报告 ── */
.metric-card {
    background: rgba(30, 41, 59, 0.5);
    border: 1px solid rgba(148, 163, 184, 0.06);
    border-radius: 10px;
    padding: 12px;
    text-align: center;
}
.metric-val {
    font-family: 'Inter', sans-serif;
    font-size: 1.4rem;
    font-weight: 700;
    color: #e2e8f0;
}
.metric-lbl {
    font-size: 0.7rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-top: 2px;
}
.risk-badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 8px;
    font-size: 0.75rem;
    font-weight: 700;
}
.risk-low     { background: rgba(52,211,153,0.12); color: #34d399; }
.risk-medium  { background: rgba(251,191,36,0.12); color: #fbbf24; }
.risk-high    { background: rgba(248,113,113,0.12); color: #f87171; }
.risk-extreme { background: rgba(239,68,68,0.15); color: #ef4444; }
</style>
""", unsafe_allow_html=True)

# ========== 页面标题 ==========
st.markdown("""
<div style="text-align:center;padding:20px 0 10px">
    <div class="hero-title">🛡️ CodeSentry</div>
    <div class="hero-sub">自研代码安全分析引擎 · 三大引擎协同检测</div>
    <div style="margin-top:6px">
        <span class="hero-badge">规则引擎</span>
        <span class="hero-badge">污点分析</span>
        <span class="hero-badge">控制流分析</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ========== 侧边栏 ==========
with st.sidebar:
    st.markdown("""
    <div style="padding:12px 0;border-bottom:1px solid rgba(148,163,184,0.08);margin-bottom:16px">
        <div style="font-size:1.1rem;font-weight:700;color:#e2e8f0">🛡️ CodeSentry</div>
        <div style="color:#64748b;font-size:0.78rem;margin-top:4px">v1.0 · 2026</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="margin-bottom:20px">
        <div style="font-size:0.82rem;font-weight:600;color:#94a3b8;margin-bottom:8px">🔧 检测能力</div>
        <div style="font-size:0.75rem;color:#64748b;line-height:2">
        ✅ 硬编码密钥<br>
        ✅ eval/exec 注入<br>
        ✅ SQL 注入<br>
        ✅ 命令注入<br>
        ✅ 不安全反序列化<br>
        ✅ 弱哈希算法<br>
        ✅ 弱随机数<br>
        ✅ XML 外部实体<br>
        ✅ 断言验证<br>
        ✅ 异常处理缺陷<br>
        ✅ 死代码检测<br>
        ✅ 深层嵌套<br>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="border-top:1px solid rgba(148,163,184,0.08);padding-top:16px;margin-top:20px">
        <div style="font-size:0.82rem;font-weight:600;color:#94a3b8;margin-bottom:8px">⚙️ 分析引擎</div>
        <div style="font-size:0.75rem;color:#64748b;line-height:2">
        🟢 规则引擎 — AST 模式匹配<br>
        🟠 污点引擎 — 数据流追踪<br>
        🟣 CFG引擎 — 控制流分析<br>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="border-top:1px solid rgba(148,163,184,0.08);padding-top:16px;margin-top:20px">
        <div style="font-size:0.75rem;color:#64748b;line-height:1.7">
            华为云 CodeArts 代码智能体 · 用于辅助开发、调试和代码审查
        </div>
    </div>
    """, unsafe_allow_html=True)

# ========== 扫描页 ==========
result = st.session_state.get("scan_result")
code = st.session_state.get("code", "")

# 代码输入区
st.markdown("""
<div style="margin-bottom:8px">
    <span style="font-size:0.85rem;font-weight:600;color:#94a3b8;letter-spacing:0.03em">📝 输入代码</span>
</div>
""", unsafe_allow_html=True)

code = st.text_area(
    "粘贴 Python 代码",
    height=300,
    value=code,
    placeholder="# 在这里粘贴你要审查的 Python 代码...\n\ndef get_user(name):\n    query = 'SELECT * FROM users WHERE name=\\'' + name + '\\''\n    cursor.execute(query)\n    return cursor.fetchone()\n",
    label_visibility="collapsed",
)

c1, c2, c3 = st.columns([1, 3, 1])
with c1:
    do_scan = st.button("🔍  开始扫描", type="primary", disabled=not code.strip(), use_container_width=True)
with c2:
    if code.strip():
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:16px;padding:8px 0;color:#64748b;font-size:0.78rem">
            <span>📄 {len(code.strip().splitlines())} 行</span>
            <span>📝 {len(code)} 字符</span>
        </div>
        """, unsafe_allow_html=True)
with c3:
    pass

# 扫描 — 直接调用引擎
if do_scan:
    with st.spinner("三大引擎分析中..."):
        result_dict = analyze_code(code, filename="<pasted_code>").to_dict()
        st.session_state["scan_result"] = result_dict
        st.session_state["code"] = code
        st.session_state.pop("fix_suggestions", None)
        st.session_state.pop("audit_report", None)
        st.session_state.pop("auto_fix_result", None)
        result = result_dict

# ===== 结果 =====
if result is not None:
    score = result["maintainability_score"]
    score_cls = "score-good" if score >= 80 else ("score-mid" if score >= 50 else "score-bad")
    risk_label = "安全" if score >= 80 else ("注意" if score >= 50 else ("警告" if score >= 20 else "危险"))
    engines = result.get("engines_used", [])

    # 评分 + 统计
    st.markdown(f"""
    <div class="glass-card">
        <div style="display:flex;align-items:center;gap:40px;justify-content:center;flex-wrap:wrap">
            <div style="text-align:center">
                <div class="score-ring {score_cls}">{score:.0f}</div>
                <div style="font-size:0.72rem;color:#64748b;text-transform:uppercase;letter-spacing:0.1em;font-weight:600">{risk_label}</div>
            </div>
            <div style="display:flex;gap:12px;flex-wrap:wrap">
                <div class="stat-card" style="min-width:80px">
                    <div class="stat-num" style="color:#f87171">{result["high"]}</div>
                    <div class="stat-label">高危</div>
                </div>
                <div class="stat-card" style="min-width:80px">
                    <div class="stat-num" style="color:#fbbf24">{result["medium"]}</div>
                    <div class="stat-label">中危</div>
                </div>
                <div class="stat-card" style="min-width:80px">
                    <div class="stat-num" style="color:#34d399">{result["low"]}</div>
                    <div class="stat-label">低危</div>
                </div>
                <div class="stat-card" style="min-width:80px">
                    <div class="stat-num" style="color:#60a5fa">{len(engines)}</div>
                    <div class="stat-label">引擎</div>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # 引擎标签
    if engines:
        tags_html = ""
        for e in engines:
            cls = "tag-taint" if "taint" in e else ("tag-cfg" if "cfg" in e else "tag-rule")
            tags_html += f'<span class="engine-tag {cls}">{e}</span>'
        st.markdown(f"""
        <div style="text-align:center;margin-top:12px">
            {tags_html}
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # ===== 问题列表 =====
    if result["issues"]:
        st.markdown(f"""
        <div style="font-size:1rem;font-weight:600;color:#e2e8f0;margin:16px 0 12px">
            发现 <span style="color:#f87171">{result['total']}</span> 个问题
        </div>
        """, unsafe_allow_html=True)

        for issue in result["issues"]:
            sev = issue["severity"]
            sev_cls = f"sev-{sev}"
            badge_cls = f"sev-badge-{sev}"
            sev_text = {"high": "HIGH", "medium": "MED", "low": "LOW"}[sev]
            src = issue.get("source", "")
            tag_cls = "tag-taint" if "taint" in src else ("tag-cfg" if "cfg" in src else "tag-rule")

            first_line = issue['message'].split("\n")[0][:60]
            detail_lines = "<br>".join(f"<span style='color:#94a3b8'>{l}</span>" for l in issue["message"].split("\n") if l.strip())

            st.markdown(f"""
            <div class="issue-card {sev_cls}">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
                    <div style="display:flex;align-items:center;gap:10px">
                        <span class="sev-badge {badge_cls}">{sev_text}</span>
                        <span class="issue-line">行 {issue['line']}</span>
                        <span class="engine-tag {tag_cls}" style="margin:0;padding:2px 10px;font-size:0.65rem">{src}</span>
                    </div>
                    <span class="issue-line">{issue.get('category', '')}</span>
                </div>
                <div class="issue-msg">{first_line}</div>
                <div style="font-size:0.78rem;color:#64748b;line-height:1.7;margin-top:4px">{detail_lines}</div>
            </div>
            """, unsafe_allow_html=True)

        # ===== 操作按钮区 =====
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        fix_suggestions = st.session_state.get("fix_suggestions")
        audit_report = st.session_state.get("audit_report")
        auto_fix_result = st.session_state.get("auto_fix_result")

        btn_c1, btn_c2, btn_c3 = st.columns(3)
        with btn_c1:
            if st.button("💡 修复建议", type="secondary", use_container_width=True):
                with st.spinner("生成中..."):
                    fix_suggestions = _generate_all_fix_suggestions(code, result["issues"])
                    st.session_state["fix_suggestions"] = fix_suggestions

        with btn_c2:
            if st.button("🔧 一键修复", type="primary", use_container_width=True):
                with st.spinner("自动修复中..."):
                    fixer = CodeAutoFixer()
                    fixed_code, applied_fixes = fixer.fix(code, result["issues"])
                    st.session_state["auto_fix_result"] = {"fixed_code": fixed_code, "applied_fixes": applied_fixes}
                    auto_fix_result = st.session_state["auto_fix_result"]

        with btn_c3:
            if st.button("📋 审计报告", type="secondary", use_container_width=True):
                with st.spinner("生成中..."):
                    audit_report = _generate_report(result["issues"], score, engines)
                    st.session_state["audit_report"] = audit_report

        # ===== 修复建议结果 =====
        if fix_suggestions:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            st.markdown("""
            <div class="glass-card" style="border-left:3px solid #60a5fa">
                <div style="font-size:1rem;font-weight:700;color:#93c5fd;margin-bottom:4px">💡 修复建议</div>
            </div>
            """, unsafe_allow_html=True)

            for sug in fix_suggestions:
                st.markdown(f"""
                <div style="font-size:0.9rem;font-weight:600;color:#e2e8f0;margin:12px 0 8px">
                    行{sug['line']} · {sug['title']}
                </div>
                """, unsafe_allow_html=True)
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("<div style='font-size:0.72rem;color:#f87171;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px'>修复前</div>", unsafe_allow_html=True)
                    st.code(sug["before"], language="python")
                with c2:
                    st.markdown("<div style='font-size:0.72rem;color:#34d399;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px'>修复后</div>", unsafe_allow_html=True)
                    st.code(sug["after"], language="python")
                st.caption(sug["explanation"])

        # ===== 一键修复结果 =====
        if auto_fix_result:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            applied = auto_fix_result.get("applied_fixes", [])
            fixed_code_text = auto_fix_result.get("fixed_code", "")

            if applied:
                st.markdown(f"""
                <div class="glass-card" style="border-left:3px solid #34d399">
                    <div style="font-size:1rem;font-weight:700;color:#34d399;margin-bottom:4px">🔧 一键修复 — 已修复 {len(applied)} 个问题</div>
                </div>
                """, unsafe_allow_html=True)

                for fix in applied:
                    st.markdown(f"""
                    <div style="font-size:0.88rem;font-weight:600;color:#e2e8f0;margin:12px 0 8px">
                        <span style="color:#34d399">✅</span> 行{fix['line']} · {fix['rule_id']}
                    </div>
                    """, unsafe_allow_html=True)
                    if fix.get("before") and fix.get("after"):
                        c1, c2 = st.columns(2)
                        with c1:
                            st.markdown("<div style='font-size:0.72rem;color:#f87171;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px'>修复前</div>", unsafe_allow_html=True)
                            st.code(fix["before"], language="python")
                        with c2:
                            st.markdown("<div style='font-size:0.72rem;color:#34d399;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px'>修复后</div>", unsafe_allow_html=True)
                            st.code(fix["after"], language="python")

                st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
                st.markdown("""
                <div style="font-size:0.95rem;font-weight:600;color:#e2e8f0;margin-bottom:8px">📄 修复后的完整代码</div>
                """, unsafe_allow_html=True)
                st.code(fixed_code_text, language="python")

                st.download_button(
                    label="📥 下载修复后的代码",
                    data=fixed_code_text,
                    file_name="fixed_code.py",
                    mime="text/x-python",
                    type="primary",
                )
            else:
                st.info("所有问题均需要人工修复，无法自动处理")

        # ===== 审计报告 =====
        if audit_report:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            summary = audit_report["summary"]
            risk = audit_report["risk_level"]
            risk_map = {"低风险": "risk-low", "中风险": "risk-medium", "高风险": "risk-high", "极高风险": "risk-extreme"}
            risk_cls = risk_map.get(risk, "risk-medium")

            st.markdown(f"""
            <div class="glass-card">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <span style="font-size:1.1rem;font-weight:700;color:#e2e8f0">📋 审计报告</span>
                    <span class="risk-badge {risk_cls}">{risk}</span>
                </div>
                <div style="color:#94a3b8;font-size:0.85rem;line-height:1.7;margin-bottom:16px">
                    {audit_report.get('executive_summary', '')}
                </div>
                <div style="display:flex;gap:10px;flex-wrap:wrap">
                    <div class="metric-card" style="flex:1;min-width:80px">
                        <div class="metric-val">{summary['score']}</div>
                        <div class="metric-lbl">评分</div>
                    </div>
                    <div class="metric-card" style="flex:1;min-width:80px">
                        <div class="metric-val" style="color:#f87171">{summary.get('security_issues', 0)}</div>
                        <div class="metric-lbl">安全</div>
                    </div>
                    <div class="metric-card" style="flex:1;min-width:80px">
                        <div class="metric-val" style="color:#fb923c">{summary.get('taint_issues', 0)}</div>
                        <div class="metric-lbl">数据流</div>
                    </div>
                    <div class="metric-card" style="flex:1;min-width:80px">
                        <div class="metric-val" style="color:#fbbf24">{summary.get('quality_issues', 0)}</div>
                        <div class="metric-lbl">质量</div>
                    </div>
                    <div class="metric-card" style="flex:1;min-width:80px">
                        <div class="metric-val" style="color:#64748b">{summary.get('dead_code_issues', 0)}</div>
                        <div class="metric-lbl">死代码</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # 风险类别
            if audit_report.get("risk_categories"):
                st.markdown("""
                <div class="glass-card">
                    <div style="font-size:0.95rem;font-weight:700;color:#e2e8f0;margin-bottom:12px">⚠️ 风险类别分析</div>
                """, unsafe_allow_html=True)
                for rc in audit_report["risk_categories"]:
                    color = {"critical": "#f87171", "high": "#fb923c", "medium": "#fbbf24", "low": "#34d399"}.get(rc["priority"], "#64748b")
                    st.markdown(f"""
                    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(148,163,184,0.06)">
                        <span style="width:8px;height:8px;border-radius:50%;background:{color};flex-shrink:0"></span>
                        <span style="font-size:0.88rem;font-weight:600;color:#e2e8f0;min-width:80px">{rc['name']}</span>
                        <span style="font-size:0.78rem;color:#64748b">{rc['count']} 个问题</span>
                        <span style="font-size:0.72rem;color:{color};font-weight:600">{rc['priority'].upper()}</span>
                    </div>
                    """, unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            # 修复优先级
            if audit_report.get("fix_priorities"):
                st.markdown("""
                <div class="glass-card">
                    <div style="font-size:0.95rem;font-weight:700;color:#e2e8f0;margin-bottom:12px">🎯 修复优先级</div>
                """, unsafe_allow_html=True)
                for fp in audit_report["fix_priorities"]:
                    sev_color = {"high": "#f87171", "medium": "#fbbf24", "low": "#34d399"}.get(fp["severity"], "#64748b")
                    st.markdown(f"""
                    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(148,163,184,0.06)">
                        <span style="width:8px;height:8px;border-radius:50%;background:{sev_color};flex-shrink:0"></span>
                        <span style="font-size:0.78rem;font-weight:700;color:{sev_color};min-width:90px">{fp['priority']}</span>
                        <span style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:#94a3b8">行{fp['line']}</span>
                        <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#64748b">{fp['rule_id']}</span>
                    </div>
                    """, unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            # 引擎统计 + 建议
            st.markdown("""
            <div class="glass-card">
                <div style="font-size:0.95rem;font-weight:700;color:#e2e8f0;margin-bottom:12px">📝 改进建议</div>
            """, unsafe_allow_html=True)
            if audit_report.get("by_engine"):
                for eng, stats in audit_report["by_engine"].items():
                    st.markdown(f"""
                    <div style="display:flex;align-items:center;gap:8px;padding:4px 0">
                        <span class="engine-tag tag-{"taint" if "taint" in eng else "cfg" if "cfg" in eng else "rule"}" style="margin:0;padding:2px 10px;font-size:0.65rem">{eng}</span>
                        <span style="font-size:0.78rem;color:#64748b">{stats['count']} 个问题</span>
                    </div>
                    """, unsafe_allow_html=True)
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

            for i, r in enumerate(audit_report["recommendations"], 1):
                st.markdown(f"""
                <div style="display:flex;gap:10px;padding:6px 0;border-bottom:1px solid rgba(148,163,184,0.04)">
                    <span style="font-size:0.72rem;font-weight:700;color:#60a5fa;min-width:20px">{i}.</span>
                    <span style="font-size:0.82rem;color:#94a3b8;line-height:1.6">{r}</span>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    else:
        st.markdown("""
        <div class="glass-card" style="text-align:center;border-left:3px solid #34d399">
            <div style="font-size:1.5rem;margin-bottom:8px">✅</div>
            <div style="font-size:1rem;font-weight:600;color:#34d399">代码质量良好</div>
            <div style="font-size:0.82rem;color:#64748b;margin-top:4px">未发现明显安全和质量问题</div>
        </div>
        """, unsafe_allow_html=True)


# ========== 后端逻辑（直接内嵌，无需 FastAPI） ==========

def _generate_all_fix_suggestions(code: str, issues: list[dict]) -> list[dict]:
    """根据检测到的问题，生成基于规则的修复建议。"""
    suggestions = []
    for issue in issues:
        suggestion = _generate_fix_suggestion(issue, code)
        if suggestion:
            suggestions.append(suggestion)
    return suggestions


def _generate_fix_suggestion(issue: dict, code: str) -> dict | None:
    """基于规则的修复建议生成。"""
    rule_id = issue.get("rule_id", "")
    line = issue.get("line", 0)
    severity = issue.get("severity", "")
    category = issue.get("category", "")

    RULE_TO_FIX = {
        "S001": "hardcoded_secret", "S002": "eval_usage", "S003": "exec_usage",
        "S005": "weak_hash", "S006": "weak_random", "S007": "file_no_context",
        "S008": "long_function", "S009": "deep_nesting", "S010": "mutable_global",
        "S011": "file_no_context", "S012": "file_no_context",
    }

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
            "explanation": "ast.literal_eval 只解析 Python 字面量，不会执行任意代码，从根本上消除代码注入风险。",
        },
        "exec_usage": {
            "title": "避免使用 exec()，改用安全替代方案",
            "before": "exec(dynamic_code)",
            "after": "# 根据具体需求选择安全替代方案：\n# 1. 动态导入：importlib.import_module(module_name)\n# 2. 函数映射：getattr(handler, method_name)()",
            "explanation": "exec() 可以执行任意 Python 代码，攻击者可借此获得完整的程序控制权。",
        },
        "bare_except": {
            "title": "指定具体异常类型并记录日志",
            "before": "try:\n    ...\nexcept:\n    pass",
            "after": "import logging\ntry:\n    ...\nexcept ValueError as e:\n    logging.error(f'Value error: {e}')",
            "explanation": "裸 except 会捕获所有异常，指定具体异常类型 + 记录日志是最佳实践。",
        },
        "weak_hash": {
            "title": "使用安全哈希算法替代 MD5/SHA1",
            "before": "hashlib.md5(data).hexdigest()",
            "after": "import hashlib\nhashlib.sha256(data).hexdigest()",
            "explanation": "MD5 和 SHA1 已被证明存在碰撞攻击。SHA-256 是最低安全要求。",
        },
        "deep_nesting": {
            "title": "提取子函数降低嵌套深度",
            "before": "def process(a, b, c):\n    if a:\n        if b:\n            if c:\n                do_something()",
            "after": "def validate_inputs(a, b, c):\n    return a and b and c\n\ndef process(a, b, c):\n    if not validate_inputs(a, b, c):\n        return\n    do_something()",
            "explanation": "嵌套超过 4 层会使代码难以理解和测试。通过提前返回和提取子函数降低嵌套。",
        },
        "weak_random": {
            "title": "使用密码学安全随机数",
            "before": "token = str(random.randint(100000, 999999))",
            "after": "import secrets\ntoken = secrets.token_hex(16)",
            "explanation": "random 模块使用确定性伪随机算法，输出可被预测。安全场景必须使用 secrets 模块。",
        },
        "taint-flow": {
            "title": "对用户输入进行参数化处理",
            "before": "query = \"SELECT * FROM users WHERE name='\" + username + \"'\"",
            "after": "# 使用参数化查询\ncursor.execute('SELECT * FROM users WHERE name = ?', (username,))",
            "explanation": "字符串拼接 SQL 是 SQL 注入的根本原因。参数化查询将用户输入作为数据参数传递。",
        },
        "unreachable_code": {
            "title": "删除不可达代码",
            "before": "return result\nx = do_something()",
            "after": "return result",
            "explanation": "不可达代码不会被执行，会误导开发者，增加维护成本。",
        },
        "swallowed_exception": {
            "title": "记录异常日志",
            "before": "try:\n    dangerous_operation()\nexcept:\n    pass",
            "after": "import logging\ntry:\n    dangerous_operation()\nexcept Exception as e:\n    logging.error(f'Operation failed: {e}')",
            "explanation": "异常被静默吞没后，bug 会变得极难定位。至少应记录日志。",
        },
        "dangerous_except_pass": {
            "title": "在异常处理中添加日志",
            "before": "try:\n    subprocess.call(user_cmd)\nexcept:\n    pass",
            "after": "import logging\ntry:\n    subprocess.call(user_cmd)\nexcept subprocess.CalledProcessError as e:\n    logging.error(f'Command failed: {e}')",
            "explanation": "对危险操作的异常静默处理会隐藏安全事件。",
        },
        "shell_true": {
            "title": "使用参数列表替代 shell=True",
            "before": 'subprocess.call("ping -c 1 " + hostname, shell=True)',
            "after": "subprocess.call(['ping', '-c', '1', hostname])",
            "explanation": "shell=True 会将命令字符串传递给系统 shell 解析，存在命令注入风险。",
        },
    }

    fix_key = RULE_TO_FIX.get(rule_id, rule_id)
    suggestion = fix_map.get(fix_key)
    if not suggestion:
        category_fallback = {
            "security": {"title": f"安全问题: {issue.get('message', '').split(chr(10))[0][:60]}", "before": "# 请参见原代码对应行", "after": "# 建议：使用经过验证的安全库", "explanation": "检测到安全类问题。"},
            "quality": {"title": f"代码质量: {issue.get('message', '').split(chr(10))[0][:60]}", "before": "# 请参见原代码对应行", "after": "# 建议：重构代码以提升可读性", "explanation": "检测到代码质量问题。"},
            "dead_code": {"title": f"死代码: {issue.get('message', '').split(chr(10))[0][:60]}", "before": "# 请参见原代码对应行", "after": "# 删除不可达代码", "explanation": "检测到不可达代码。"},
        }
        suggestion = category_fallback.get(category)
        if not suggestion:
            return None

    suggestion = suggestion.copy()
    # 尝试提取实际代码行
    if line and code:
        lines = code.split("\n")
        if line <= len(lines):
            actual = lines[line - 1].rstrip()
            if actual.strip():
                suggestion["before"] = actual
    suggestion["line"] = line
    suggestion["severity"] = severity
    suggestion["rule_id"] = rule_id
    return suggestion


def _generate_report(issues: list[dict], score: float, engines: list[str]) -> dict:
    """生成审计报告。"""
    high = [i for i in issues if i.get("severity") == "high"]
    medium = [i for i in issues if i.get("severity") == "medium"]
    low = [i for i in issues if i.get("severity") == "low"]

    by_engine = {}
    for i in issues:
        src = i.get("source", "unknown")
        by_engine.setdefault(src, []).append(i)

    by_category = {}
    for i in issues:
        cat = i.get("category", "other")
        by_category.setdefault(cat, []).append(i)

    risk_categories = _analyze_risk_categories(issues)
    fix_priorities = _prioritize_fixes(issues)

    risk = "低风险" if score >= 80 else ("中风险" if score >= 50 else ("高风险" if score >= 20 else "极高风险"))

    return {
        "summary": {
            "score": score, "total_issues": len(issues),
            "high": len(high), "medium": len(medium), "low": len(low),
            "engines_used": engines,
            "security_issues": len([i for i in issues if i.get("category") == "security"]),
            "quality_issues": len([i for i in issues if i.get("category") == "quality"]),
            "dead_code_issues": len([i for i in issues if i.get("category") == "dead_code"]),
            "taint_issues": len([i for i in issues if i.get("category") == "taint"]),
        },
        "risk_level": risk,
        "by_engine": {e: {"count": len(ei), "high": len([i for i in ei if i.get("severity") == "high"])} for e, ei in by_engine.items()},
        "by_category": {c: len(ci) for c, ci in by_category.items()},
        "risk_categories": risk_categories,
        "fix_priorities": fix_priorities,
        "recommendations": _generate_recommendations(issues),
        "executive_summary": _executive_summary(score, issues, engines),
    }


def _analyze_risk_categories(issues: list[dict]) -> list[dict]:
    risk_map = {
        "taint": {"name": "数据流安全", "description": "检测到用户输入未经清洗直接传入危险函数", "impact": "可能导致 SQL 注入、命令注入等", "priority": "critical"},
        "security": {"name": "一般安全", "description": "检测到硬编码密钥、弱哈希等", "impact": "可能导致敏感信息泄露", "priority": "high"},
        "quality": {"name": "代码质量", "description": "检测到深层嵌套等问题", "impact": "增加维护成本", "priority": "medium"},
        "dead_code": {"name": "代码结构", "description": "检测到不可达代码", "impact": "误导开发者", "priority": "low"},
    }
    by_cat = {}
    for i in issues:
        by_cat.setdefault(i.get("category", "other"), []).append(i)
    result = []
    for cat, cat_issues in by_cat.items():
        info = risk_map.get(cat, {"name": cat, "description": "", "impact": "", "priority": "medium"})
        result.append({"category": cat, "name": info["name"], "description": info["description"],
                        "impact": info["impact"], "priority": info["priority"], "count": len(cat_issues),
                        "high": len([i for i in cat_issues if i.get("severity") == "high"]),
                        "rule_ids": list(set(i.get("rule_id", "") for i in cat_issues))})
    return result


def _prioritize_fixes(issues: list[dict]) -> list[dict]:
    severity_order = {"high": 0, "medium": 1, "low": 2}
    priority_labels = {0: "P0 - 立即修复", 1: "P1 - 尽快修复", 2: "P2 - 计划修复"}
    sorted_issues = sorted(issues, key=lambda i: severity_order.get(i.get("severity", ""), 3))
    return [{"line": i.get("line", 0), "severity": i.get("severity", ""), "rule_id": i.get("rule_id", ""),
             "category": i.get("category", ""), "message": i.get("message", "").split("\n")[0][:100],
             "priority": priority_labels.get(severity_order.get(i.get("severity", ""), 3), "P3"),
             "source": i.get("source", "")} for i in sorted_issues]


def _generate_recommendations(issues: list[dict]) -> list[str]:
    recs = []
    rule_ids = set(i.get("rule_id", "") for i in issues)
    categories = set(i.get("category", "") for i in issues)

    if "taint" in categories:
        recs.append("【数据流安全】发现污点传播路径：建议建立统一的输入验证层，SQL 查询必须使用参数化查询。")
    if "hardcoded_secret" in rule_ids:
        recs.append("【密钥管理】发现硬编码密钥：建议使用环境变量或密钥管理服务。")
    if "eval_usage" in rule_ids or "exec_usage" in rule_ids:
        recs.append("【代码注入】发现动态代码执行：应使用 ast.literal_eval() 或类型安全的替代方案。")
    if "weak_hash" in rule_ids:
        recs.append("【密码学安全】发现弱哈希算法：密码存储应使用 bcrypt/scrypt/argon2。")
    if "deep_nesting" in rule_ids:
        recs.append("【可读性】发现深层嵌套：建议使用 Guard Clause 降低嵌套深度。")
    if "bare_except" in rule_ids:
        recs.append("【异常处理】发现裸 except：应指定具体异常类型并记录日志。")
    if "unreachable_code" in rule_ids:
        recs.append("【死代码】发现不可达代码：建议立即删除。")

    high_count = len([i for i in issues if i.get("severity") == "high"])
    if high_count >= 3:
        recs.append(f"【紧急】发现 {high_count} 个高危问题：建议立即修复。")

    if not recs:
        recs.append("代码质量良好，建议保持现有编码规范。")
    return recs


def _executive_summary(score: float, issues: list[dict], engines: list[str]) -> str:
    high = len([i for i in issues if i.get("severity") == "high"])
    medium = len([i for i in issues if i.get("severity") == "medium"])
    low = len([i for i in issues if i.get("severity") == "low"])
    total = len(issues)

    if total == 0:
        return f"代码质量评分 {score:.0f}/100，未发现明显安全和质量问题。"

    risk = "低风险" if score >= 80 else ("中风险" if score >= 50 else ("高风险" if score >= 20 else "极高风险"))
    engines_str = "、".join(engines) if engines else "未知"

    parts = [f"代码质量评分 {score:.0f}/100（{risk}），"]
    parts.append(f"共发现 {total} 个问题（高危 {high}、中危 {medium}、低危 {low}）。")
    parts.append(f"通过 {engines_str} {len(engines)} 个分析引擎检测。")
    if high > 0:
        parts.append(f"存在 {high} 个高危安全问题，建议立即修复。")
    return "".join(parts)
