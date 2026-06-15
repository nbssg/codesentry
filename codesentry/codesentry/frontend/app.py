"""CodeSentry Streamlit 前端 — 暗色高级主题。"""

import streamlit as st
import requests

BACKEND = "http://localhost:8000"

st.set_page_config(page_title="CodeSentry", page_icon="🛡️", layout="wide")

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
    border-radius: 10px !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    padding: 10px 24px !important;
}
.stTabs [aria-selected="true"] {
    background: rgba(59, 130, 246, 0.15) !important;
    color: #93c5fd !important;
}

/* ── Expander ── */
.streamlit-expanderHeader {
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    border-radius: 10px !important;
    background: rgba(30, 41, 59, 0.4) !important;
    border: 1px solid rgba(148, 163, 184, 0.06) !important;
}

/* ── Text Area ── */
.stTextArea textarea {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
    line-height: 1.6 !important;
    background: rgba(15, 23, 42, 0.8) !important;
    border: 1px solid rgba(148, 163, 184, 0.1) !important;
    border-radius: 12px !important;
    color: #e2e8f0 !important;
}

/* ── Code Block ── */
.stCodeBlock code {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.82rem !important;
}

/* ── 分割线 ── */
hr {
    border: none !important;
    border-top: 1px solid rgba(148, 163, 184, 0.08) !important;
    margin: 1.5rem 0 !important;
}

/* ── 指标卡片 ── */
.metric-card {
    background: rgba(30, 41, 59, 0.5);
    border: 1px solid rgba(148, 163, 184, 0.06);
    border-radius: 12px;
    padding: 16px;
    text-align: center;
}
.metric-val {
    font-family: 'Inter', sans-serif;
    font-size: 1.6rem; font-weight: 700;
    color: #f1f5f9;
}
.metric-lbl {
    font-size: 0.7rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 2px;
}

/* ── 风险标签 ── */
.risk-badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 8px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.04em;
}
.risk-low    { background: rgba(52,211,153,0.12); color: #34d399; }
.risk-medium { background: rgba(251,191,36,0.12); color: #fbbf24; }
.risk-high   { background: rgba(251,146,60,0.12); color: #fb923c; }
.risk-extreme{ background: rgba(248,113,113,0.12); color: #f87171; }

/* ── 修复结果 ── */
.fix-card {
    background: rgba(30, 41, 59, 0.4);
    border: 1px solid rgba(52, 211, 153, 0.15);
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 12px;
}

/* ── Streamlit 内部文字覆盖 ── */
h1, h2, h3, h4, h5, h6, p, span, label, div {
    font-family: 'Inter', sans-serif;
}
</style>
""", unsafe_allow_html=True)

# ========== 页头 ==========
st.markdown("""
<div style="margin-bottom:1.5rem">
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:6px">
        <span class="hero-title">CodeSentry</span>
        <span class="hero-badge">v1.1</span>
    </div>
    <div class="hero-sub">基于自研三大分析引擎的 AI 代码安全审查系统 · 华为云 CodeArts 开发</div>
</div>
""", unsafe_allow_html=True)

# ========== Tab ==========
tab_scan, tab_arch, tab_about = st.tabs(["🔍 智能扫描", "🏗️ 系统架构", "📖 关于项目"])

# ========== 架构页 ==========
with tab_arch:
    st.markdown("""
    <div class="glass-card">
        <div style="text-align:center;margin-bottom:20px">
            <span style="font-size:1.4rem;font-weight:700;color:#e2e8f0">三大自研分析引擎</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("""
        <div class="glass-card" style="border-top:2px solid #34d399">
            <div style="text-align:center">
                <div style="font-size:2rem;margin-bottom:8px">🔍</div>
                <div style="font-size:1rem;font-weight:700;color:#34d399;margin-bottom:12px">规则引擎</div>
                <div style="font-size:0.8rem;color:#94a3b8;line-height:1.7">
                    RuleEngine · 12 条内置规则<br>
                    基于 AST 的模式检测<br><br>
                    <span style="color:#64748b">
                    · 硬编码密钥<br>
                    · eval/exec 使用<br>
                    · 弱哈希算法<br>
                    · 深层嵌套<br>
                    · 过长函数<br>
                    · 可变全局状态
                    </span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown("""
        <div class="glass-card" style="border-top:2px solid #fb923c">
            <div style="text-align:center">
                <div style="font-size:2rem;margin-bottom:8px">🔬</div>
                <div style="font-size:1rem;font-weight:700;color:#fb923c;margin-bottom:12px">污点分析引擎</div>
                <div style="font-size:0.8rem;color:#94a3b8;line-height:1.7">
                    TaintAnalyzer · 数据流追踪<br>
                    追踪输入→危险函数完整路径<br><br>
                    <span style="color:#64748b">
                    · 污点源识别<br>
                    · 危险汇聚点检测<br>
                    · 跨函数传播追踪<br>
                    · 清洗函数置信度<br>
                    · 调用图构建
                    </span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        st.markdown("""
        <div class="glass-card" style="border-top:2px solid #a78bfa">
            <div style="text-align:center">
                <div style="font-size:2rem;margin-bottom:8px">📊</div>
                <div style="font-size:1rem;font-weight:700;color:#a78bfa;margin-bottom:12px">控制流分析引擎</div>
                <div style="font-size:0.8rem;color:#94a3b8;line-height:1.7">
                    CFGAnalyzer · 控制流图<br>
                    构建执行路径图检测结构性问题<br><br>
                    <span style="color:#64748b">
                    · 不可达代码检测<br>
                    · 裸 except 检测<br>
                    · 异常吞没检测<br>
                    · 返回值不一致<br>
                    · 危险异常处理
                    </span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # 对比表
    st.markdown("""
    <div class="glass-card">
        <div style="font-size:1rem;font-weight:700;color:#e2e8f0;margin-bottom:16px">与传统工具对比</div>
        <table style="width:100%;border-collapse:separate;border-spacing:0;font-size:0.82rem">
            <tr style="background:rgba(59,130,246,0.08)">
                <td style="padding:10px 14px;border-radius:8px 0 0 0;color:#94a3b8;font-weight:600">维度</td>
                <td style="padding:10px 14px;color:#94a3b8;font-weight:600">Bandit / Semgrep</td>
                <td style="padding:10px 14px;border-radius:0 8px 0 0;color:#60a5fa;font-weight:600">CodeSentry</td>
            </tr>
            <tr style="border-top:1px solid rgba(148,163,184,0.06)">
                <td style="padding:10px 14px;color:#94a3b8">分析方式</td>
                <td style="padding:10px 14px;color:#64748b">模式匹配</td>
                <td style="padding:10px 14px;color:#34d399;font-weight:500">数据流追踪 + 控制流图</td>
            </tr>
            <tr style="border-top:1px solid rgba(148,163,184,0.06)">
                <td style="padding:10px 14px;color:#94a3b8">SQL 注入</td>
                <td style="padding:10px 14px;color:#64748b">检测拼接模式</td>
                <td style="padding:10px 14px;color:#34d399;font-weight:500">追踪完整数据流路径</td>
            </tr>
            <tr style="border-top:1px solid rgba(148,163,184,0.06)">
                <td style="padding:10px 14px;color:#94a3b8">跨函数分析</td>
                <td style="padding:10px 14px;color:#64748b">不支持</td>
                <td style="padding:10px 14px;color:#34d399;font-weight:500">调用图追踪参数传递</td>
            </tr>
            <tr style="border-top:1px solid rgba(148,163,184,0.06)">
                <td style="padding:10px 14px;color:#94a3b8">不可达代码</td>
                <td style="padding:10px 14px;color:#64748b">不检测</td>
                <td style="padding:10px 14px;color:#34d399;font-weight:500">CFG 分析自动检测</td>
            </tr>
            <tr style="border-top:1px solid rgba(148,163,184,0.06)">
                <td style="padding:10px 14px;border-radius:0 0 0 8px;color:#94a3b8">自动修复</td>
                <td style="padding:10px 14px;color:#64748b">不支持</td>
                <td style="padding:10px 14px;border-radius:0 0 8px 0;color:#34d399;font-weight:500">一键修复 + 下载</td>
            </tr>
        </table>
    </div>
    """, unsafe_allow_html=True)

# ========== 关于页 ==========
with tab_about:
    st.markdown("""
    <div class="glass-card">
        <div style="font-size:1.3rem;font-weight:700;color:#e2e8f0;margin-bottom:16px">关于 CodeSentry</div>
        <div style="color:#94a3b8;line-height:1.8;font-size:0.9rem">
            CodeSentry 是一个完全自研的代码安全审查系统，核心分析能力不依赖任何第三方扫描工具或外部大模型。
        </div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
        <div class="glass-card" style="text-align:center">
            <div style="font-size:2rem">🧬</div>
            <div style="font-size:0.95rem;font-weight:600;color:#e2e8f0;margin:8px 0">污点分析</div>
            <div style="font-size:0.78rem;color:#64748b;line-height:1.6">
                追踪用户输入在代码中的传播路径，检测数据从进入程序到被危险使用之间的完整链路
            </div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown("""
        <div class="glass-card" style="text-align:center">
            <div style="font-size:2rem">🕸️</div>
            <div style="font-size:0.95rem;font-weight:600;color:#e2e8f0;margin:8px 0">控制流图</div>
            <div style="font-size:0.78rem;color:#64748b;line-height:1.6">
                构建代码执行路径图，检测不可达代码、异常处理缺陷和结构性问题
            </div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown("""
        <div class="glass-card" style="text-align:center">
            <div style="font-size:2rem">⚙️</div>
            <div style="font-size:0.95rem;font-weight:600;color:#e2e8f0;margin:8px 0">规则引擎</div>
            <div style="font-size:0.78rem;color:#64748b;line-height:1.6">
                可扩展的 AST 模式匹配，内置 12 条安全检测规则，支持自定义扩展
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="glass-card" style="margin-top:16px">
        <div style="font-size:0.9rem;font-weight:600;color:#e2e8f0;margin-bottom:8px">开发工具</div>
        <div style="color:#94a3b8;font-size:0.85rem;line-height:1.7">
            华为云 CodeArts 代码智能体 · 用于辅助开发、调试和代码审查
        </div>
    </div>
    """, unsafe_allow_html=True)

# ========== 扫描页 ==========
with tab_scan:
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

    # 扫描
    if do_scan:
        with st.spinner("三大引擎分析中..."):
            resp = requests.post(f"{BACKEND}/scan-text", json={"code": code}, timeout=30)
            if resp.status_code != 200:
                st.error("后端服务未启动")
                st.stop()
            result = resp.json()
            st.session_state["scan_result"] = result
            st.session_state["code"] = code
            st.session_state.pop("fix_suggestions", None)
            st.session_state.pop("audit_report", None)
            st.session_state.pop("auto_fix_result", None)

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
                        r = requests.post(f"{BACKEND}/fix-suggestions", json={"code": code, "issues": result["issues"]}, timeout=15)
                        if r.status_code == 200:
                            fix_suggestions = r.json().get("suggestions", [])
                            st.session_state["fix_suggestions"] = fix_suggestions

            with btn_c2:
                if st.button("🔧 一键修复", type="primary", use_container_width=True):
                    with st.spinner("自动修复中..."):
                        r = requests.post(f"{BACKEND}/auto-fix", json={"code": code, "issues": result["issues"]}, timeout=30)
                        if r.status_code == 200:
                            auto_fix_result = r.json()
                            st.session_state["auto_fix_result"] = auto_fix_result

            with btn_c3:
                if st.button("📋 审计报告", type="secondary", use_container_width=True):
                    with st.spinner("生成中..."):
                        r = requests.post(f"{BACKEND}/report", json={"issues": result["issues"], "score": score, "engines_used": engines}, timeout=15)
                        if r.status_code == 200:
                            audit_report = r.json()
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
                        <div style="font-size:1rem;font-weight:700;color:#34d399;margin-bottom:4px">🔧 已自动修复 {len(applied)} 个问题</div>
                    </div>
                    """, unsafe_allow_html=True)

                    for fix in applied:
                        st.markdown(f"""
                        <div class="fix-card">
                            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                                <span class="sev-badge sev-badge-low">FIXED</span>
                                <span style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:#94a3b8">行{fix['line']}</span>
                                <span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#64748b">{fix['rule_id']}</span>
                            </div>
                            <div style="font-size:0.82rem;color:#94a3b8;margin-bottom:10px">{fix['description']}</div>
                        </div>
                        """, unsafe_allow_html=True)
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
                    for engine, stats in audit_report["by_engine"].items():
                        st.markdown(f"""
                        <div style="display:flex;align-items:center;gap:8px;padding:4px 0">
                            <span class="engine-tag tag-{"taint" if "taint" in engine else "cfg" if "cfg" in engine else "rule"}" style="margin:0;padding:2px 10px;font-size:0.65rem">{engine}</span>
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
