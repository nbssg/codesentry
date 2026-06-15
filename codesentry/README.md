# CodeSentry — 自研代码安全分析引擎

完全自研的代码安全审查系统，核心分析能力不依赖任何第三方扫描工具或外部大模型。

## 三大自研引擎

### 1. 规则引擎 (RuleEngine)
基于 AST 的 12 条内置检测规则，覆盖：
- 硬编码密钥、eval/exec、裸except、弱哈希
- 长函数、深嵌套、全局可变状态、硬编码IP
- 伪随机数、文件未使用with、assert验证、不可达代码

### 2. 污点分析引擎 (TaintEngine)
**核心创新**：追踪"用户输入 → 危险函数"的数据流路径。

- 识别污点源：函数参数、input()、request.args 等
- 追踪传播：赋值、字符串拼接、f-string、函数调用
- 检测汇聚：SQL执行、命令执行、eval、文件操作
- 清洗检测：int()、shlex.quote、html.escape 等降低风险

### 3. 控制流分析引擎 (CFGEngine)
构建代码控制流图，检测结构性缺陷：
- 不可达代码（return/raise 之后的代码）
- 异常处理缺陷（裸except、异常吞没）
- 返回值不一致

## 快速启动

```bash
pip install -r requirements.txt

# 启动后端
cd backend && uvicorn main:app --reload --port 8000

# 启动前端
cd frontend && streamlit run app.py
```

## 项目结构

```
codesentry/
├── engine/              # 自研分析引擎（核心）
│   ├── __init__.py
│   ├── models.py        # 数据模型
│   ├── analyzer.py      # 统一分析入口
│   ├── rules.py         # 规则引擎（12条规则）
│   ├── taint.py         # 污点分析引擎
│   └── cfg.py           # 控制流分析引擎
├── backend/
│   └── main.py          # FastAPI 接口
├── frontend/
│   └── app.py           # Streamlit 界面
├── samples/
│   └── vulnerable.py    # 测试代码
├── requirements.txt
└── README.md
```

## API

| 接口 | 说明 |
|------|------|
| `POST /scan-text` | 扫描代码文本 |
| `POST /scan` | 扫描上传的文件 |
| `POST /fix-suggestions` | 基于规则的修复建议 |
| `POST /report` | 结构化审计报告 |

## 技术栈

- **分析引擎**: 纯 Python，基于 ast 模块，完全自研
- **后端**: FastAPI
- **前端**: Streamlit
- **开发工具**: 华为云 CodeArts 代码智能体
