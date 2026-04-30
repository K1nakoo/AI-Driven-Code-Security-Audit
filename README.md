# AI-Driven Code Security Audit & Auto-Fix Agent

## 项目简介

AI驱动的代码安全审计与自动修复Agent，利用LLM（大语言模型）进行深度代码分析，检测安全漏洞并自动生成修复方案。支持多种编程语言和漏洞类型，提供完整的安全审计pipeline。

## 架构概览

```
+------------------+
|   CLI Interface  |  (click-based, 命令行入口)
+--------+---------+
         |
         v
+--------+---------+
|   Orchestrator   |  (编排器 - 核心调度引擎)
|  - 扫描调度        |
|  - Agent协调       |
|  - 结果聚合        |
+--------+---------+
         |
    +----+----+---------------------+
    |         |                     |
    v         v                     v
+---+--+ +----+-----+     +--------+--------+
|Static| |  LLM     |     | Supply Chain   |
|Scan  | | Analysis |     | Checker        |
+---+--+ +----+-----+     +--------+--------+
    |         |                     |
    |    +----+----+                |
    |    |         |                |
    v    v         v                v
+---+----+---+ +---+------+  +-----+-------+
| Semgrep    | | DeepSeek |  | Dep. Conf.  |
| CodeQL     | | OpenAI   |  | Vuln. Check |
| Regex      | | Local LLM|  | License     |
+------------+ +----------+  +-------------+
         |            |              |
         v            v              v
    +----+------------+--------------+----+
    |         Report Generator             |
    |  (JSON / HTML / Markdown)            |
    +-------------------+-----------------+
                        |
                        v
               +--------+---------+
               |    Fix Engine    |
               |  - Patch 生成     |
               |  - Git分支创建    |
               |  - Auto PR        |
               +--------+---------+
                        |
                        v
               +--------+---------+
               |   Validator       |
               |  - 测试验证        |
               |  - 构建检查        |
               +------------------+
```

## 功能特性

- **多语言支持**: Python, JavaScript, TypeScript, Java, Go, PHP
- **多引擎分析**: Semgrep规则匹配 + CodeQL查询 + 正则表达式 + LLM深度分析
- **LLM增强**: 利用GPT-4/DeepSeek进行上下文感知的漏洞检测和数据流分析
- **漏洞覆盖广**:
  - SQL注入 (CWE-89)
  - XSS跨站脚本 (CWE-79)
  - 命令注入 (CWE-78)
  - 路径遍历 (CWE-22)
  - 硬编码凭据 (CWE-798)
  - 不安全反序列化 (CWE-502)
  - 弱加密算法 (CWE-327)
  - SSRF服务端请求伪造 (CWE-918)
  - 原型污染 (CWE-1321)
  - NoSQL注入 (CWE-943)
  - 服务端模板注入 (CWE-1336)
- **自动修复**: 生成修复补丁，创建Git分支，支持dry-run模式
- **供应链检查**: 依赖混淆检测、已知漏洞数据库查询
- **多种报告格式**: JSON, HTML, Markdown
- **验证机制**: 修复后自动运行测试和构建验证

## 快速开始

### 环境要求

- Python >= 3.9
- Git (用于分支创建)
- [可选] Semgrep (用于静态分析)
- [可选] CodeQL CLI (用于高级查询)

### 安装

```bash
# 克隆项目
git clone <repository-url>
cd ai-code-audit

# 创建虚拟环境
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# 安装依赖
pip install -r requirements.txt

# 安装为可执行命令 (可选)
pip install -e .
```

### 配置

```bash
# 复制环境变量配置
cp .env.example .env

# 编辑.env文件，填入API Key
# LLM_API_KEY=your-actual-api-key

# 编辑配置文件 config/default.yaml
# 根据需要调整扫描参数
```

### 运行

```bash
# 安装后使用命令行
ai-audit scan /path/to/your/project

# 快速扫描 (仅高危漏洞)
ai-audit quick-scan ./

# 供应链检查
ai-audit supply-chain --path ./package.json

# 生成修复方案 (dry-run，不修改代码)
ai-audit fix --dry-run ./

# 执行修复 (自动应用，创建git分支)
ai-audit fix --apply ./

# 验证修复
ai-audit verify ./

# 生成报告
ai-audit report --format html ./reports/audit_result.json
```

## 使用示例

### 1. 完整扫描

```bash
# 扫描项目并生成JSON报告
ai-audit scan ./my-project \
    --output ./reports/scan_result.json \
    --format json \
    --severity medium
```

### 2. 快速扫描

```bash
# 仅检测高危和严重漏洞
ai-audit quick-scan ./my-project \
    --only critical,high \
    --timeout 60
```

### 3. 供应链检查

```bash
# 检查依赖是否安全
ai-audit supply-chain ./my-project \
    --check-dependency-confusion \
    --check-known-vulns \
    --output ./reports/supply_chain.json
```

### 4. 自动修复

```bash
# Dry-run模式 - 只生成补丁不应用
ai-audit fix ./my-project \
    --dry-run \
    --confidence 0.9

# 实际修复模式 - 创建Git分支并应用修复
ai-audit fix ./my-project \
    --apply \
    --create-branch \
    --confidence 0.85
```

### 5. 修复验证

```bash
# 运行测试验证修复
ai-audit verify ./my-project \
    --run-tests \
    --check-build \
    --test-framework pytest
```

## 支持的漏洞类型

| 漏洞类型 | CWE编号 | Python | JavaScript | Java | Go | PHP |
|---------|---------|--------|------------|------|----|-----|
| SQL注入 | CWE-89 | Yes | N/A | Yes | Yes | Yes |
| XSS | CWE-79 | Yes | Yes | Yes | Yes | Yes |
| 命令注入 | CWE-78 | Yes | Yes | Yes | Yes | Yes |
| 路径遍历 | CWE-22 | Yes | Yes | Yes | Yes | Yes |
| 硬编码凭据 | CWE-798 | Yes | Yes | Yes | Yes | Yes |
| 反序列化 | CWE-502 | Yes | Yes | Yes | Yes | Yes |
| 弱加密 | CWE-327 | Yes | Yes | Yes | Yes | Yes |
| SSRF | CWE-918 | Yes | Yes | Yes | No | Yes |
| 原型污染 | CWE-1321 | No | Yes | No | No | No |
| NoSQL注入 | CWE-943 | No | Yes | No | No | No |
| 模板注入(SSTI) | CWE-1336 | Yes | Yes | Yes | Yes | No |
| XML外部实体(XXE) | CWE-611 | Yes | Yes | Yes | Yes | Yes |

## 项目结构

```
ai-code-audit/
├── README.md                           # 项目文档(本文件)
├── setup.py                            # 安装脚本
├── requirements.txt                    # Python依赖
├── .env.example                        # 环境变量示例
├── .gitignore                          # Git忽略规则
├── config/
│   └── default.yaml                    # 主配置文件
├── src/
│   ├── __init__.py                     # 版本信息
│   ├── agents/                         # Agent模块
│   │   ├── base.py                     # Agent基类
│   │   ├── static_scan.py              # 静态扫描Agent
│   │   ├── llm_agent.py                # LLM分析Agent
│   │   └── fix_agent.py                # 修复Agent
│   ├── analyzers/                      # 分析器
│   │   ├── semgrep.py                  # Semgrep集成
│   │   ├── codeql.py                   # CodeQL集成
│   │   └── regex_scanner.py            # 正则扫描器
│   ├── llm/                            # LLM客户端
│   │   ├── base.py                     # LLM基类
│   │   ├── openai_client.py            # OpenAI客户端
│   │   └── deepseek_client.py          # DeepSeek客户端
│   ├── orchestrator/                   # 编排器
│   │   └── pipeline.py                 # 扫描管线
│   ├── fixing/                         # 修复引擎
│   │   ├── patch_generator.py          # 补丁生成
│   │   └── git_manager.py              # Git分支管理
│   ├── reporting/                      # 报告生成
│   │   ├── generator.py                # 报告生成器
│   │   └── templates/                  # 报告模板
│   ├── validation/                     # 验证模块
│   │   ├── test_runner.py              # 测试执行
│   │   └── build_checker.py            # 构建检查
│   ├── utils/                          # 工具函数
│   │   ├── config.py                   # 配置加载
│   │   ├── logger.py                   # 日志工具
│   │   └── file_utils.py               # 文件工具
│   └── cli/                            # 命令行接口
│       └── main.py                     # CLI入口
├── fixtures/                           # 测试用例
│   └── vulnerable_code/
│       ├── python/
│       │   ├── sql_injection.py         # SQL注入样本
│       │   ├── xss_vulnerable.py        # XSS样本
│       │   ├── command_injection.py     # 命令注入样本
│       │   ├── hardcoded_secrets.py     # 硬编码凭据样本
│       │   └── insecure_crypto.py       # 弱加密样本
│       └── javascript/
│           ├── xss_dom.js               # DOM-XSS样本
│           ├── nosql_injection.js       # NoSQL注入样本
│           └── prototype_pollution.js   # 原型污染样本
└── reports/                            # 报告输出目录
    └── .gitkeep
```

## 配置说明

### 主要配置项 (`config/default.yaml`)

```yaml
audit:
  scan:
    timeout: 300          # 单个文件扫描超时(秒)
    max_file_size: 10485760 # 跳过大于10MB的文件
    deep_analysis: true   # 启用LLM深度分析

llm:
  provider: "openai"     # LLM提供商
  model: "gpt-4"         # 模型名称
  temperature: 0.1       # 低温度提高一致性

fixing:
  auto_apply: false      # 不自动应用修复
  dry_run: true          # 仅生成补丁
  confidence_threshold: 0.8  # 修复置信度阈值

reporting:
  format: "json"         # 报告格式
  severity_filter: "low" # 最低报告等级
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `LLM_API_KEY` | LLM API密钥 | 无 |
| `LLM_API_BASE` | API端点 | `https://api.openai.com/v1` |
| `LLM_MODEL` | 模型名称 | `gpt-4` |
| `GIT_AUTHOR_NAME` | Git提交作者名 | `AI Audit Bot` |
| `GIT_AUTHOR_EMAIL` | Git提交邮箱 | `ai-audit@example.com` |

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest tests/ -v --cov=src

# 代码格式化
black src/ tests/

# 类型检查
mypy src/

# Lint检查
flake8 src/
```

## 许可

MIT License

---

**注意**: 本工具仅用于合法的安全审计目的。请确保您有权审计目标代码库。对于任何滥用行为，项目维护者不承担责任。

**WARNING**: This tool is for authorized security testing only. Always obtain proper permission before auditing any codebase.
