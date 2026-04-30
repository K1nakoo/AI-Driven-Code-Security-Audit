# -*- coding: utf-8 -*-
"""修复模板引擎 — 常见漏洞的固定修复模式"""
import re
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class FixTemplate:
    name: str
    description: str
    language: str
    severity: str
    pattern_before: str   # 待匹配的漏洞模式(regex)
    pattern_after: str    # 修复后的代码(可带{group}引用)
    guidance: str         # 中文修复指导


# --- 预定义修复模板 ---
FIX_TEMPLATES = [
    # === SQL注入修复 ===
    FixTemplate(
        name="sql_injection_python_fstring",
        description="Python f-string SQL注入 → 参数化查询",
        language="python",
        severity="critical",
        pattern_before=r'''([\w.]+)\.execute\(f".*?\{(.*?)\}.*?"\)''',
        pattern_after=r'''\1.execute("SELECT ... WHERE col=? AND col=?", (\2,))  # FIXED: 参数化查询''',
        guidance="用参数化查询替代字符串拼接。cursor.execute(sql, (param1, param2)) 这种写法是安全的。",
    ),
    FixTemplate(
        name="sql_injection_python_concat",
        description="Python 字符串拼接SQL → 参数化查询",
        language="python",
        severity="critical",
        # 这个pattern不好精确匹配，用suggestion的方式
        pattern_before=r'''.execute\(["'](.+?)\+\s*(.+?)\+''',
        pattern_after=r'''.execute("USE PARAMETERIZED QUERY", params)  # FIXED''',
        guidance="永远不要用 + 拼接SQL语句。使用 ? 或 %s 占位符 + 参数元组。",
    ),
    # === XSS修复 ===
    FixTemplate(
        name="xss_python_flask_render",
        description="Flask XSS → 使用escape()或render_template",
        language="python",
        severity="high",
        pattern_before=r"return\s+f[\"'](.+?){(\w+)}",
        pattern_after=r"""return f"escape({{\1}})"  # FIXED: 需要先 from markupsafe import escape""",
        guidance="对用户输入使用escape()函数进行HTML实体编码。或使用Jinja2模板的自动转义。",
    ),
    FixTemplate(
        name="xss_js_innerhtml",
        description="JS innerHTML XSS → textContent或DOMPurify",
        language="javascript",
        severity="high",
        pattern_before=r"(\w+)\.innerHTML\s*=\s*(.+)",
        pattern_after=r"\1.textContent = \2  // FIXED: textContent是安全的",
        guidance="避免使用innerHTML。用textContent设置文本, 或用DOMPurify.sanitize()清理HTML。",
    ),
    # === 命令注入修复 ===
    FixTemplate(
        name="command_injection_os_system",
        description="os.system注入 → subprocess.run(列表参数)",
        language="python",
        severity="critical",
        pattern_before=r"os\.system\((.+)\)",
        pattern_after=r"# FIXED: 用subprocess.run替代os.system\nsubprocess.run([\"cmd\", \"arg\"], shell=False)",
        guidance="os.system() 有命令注入风险。改用 subprocess.run([cmd, arg1, arg2], shell=False)。",
    ),
    FixTemplate(
        name="command_injection_subprocess_shell",
        description="subprocess shell=True → shell=False + list args",
        language="python",
        severity="critical",
        pattern_before=r"subprocess\.\w+\((.+),\s*shell\s*=\s*True",
        pattern_after=r"subprocess.run(SHLEX_QUOTE_ARGS, shell=False)  # FIXED",
        guidance="shell=True + 用户输入 = 命令注入。使用列表参数 + shell=False。",
    ),
    # === 路径遍历修复 ===
    FixTemplate(
        name="path_traversal_open",
        description="文件路径未验证 → os.path.abspath校验",
        language="python",
        severity="high",
        pattern_before=r"open\((.+)\)",
        pattern_after=r"""# FIXED: 路径白名单校验
safe_path = os.path.abspath(os.path.join(BASE_DIR, user_input))
if not safe_path.startswith(BASE_DIR):
    raise ValueError("Invalid path")
open(safe_path)""",
        guidance="用os.path.abspath()解析路径，再用.startswith()校验是否在允许目录内。",
    ),
    # === 硬编码凭据修复 ===
    FixTemplate(
        name="hardcoded_secret_env",
        description="硬编码密码 → 环境变量",
        language="python",
        severity="high",
        pattern_before=r'''(\w+)\s*=\s*["']([\w\-]{8,})["']\s*#\s*(?:密码|password|secret|key|token)''',
        pattern_after=r'''\1 = os.environ.get("\1", "")  # FIXED: 从环境变量读取''',
        guidance="敏感凭据应从环境变量读取: os.environ.get('SECRET_KEY')。永远不要硬编码在代码里。",
    ),
    # === 反序列化修复 ===
    FixTemplate(
        name="deserialization_pickle",
        description="pickle.loads → json.loads",
        language="python",
        severity="critical",
        pattern_before=r"pickle\.loads?\((.+)\)",
        pattern_after="# FIXED: 用json替代pickle (仅限JSON-safe数据)\njson.loads(data)",
        guidance="pickle可执行任意代码。如果数据格式是JSON兼容的，用json.loads()替代。",
    ),
    FixTemplate(
        name="deserialization_yaml",
        description="yaml.load → yaml.safe_load",
        language="python",
        severity="critical",
        pattern_before=r"yaml\.load\((.+)\)",
        pattern_after=r"yaml.safe_load(\1)  # FIXED: safe_load防止任意代码执行",
        guidance="yaml.load() 可构造Python对象。改用yaml.safe_load()，仅解析基本类型。",
    ),
    # === 弱加密修复 ===
    FixTemplate(
        name="weak_hash_md5",
        description="MD5 → SHA256",
        language="python",
        severity="medium",
        pattern_before=r"hashlib\.md5\((.+)\)\s*\.hexdigest\(\)",
        pattern_after=r"hashlib.sha256(\1).hexdigest()  # FIXED: SHA256代替MD5",
        guidance="MD5/SHA1已被攻破。密码hash用bcrypt/scrypt/argon2；完整性校验用SHA256+。",
    ),
    FixTemplate(
        name="insecure_random",
        description="random → secrets模块",
        language="python",
        severity="medium",
        pattern_before=r"random\.(choice|randint|randrange)\((.*)\)\s*#\s*(?:token|key|secret|密码|加密|auth)",
        pattern_after=r"secrets.\1(\2)  # FIXED: secrets模块适合安全场景",
        guidance="random模块不是密码学安全的。安全场景(如生成token)必须用secrets模块。",
    ),
]


class FixTemplateEngine:
    """修复模板引擎 - 匹配漏洞模式并生成修复代码"""

    def __init__(self):
        self.templates = FIX_TEMPLATES
        # self._compiled = {}  # 缓存编译后的regex - 实验性，暂时不用

    def get_template(self, rule_id: str) -> Optional[FixTemplate]:
        """根据rule_id匹配最合适的修复模板"""
        rule_lower = rule_id.lower()

        # 模糊匹配: 检查rule_id中是否包含模板相关的关键词
        for template in self.templates:
            name_lower = template.name.lower()
            # 例如 rule_id = "python-sql-injection" 匹配 sql_injection 模板
            if any(kw in rule_lower for kw in name_lower.split("_") if len(kw) > 2):
                return template

        return None

    def find_templates(self, rule_id: str, language: str = "") -> list:
        """找到所有匹配的模板(按匹配度排序)"""
        matches = []
        rule_lower = rule_id.lower()

        for t in self.templates:
            if language and t.language != language:
                continue
            # 简单打分
            score = 0
            t_kws = set(t.name.lower().split("_"))
            r_kws = set(rule_lower.replace("-", "_").split("_"))
            matched = t_kws & r_kws
            score = len(matched)
            if score > 0:
                matches.append((score, t))

        matches.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in matches]

    def apply_template(
        self,
        template: FixTemplate,
        original_code: str,
        context: Dict[str, Any] = None,
    ) -> str:
        """应用模板生成修复代码"""
        context = context or {}

        # 尝试regex替换
        try:
            fixed = re.sub(template.pattern_before, template.pattern_after, original_code)
            if fixed != original_code:
                return fixed
        except re.error as e:
            print(f"[Template] regex错误: {e}")

        # Regex没匹配上 → 返回模板指导 + 原始代码(标记需要手动修复)
        return f"""# ======== NEEDS MANUAL FIX ========
# 漏洞类型: {template.name}
# 修复指导: {template.guidance}
# ======== ORIGINAL CODE ========
{original_code}
# ======== TODO: 手动应用上述修复 ========
"""

    def generate_diff(self, original: str, fixed: str, file_path: str = "") -> str:
        """生成unified diff"""
        import difflib
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{file_path or 'original'}",
            tofile=f"b/{file_path or 'fixed'}",
            lineterm="",
        )
        return "\n".join(diff)
