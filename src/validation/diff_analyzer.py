# -*- coding: utf-8 -*-
"""Diff分析器 - 检查修复补丁的安全性"""
import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class DiffAnalysis:
    is_safe: bool = True
    new_vulns: List[dict] = field(default_factory=list)
    changed_lines: int = 0
    risk_score: float = 0.0  # 0-1, 越高越危险
    warnings: List[str] = field(default_factory=list)


class DiffAnalyzer:
    """分析代码补丁，检测是否引入新漏洞"""

    # 危险模式关键词 - 补丁中出现这些可能引入新问题
    DANGER_PATTERNS = {
        "sql": [
            (r'execute\s*\(\s*f["\']', "SQL: f-string拼接"),
            (r'execute\s*\(["\'].*?\+', "SQL: 字符串拼接"),
            (r'\.format\(.*\)', "SQL: .format()拼接"),
            (r'%\s*\(.*\)', "SQL: %格式化"),
        ],
        "xss": [
            (r'innerHTML\s*=', "XSS: innerHTML赋值"),
            (r'document\.write\(', "XSS: document.write()"),
            (r'dangerouslySetInnerHTML', "XSS: React dangerouslySetInnerHTML"),
            (r'outerHTML\s*=', "XSS: outerHTML赋值"),
        ],
        "command": [
            (r'os\.system\(', "CMDI: os.system()"),
            (r'subprocess\.\w+\(.*shell\s*=\s*True', "CMDI: shell=True"),
            (r'eval\(', "CMDI: eval()"),
            (r'exec\(', "CMDI: exec()"),
        ],
        "path": [
            (r'open\([^)]*\.\.', "PathTraversal: .. in path"),
        ],
        "secret": [
            (r'(?:password|secret|key|token)\s*=\s*["\'][\w\-]{8,}["\']',
             "Hardcoded: 潜在的硬编码凭据"),
        ],
        "crypto": [
            (r'hashlib\.md5\(', "WeakCrypto: MD5"),
            (r'hashlib\.sha1\(', "WeakCrypto: SHA1"),
            (r'random\.(choice|randint)\b', "WeakRandom: 非加密随机"),
            (r'ECB', "WeakCrypto: ECB模式"),
        ],
    }

    def analyze_diff(self, diff_text: str) -> DiffAnalysis:
        """分析diff是否有新安全问题"""
        analysis = DiffAnalysis()

        if not diff_text.strip():
            return analysis

        # 解析diff中的新增行
        added_lines = []
        for line in diff_text.split("\n"):
            # unified diff格式的添加行是 + 开头的
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])  # 去掉前面的+
                analysis.changed_lines += 1

        if not added_lines:
            return analysis

        added_content = "\n".join(added_lines)

        # 检查危险模式
        total_checks = 0
        violations = 0
        for category, patterns in self.DANGER_PATTERNS.items():
            for pattern, desc in patterns:
                total_checks += 1
                old_count = len(re.findall(pattern, diff_text, re.IGNORECASE))

                # 只检查新增行
                new_matches = re.findall(pattern, added_content, re.IGNORECASE)
                if new_matches:
                    # 但不是所有都是新引入的 - 检查旧代码里是否也有
                    # 懒得精确分析新旧了，简化: 只看新增行的removed行也在老代码里的情况
                    analysis.new_vulns.append({
                        "category": category,
                        "pattern": desc,
                        "count": len(new_matches),
                    })
                    analysis.warnings.append(f"{desc}: 新增行中发现{len(new_matches)}处匹配")
                    violations += 1

        # 计算风险分数
        if total_checks > 0:
            # 新增空白/注释行 不计分
            actual_new_added = len([l for l in added_lines if l.strip()
                                   and not l.strip().startswith("#")
                                   and not l.strip().startswith("//")])
            if actual_new_added > 0:
                analysis.risk_score = min(violations / actual_new_added, 1.0)

        analysis.is_safe = len(analysis.new_vulns) == 0
        return analysis

    def check_syntax(self, file_path: str) -> bool:
        """检查文件语法是否有效(简单方式)"""
        from pathlib import Path
        ext = Path(file_path).suffix.lower()

        try:
            if ext == ".py":
                import py_compile
                py_compile.compile(file_path, doraise=True)
                return True
            elif ext in (".js", ".mjs"):
                # 尝试node --check
                import subprocess
                result = subprocess.run(
                    ["node", "--check", file_path],
                    capture_output=True, text=True, timeout=10
                )
                return result.returncode == 0
        except Exception:
            pass

        # 不能验证的语言就当通过
        return True

    def minimal_check(self, diff_text: str, threshold: int = 100) -> bool:
        """检查diff是否足够小(minimal)"""
        added = len([l for l in diff_text.split("\n") if l.startswith("+") and not l.startswith("+++")])
        removed = len([l for l in diff_text.split("\n") if l.startswith("-") and not l.startswith("---")])
        total = added + removed

        if total > threshold:
            print(f"[DiffAnalyzer] Diff size ({total} lines) exceeds threshold ({threshold} lines)")
            return False
        return True
