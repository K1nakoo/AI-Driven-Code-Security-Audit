# -*- coding: utf-8 -*-
"""补丁生成器 - 模板优先 + LLM兜底"""
import difflib
from dataclasses import dataclass
from typing import Optional, Dict, Any

from .templates import FixTemplateEngine, FixTemplate


@dataclass
class FixResult:
    success: bool
    patch_content: str = ""        # 修复后的完整代码
    diff: str = ""                 # unified diff
    explanation: str = ""          # 修复原因说明
    confidence: float = 0.0        # 置信度
    method: str = "none"           # template / llm / manual


class PatchGenerator:
    """生成代码安全修复补丁"""

    def __init__(self, llm_client=None, config=None):
        self.llm_client = llm_client
        self.config = config or {}
        self.template_engine = FixTemplateEngine()
        self.confidence_threshold = self.config.get("confidence_threshold", 0.8)

    def generate_fix(
        self,
        finding: dict,
        file_content: str,
        language: str = "python",
        use_llm: bool = True,
    ) -> FixResult:
        """为核心方法: 为漏洞生成修复补丁"""
        rule_id = finding.get("rule_id", "")
        # print(f"[PatchGen] 尝试修复: {rule_id}")  # debug

        # 1. 先试模板修复
        template_fix = self._template_fix(finding, file_content, language)
        if template_fix and template_fix.success and template_fix.confidence >= self.confidence_threshold:
            template_fix.method = "template"
            return template_fix

        # 2. 模板不够好 → 用LLM生成
        if use_llm and self.llm_client and self.llm_client.is_available:
            llm_fix = self._llm_fix(finding, file_content, language)
            if llm_fix and llm_fix.success:
                llm_fix.method = "llm"
                return llm_fix

        # 3. 兜底: 返回模板建议(即使置信度低)
        if template_fix:
            template_fix.method = "template_low_confidence"
            return template_fix

        return FixResult(
            success=False,
            explanation=f"无法为 {rule_id} 生成修复",
            method="none",
        )

    def _template_fix(self, finding: dict, file_content: str, language: str) -> Optional[FixResult]:
        """尝试用预定义模板修复"""
        rule_id = finding.get("rule_id", "")
        templates = self.template_engine.find_templates(rule_id, language)

        if not templates:
            # print(f"[PatchGen] 无匹配模板: {rule_id}")
            return None

        # 取最佳匹配
        best = templates[0]
        fixed_code = self.template_engine.apply_template(best, file_content, {
            "rule_id": rule_id,
            "file_path": finding.get("file_path", ""),
        })

        diff = self.template_engine.generate_diff(
            file_content, fixed_code, finding.get("file_path", "")
        )

        return FixResult(
            success=fixed_code != file_content,
            patch_content=fixed_code,
            diff=diff,
            explanation=f"{best.guidance}\n\n修复模式: {best.name}",
            confidence=0.85 if fixed_code != file_content else 0.3,
        )

    def _llm_fix(self, finding: dict, original_code: str, language: str) -> Optional[FixResult]:
        """用LLM生成修复"""
        try:
            result = self.llm_client.generate_fix(finding, original_code, language)
        except Exception as e:
            print(f"[PatchGen] LLM修复失败: {e}")
            return None

        if result.get("error"):
            return None

        fixed_code = result.get("fixed_code", original_code)
        diff = result.get("diff", "")
        if not diff and fixed_code != original_code:
            diff = self.template_engine.generate_diff(original_code, fixed_code)

        return FixResult(
            success=True,
            patch_content=fixed_code,
            diff=diff,
            explanation=result.get("explanation", ""),
            confidence=result.get("confidence", 0.7),
        )

    def apply_patch(self, file_path: str, patch_content: str) -> bool:
        """将修复写入文件(会覆盖原文件!)"""
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(patch_content)
            print(f"[PatchGen] 已修复: {file_path}")
            return True
        except Exception as e:
            print(f"[PatchGen] 写入失败: {e}")
            return False

    def generate_diff_only(self, original: str, fixed: str, file_path: str = "") -> str:
        """只生成diff, 不改文件"""
        return self.template_engine.generate_diff(original, fixed, file_path)

    def batch_generate(
        self,
        findings: list,
        files_content: Dict[str, str],
        language: str = "python",
    ) -> list:
        """批量生成修复"""
        results = []
        for finding in findings:
            file_path = finding.get("file_path", "")
            content = files_content.get(file_path, "")
            if content:
                result = self.generate_fix(finding, content, language)
                results.append(result)
        return results
