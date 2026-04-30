# -*- coding: utf-8 -*-
"""修复生成Agent — 生成并应用安全修复"""
import time
import os
from typing import Dict, Any, List

from .base import BaseAgent, AgentResult
from ..fixing.patch_generator import PatchGenerator, FixResult
from ..fixing.git_ops import GitOperator


class FixGeneratorAgent(BaseAgent):
    """代码修复Agent - 生成补丁并提交"""

    @property
    def agent_name(self) -> str:
        return "FixGeneratorAgent"

    def __init__(self, config=None, knowledge_graph=None, llm_client=None):
        super().__init__(config, knowledge_graph, llm_client)
        self.patch_gen = PatchGenerator(llm_client, config.get("fixing", {}) if config else {})
        self.git = GitOperator()
        self.dry_run = config.get("fixing", {}).get("dry_run", True) if config else True
        self.auto_apply = config.get("fixing", {}).get("auto_apply", False) if config else False
        self.confidence_threshold = config.get("fixing", {}).get("confidence_threshold", 0.8) if config else 0.8

    def run(self, task) -> AgentResult:
        target = task.get("target_path", ".")
        findings = task.get("findings", [])
        start_t = time.perf_counter()

        if not findings:
            self._log("info", "No findings to fix")
            return AgentResult(success=True, agent_name=self.agent_name)

        self._log("info", f"开始修复 {len(findings)} 个漏洞(DryRun={self.dry_run})")

        # 按文件分组
        findings_by_file = {}
        for f in findings:
            fp = f.get("file_path", "unknown")
            findings_by_file.setdefault(fp, []).append(f)

        all_fix_results = []
        errors = []
        applied_count = 0

        for file_path, file_findings in findings_by_file.items():
            # 读取文件内容
            original_content = ""
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    original_content = f.read()
            except FileNotFoundError:
                self._log("warning", f"文件不存在: {file_path}")
                continue
            except Exception as e:
                errors.append({"file": file_path, "error": str(e)})
                continue

            language = self._detect_language(file_path)

            for finding in file_findings:
                fix = self._generate_fix_for_finding(finding, original_content, file_path, language)
                all_fix_results.append(fix)

                if fix.success and fix.confidence >= self.confidence_threshold:
                    if not self.dry_run and (self.auto_apply or task.get("apply_fixes")):
                        applied = self._apply_fix(file_path, fix)
                        if applied:
                            applied_count += 1
                            self._log("info", f"已应用修复: {file_path} ({finding.get('rule_id')})")

            # 进度
            # print(f"[FixGen] 文件进度: {file_path}")  # debug

        duration = time.perf_counter() - start_t
        self._log("info", f"修复完成: {len(all_fix_results)} 个, 应用 {applied_count} 个")

        return AgentResult(
            success=True,
            agent_name=self.agent_name,
            findings=[
                {"fix": r.patch_content[:200], "diff": r.diff[:200],
                 "confidence": r.confidence, "method": r.method}
                for r in all_fix_results if r.success
            ],
            errors=errors,
            metadata={
                "total_findings": len(findings),
                "fixes_generated": len(all_fix_results),
                "fixes_applied": applied_count,
                "dry_run": self.dry_run,
            },
            duration=duration,
        )

    def _generate_fix_for_finding(
        self, finding: dict, file_content: str, file_path: str, language: str
    ) -> FixResult:
        """为单个finding生成修复"""
        return self.patch_gen.generate_fix(
            finding=finding,
            file_content=file_content,
            language=language,
            use_llm=bool(self.llm_client and self.llm_client.is_available),
        )

    def _apply_fix(self, file_path: str, fix: FixResult) -> bool:
        """应用修复到文件系统"""
        if self.dry_run:
            print(f"[FixGen] DRY-RUN: 跳过写入 {file_path}")
            return False

        try:
            # 写入修复后的代码
            return self.patch_gen.apply_patch(file_path, fix.patch_content)
        except Exception as e:
            self._log("error", f"应用修复失败 {file_path}: {e}")
            return False

    def _apply_safe_fixes(self, fixes: List[FixResult], threshold: float = 0.8) -> List[FixResult]:
        """只应用高置信度的修复"""
        safe = [f for f in fixes if f.confidence >= threshold]
        print(f"[FixGen] 安全修复: {len(safe)}/{len(fixes)} (threshold={threshold})")
        return safe

    def _generate_branch_name(self, finding_id: str) -> str:
        """生成唯一的修复分支名"""
        import hashlib
        h = hashlib.md5(finding_id.encode()).hexdigest()[:8]
        return f"ai-fix/{h}"

    def _detect_language(self, file_path: str) -> str:
        from pathlib import Path
        ext = Path(file_path).suffix.lower()
        return {".py": "python", ".js": "javascript", ".ts": "typescript",
                ".java": "java", ".go": "go", ".php": "php",
                ".rb": "ruby", ".cs": "csharp"}.get(ext, "python")
