# -*- coding: utf-8 -*-
"""验证Agent — 测试+构建+重扫+diff分析"""
import time
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

from .base import BaseAgent, AgentResult
from ..validation.test_runner import TestRunner, TestResult
from ..validation.build_checker import BuildChecker, BuildResult
from ..validation.diff_analyzer import DiffAnalyzer, DiffAnalysis
from ..analyzers.semgrep_runner import SemgrepRunner
from ..analyzers.sarif_parser import SARIFParser


@dataclass
class VerificationResult:
    passed: bool
    test_result: Optional[TestResult] = None
    build_result: Optional[BuildResult] = None
    diff_analysis: Optional[DiffAnalysis] = None
    re_scan_findings: List[dict] = None
    original_finding_fixed: bool = False

    def __post_init__(self):
        if self.re_scan_findings is None:
            self.re_scan_findings = []


class VerifierAgent(BaseAgent):
    """验证修复的正确性和安全性"""

    @property
    def agent_name(self) -> str:
        return "VerifierAgent"

    def __init__(self, config=None, knowledge_graph=None, llm_client=None):
        super().__init__(config, knowledge_graph, llm_client)
        self.test_runner = None
        self.build_checker = None
        self.diff_analyzer = DiffAnalyzer()
        self.semgrep = SemgrepRunner()
        self.sarif_parser = SARIFParser()
        self.run_tests_flag = config.get("validation", {}).get("run_tests", True) if config else True
        self.check_build_flag = config.get("validation", {}).get("check_build", True) if config else True

    def run(self, task) -> AgentResult:
        target = task.get("target_path", ".")
        fixes = task.get("fixes", [])
        start_t = time.perf_counter()

        self.test_runner = TestRunner(target)
        self.build_checker = BuildChecker(target)

        self._log("info", f"开始验证 {len(fixes)} 个修复")

        results = []
        errors = []

        for fix in fixes:
            try:
                vr = self._verify_fix(fix)
                results.append(vr)
            except Exception as e:
                self._log("error", f"验证失败: {e}")
                errors.append({"fix": str(fix)[:100], "error": str(e)})

        passed_count = sum(1 for r in results if r.passed)
        self._log("info", f"验证完成: {passed_count}/{len(results)} 通过")

        duration = time.perf_counter() - start_t
        return AgentResult(
            success=len(errors) == 0,
            agent_name=self.agent_name,
            findings=[
                {"passed": r.passed, "original_fixed": r.original_finding_fixed}
                for r in results
            ],
            errors=errors,
            metadata={
                "total_fixes": len(fixes),
                "verified": len(results),
                "passed": passed_count,
                "failed": len(results) - passed_count,
            },
            duration=duration,
        )

    def _verify_fix(self, fix: dict) -> VerificationResult:
        """验证单个修复"""
        file_path = fix.get("file_path", "")
        original_finding = fix.get("finding", {})
        diff_text = fix.get("diff", "")

        # 1. Diff分析
        diff_analysis = self.diff_analyzer.analyze_diff(diff_text)

        # 2. 语法检查
        syntax_ok = self.diff_analyzer.check_syntax(file_path) if file_path else True

        # 3. 测试(如果配置了)
        test_result = None
        if self.run_tests_flag:
            test_result = self.test_runner.run_tests()

        # 4. 构建检查
        build_result = None
        if self.check_build_flag:
            build_result = self.build_checker.check_build()

        # 5. 重扫文件
        re_scan = []
        original_fixed = False
        if file_path:
            sarif = self.semgrep.scan_file(file_path)
            if sarif:
                re_scan = self.sarif_parser.parse_string(sarif)
                # 检查原始finding是否还在
                original_rule = original_finding.get("rule_id", "")
                original_line = original_finding.get("line", 0)
                original_fixed = not any(
                    f.get("rule_id") == original_rule and f.get("line") == original_line
                    for f in re_scan
                )

        # 综合判断
        all_checks_pass = True
        if diff_analysis and not diff_analysis.is_safe:
            all_checks_pass = False
        if test_result and not test_result.success:
            all_checks_pass = False
        if build_result and not build_result.success:
            all_checks_pass = False
        if not syntax_ok:
            all_checks_pass = False

        return VerificationResult(
            passed=all_checks_pass and original_fixed,
            test_result=test_result,
            build_result=build_result,
            diff_analysis=diff_analysis,
            re_scan_findings=re_scan,
            original_finding_fixed=original_fixed,
        )

    def _re_scan_fixed_file(self, file_path: str) -> list:
        """重扫修复后的文件"""
        sarif = self.semgrep.scan_file(file_path)
        if sarif:
            return self.sarif_parser.parse_string(sarif)
        return []

    def verify_pipeline(self, target: str, fixes: list) -> dict:
        """完整的验证流水线，返回摘要"""
        task = {"target_path": target, "fixes": fixes}
        result = self.run(task)
        return result.to_dict()
