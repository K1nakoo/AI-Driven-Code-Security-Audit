# -*- coding: utf-8 -*-
"""深度分析Agent - 用LLM追踪数据流，消除误报"""
import time
from typing import Dict, Any, List, Optional
from pathlib import Path

from .base import BaseAgent, AgentResult
from ..knowledge.nodes import KnowledgeNode, NodeType
from ..knowledge.edges import KnowledgeEdge, RelationType


class DeepAnalyzerAgent(BaseAgent):
    """LLM深度数据流追踪分析 - 减少误报"""

    @property
    def agent_name(self) -> str:
        return "DeepAnalyzerAgent"

    def __init__(self, config=None, knowledge_graph=None, llm_client=None):
        super().__init__(config, knowledge_graph, llm_client)
        self.confidence_threshold = config.get("deep_analysis", {}).get("confidence_threshold", 0.6) if config else 0.6

    def run(self, task) -> AgentResult:
        findings = task.get("findings", [])
        if not findings:
            self._log("info", "No findings to analyze")
            return AgentResult(success=True, agent_name=self.agent_name, metadata={"analyzed": 0})

        start_t = time.perf_counter()
        self._log("info", f"开始深度分析 {len(findings)} 个发现")

        enriched_findings = []
        false_positives = 0
        errors = []

        for i, finding in enumerate(findings):
            try:
                result = self._analyze_finding(finding)
                if result:
                    enriched_findings.append(result)
                    if result.get("is_false_positive"):
                        false_positives += 1

            except Exception as e:
                self._log("error", f"分析失败 {finding.get('rule_id')}: {e}")
                errors.append({"finding": finding.get("rule_id"), "error": str(e)})
                enriched_findings.append(finding)  # 保留原始发现

            # 进度打印
            if (i + 1) % 10 == 0:
                print(f"[DeepAnalyzer] 进度: {i+1}/{len(findings)}")

        # 更新知识图谱中的数据流信息
        if self.knowledge_graph:
            for f in enriched_findings:
                data_flow = f.get("data_flow", {})
                if data_flow:
                    # 找对应的finding节点更新属性
                    for node in self.knowledge_graph.get_all_findings():
                        if (node.properties.get("rule_id") == f.get("rule_id") and
                            node.properties.get("file_path") == f.get("file_path")):
                            node.properties["analyzed"] = True
                            node.properties["confidence"] = f.get("confidence", 0.5)
                            node.properties["data_flow"] = data_flow
                            break

        duration = time.perf_counter() - start_t
        self._log("info", f"深度分析完成: {len(enriched_findings)} 个, 误报 {false_positives} 个")

        return AgentResult(
            success=True,
            agent_name=self.agent_name,
            findings=enriched_findings,
            errors=errors,
            metadata={
                "total": len(findings),
                "analyzed": len(enriched_findings),
                "false_positives": false_positives,
                "true_positives": len(enriched_findings) - false_positives,
            },
            duration=duration,
        )

    def _analyze_finding(self, finding: dict) -> dict:
        """分析单个finding - 核心逻辑"""
        file_path = finding.get("file_path", "")
        code_context = self._read_file_context(file_path, finding.get("line", 1))

        if not self.llm_client or not self.llm_client.is_available:
            self._log("debug", "LLM不可用，跳过深度分析")
            finding["analyzed"] = False
            finding["confidence"] = 0.5
            return finding

        # 调用LLM分析
        language = self._detect_language(file_path)
        analysis = self.llm_client.analyze_code(
            code=code_context,
            finding=finding,
            file_path=file_path,
            language=language,
        )

        # 合并结果
        finding.update({
            "analyzed": True,
            "confidence": analysis.get("confidence", 0.5),
            "is_false_positive": analysis.get("is_false_positive", False),
            "data_flow": analysis.get("data_flow", {}),
            "exploit_scenario": analysis.get("exploit_scenario", ""),
            "remediation": analysis.get("remediation", ""),
            "deep_analysis": analysis,
        })

        return finding

    def _read_file_context(self, file_path: str, target_line: int,
                           context_lines: int = 30) -> str:
        """读取目标行周围的代码"""
        if not file_path or not Path(file_path).exists():
            return ""

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            start = max(0, target_line - context_lines // 2 - 1)
            end = min(len(lines), target_line + context_lines // 2)

            # 加行号方便LLM理解
            context = ""
            for i in range(start, end):
                context += f"{i+1}: {lines[i]}"

            return context
        except Exception:
            return ""

    def _detect_language(self, file_path: str) -> str:
        ext = Path(file_path).suffix.lower()
        lang_map = {
            ".py": "python", ".pyw": "python",
            ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
            ".ts": "typescript", ".tsx": "typescript",
            ".java": "java", ".kt": "kotlin",
            ".go": "go",
            ".php": "php",
            ".rb": "ruby",
            ".cs": "csharp",
        }
        return lang_map.get(ext, "python")

    def _assess_false_positive(self, finding: dict, analysis: dict) -> float:
        """评估误报可能性: 0=确认的漏洞, 1=确定误报"""
        score = 0.0
        if analysis.get("is_false_positive"):
            score += 0.7
        if analysis.get("data_flow", {}).get("sanitizers"):
            score += 0.3
        return min(score, 1.0)

    def _generate_dataflow_graph(self, finding: dict) -> dict:
        """提取数据流图: source → sanitizer → sink"""
        df = finding.get("data_flow", {})
        return {
            "source": df.get("source", "未知"),
            "sanitizers": df.get("sanitizers", []),
            "sink": df.get("sink", "未知"),
            "path": df.get("path_summary", ""),
        }

    def _build_context(self, finding: dict, file_content: str) -> str:
        """构建分析上下文(用于prompt)"""
        parts = [
            f"Rule: {finding.get('rule_id', 'unknown')}",
            f"Severity: {finding.get('severity', 'unknown')}",
            f"Message: {finding.get('message', '')}",
            f"File: {finding.get('file_path', '')}",
            f"Line: {finding.get('line', '')}",
            "",
            "Code:",
            finding.get("code_snippet", file_content[:2000]),
        ]
        return "\n".join(parts)
