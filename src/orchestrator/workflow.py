# -*- coding: utf-8 -*-
"""工作流编排器 — 核心协调器，串联所有Agent"""
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from ..utils.config import config
from ..utils.logger import get_logger
from ..utils.timer import Timer
from ..knowledge.graph import KnowledgeGraph
from ..llm.client import LLMClient
from .pipeline import Pipeline, PipelineContext

# Agents
from ..agents.scheduler import SchedulerAgent
from ..agents.static_analyzer import StaticAnalyzerAgent
from ..agents.deep_analyzer import DeepAnalyzerAgent
from ..agents.fix_generator import FixGeneratorAgent
from ..agents.verifier import VerifierAgent
from ..agents.supply_chain import SupplyChainAgent


@dataclass
class WorkflowResult:
    """完整审计工作流的结果"""
    success: bool = True
    target: str = ""
    duration: float = 0.0
    summary: Dict[str, Any] = field(default_factory=dict)
    findings: List[dict] = field(default_factory=list)
    fixes: List[dict] = field(default_factory=list)
    supply_chain_findings: List[dict] = field(default_factory=list)
    errors: List[dict] = field(default_factory=list)
    pipeline_trace: List[dict] = field(default_factory=list)
    knowledge_graph: Optional[KnowledgeGraph] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "target": self.target,
            "duration": self.duration,
            "summary": self.summary,
            "errors": self.errors,
        }


class WorkflowOrchestrator:
    """核心编排器 — 管理整个审计流水线"""

    def __init__(self, config_instance=None):
        self.cfg = config_instance or config
        self.logger = get_logger("orchestrator")

        # 初始化组件
        self.kg = KnowledgeGraph()
        llm_cfg = self.cfg.get("llm", {})
        if isinstance(llm_cfg, dict):
            self.llm = LLMClient(llm_cfg)
        else:
            self.llm = LLMClient({})

        # 初始化Agent (pass config as dict)
        cfg_dict = self.cfg.to_dict() if hasattr(self.cfg, "to_dict") else {}
        self.scheduler = SchedulerAgent(cfg_dict, self.kg, self.llm)
        self.static_analyzer = StaticAnalyzerAgent(cfg_dict, self.kg, self.llm)
        self.deep_analyzer = DeepAnalyzerAgent(cfg_dict, self.kg, self.llm)
        self.fix_generator = FixGeneratorAgent(cfg_dict, self.kg, self.llm)
        self.verifier = VerifierAgent(cfg_dict, self.kg, self.llm)
        self.supply_chain = SupplyChainAgent(cfg_dict, self.kg, self.llm)

        # print("[Orchestrator] 初始化完成")  # debug

    # ============== 主要工作流 ==============

    def scan(self, target_path: str, deep_analysis: bool = True,
             auto_fix: bool = False, output_format: str = "json") -> WorkflowResult:
        """
        完整审计工作流:
        Scheduler → StaticAnalyzer+SupplyChain(并行) → DeepAnalyzer → FixGenerator → Verifier
        """
        t0 = time.perf_counter()
        result = WorkflowResult(target=target_path)

        print(f"\n{'='*60}")
        print(f"  AI Code Security Audit - Target: {target_path}")
        print(f"  Deep Analysis: {deep_analysis}, Auto Fix: {auto_fix}")
        print(f"{'='*60}\n")

        try:
            with Timer("Phase 1: 调度"):
                # Phase 1: 文件调度
                sched_result = self.scheduler.run({"root_path": target_path})
                if not sched_result.success:
                    result.errors.append({"phase": "scheduler", "error": "No files found"})
                    return result
                # Extract file paths from scheduler batches
                scheduler_files = []
                for batch in sched_result.metadata.get("batches", []):
                    for fd in batch.get("files", []):
                        scheduler_files.append(fd.get("file_path", ""))

            with Timer("Phase 2: 静态分析+供应链"):
                # Phase 2: 并行: 静态分析 + 供应链
                pipeline = Pipeline("scan-phase2")
                pipeline.add_stage("static", self.static_analyzer)
                pipeline.add_stage("supply_chain", self.supply_chain)
                # 并行执行
                parallel_results = pipeline.execute_parallel([
                    {"name": "static", "agent": self.static_analyzer,
                     "task_data": {"files": scheduler_files, "root_path": target_path}},
                    {"name": "supply_chain", "agent": self.supply_chain,
                     "task_data": {"root_path": target_path}},
                ])

                static_findings = []
                sc_findings = []
                for r in parallel_results:
                    if r.get("error"):
                        result.errors.append(r)
                    elif r["name"] == "static":
                        static_findings = r["result"].findings
                    elif r["name"] == "supply_chain":
                        sc_findings = r["result"].findings

                result.supply_chain_findings = sc_findings
                print(f"[Phase2] 静态分析: {len(static_findings)} 发现, "
                      f"供应链: {len(sc_findings)} 风险")

            # Phase 3: LLM深度分析
            if deep_analysis and static_findings:
                with Timer("Phase 3: 深度分析"):
                    deep_result = self.deep_analyzer.run({
                        "root_path": target_path,
                        "findings": static_findings,
                    })
                    enriched_findings = deep_result.findings
                    result.findings = enriched_findings
            else:
                result.findings = static_findings

            # Phase 4: 生成修复
            if auto_fix and result.findings:
                with Timer("Phase 4: 生成修复"):
                    fix_result = self.fix_generator.run({
                        "root_path": target_path,
                        "findings": result.findings,
                        "apply_fixes": False,  # dry-run by default
                    })
                    result.fixes = fix_result.findings

            # Phase 5: 验证(如果有修复)
            if result.fixes:
                with Timer("Phase 5: 验证修复"):
                    verify_result = self.verifier.run({
                        "root_path": target_path,
                        "fixes": result.fixes,
                    })

            # 汇总
            total_duration = time.perf_counter() - t0
            result.duration = total_duration
            result.success = len(result.errors) == 0
            result.summary = self._build_summary(result, target_path)

            print(f"\n[Orchestrator] 审计完成 耗时 {total_duration:.1f}s")
            print(f"[Orchestrator] 发现: {len(result.findings)} 问题, "
                  f"供应链: {len(result.supply_chain_findings)} 风险, "
                  f"修复: {len(result.fixes)} 建议")

            return result

        except Exception as e:
            self.logger.error(f"审计失败: {e}")
            result.success = False
            result.errors.append({"phase": "orchestrator", "error": str(e)})
            result.duration = time.perf_counter() - t0
            return result

    def quick_scan(self, target_path: str) -> WorkflowResult:
        """快速扫描: 仅静态分析"""
        return self.scan(target_path, deep_analysis=False, auto_fix=False)

    def supply_chain_check(self, target_path: str) -> WorkflowResult:
        """仅供应链检查"""
        result = WorkflowResult(target=target_path)
        t0 = time.perf_counter()

        sc_result = self.supply_chain.run({"root_path": target_path})
        result.supply_chain_findings = sc_result.findings
        result.duration = time.perf_counter() - t0
        result.success = sc_result.success
        result.summary = {
            "supply_chain_risks": len(sc_result.findings),
            "message": f"发现 {len(sc_result.findings)} 个供应链风险",
        }
        return result

    def fix(self, target_path: str, finding_ids: List[str] = None, dry_run: bool = True) -> WorkflowResult:
        """生成修复补丁(不运行完整扫描)"""
        result = WorkflowResult(target=target_path)
        t0 = time.perf_counter()

        # 从知识图谱获取findings
        all_findings = self.kg.get_all_findings()
        if finding_ids:
            all_findings = [f for f in all_findings if f.id in finding_ids]

        findings_list = [{**f.properties, "id": f.id} for f in all_findings]

        fix_result = self.fix_generator.run({
            "root_path": target_path,
            "findings": findings_list,
            "apply_fixes": not dry_run,
        })

        result.fixes = fix_result.findings
        result.duration = time.perf_counter() - t0
        result.success = fix_result.success
        result.summary = {"fixes_generated": len(fix_result.findings), "dry_run": dry_run}
        return result

    def verify(self, target_path: str) -> WorkflowResult:
        """验证已应用的修复"""
        result = WorkflowResult(target=target_path)
        t0 = time.perf_counter()

        # 获取所有fix节点
        from ..knowledge.nodes import NodeType
        fix_nodes = self.kg.get_nodes_by_type(NodeType.FIX)
        fixes_list = [f.properties for f in fix_nodes]

        verify_result = self.verifier.run({
            "root_path": target_path,
            "fixes": fixes_list,
        })

        result.duration = time.perf_counter() - t0
        result.success = verify_result.success
        result.summary = verify_result.metadata
        return result

    # ============== 内部方法 ==============

    def _build_summary(self, wf_result: WorkflowResult, target: str) -> dict:
        """生成摘要"""
        findings = wf_result.findings
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "target": target,
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "supply_chain_risks": len(wf_result.supply_chain_findings),
            "fixes_generated": len(wf_result.fixes),
            "duration": wf_result.duration,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _create_default_pipeline(self) -> Pipeline:
        """创建默认管线"""
        pipeline = Pipeline("default")
        pipeline.add_stage("scheduler", self.scheduler)
        pipeline.add_stage("static", self.static_analyzer)
        pipeline.add_stage("supply_chain", self.supply_chain)
        pipeline.add_stage("deep", self.deep_analyzer,
                           condition=lambda ctx: bool(ctx.findings))
        pipeline.add_stage("fix", self.fix_generator,
                           condition=lambda ctx: bool(ctx.findings))
        pipeline.add_stage("verify", self.verifier)
        return pipeline

    def _handle_workflow_error(self, error: Exception, stage: str):
        self.logger.error(f"工作流错误 [{stage}]: {error}")
        # TODO: 发送告警通知

    # --- 上下文管理器 ---
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 清理知识图谱
        pass
        return False
