# -*- coding: utf-8 -*-
"""
Static Analyzer Agent - 管道第二阶段: 静态代码安全分析

执行流程:
  1. 接收 FileTask / BatchTask / 文件列表
  2. 并行运行 Semgrep(必选) + CodeQL(可选)
  3. 解析所有SARIF输出
  4. 去重 + 按severity过滤
  5. 存储findings到knowledge_graph
  6. 返回聚合的AgentResult

当前策略:
  - Semgrep总是运行(如果可用), CodeQL按需启用
  - 两者并行以节省时间
  - Semgrep失败时尝试CodeQL兜底(互备策略)

TODO: 增量分析(git diff → 只扫描变更文件)
FIXME: CodeQL数据库创建在大项目中非常慢, 需要更好的超时策略
"""

import time
import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTO

# ---- 导入analyzers ----
from ..analyzers.sarif_parser import SARIFParser
from ..analyzers.semgrep_runner import SemgrepRunner
from ..analyzers.codeql import CodeQLRunner

# ---- 导入base ----
from .base import (
    BaseAgent, AgentResult, FileTask, BatchTask,
    severity_gte, merge_results,
)

# ---- 柔性导入file_scanner ----
try:
    from ..utils.file_scanner import detect_language
except ImportError:
    def detect_language(path: str) -> str:
        ext = Path(path).suffix.lower()
        m = {'.py': 'python', '.js': 'javascript', '.ts': 'typescript',
             '.java': 'java', '.go': 'go', '.rb': 'ruby'}
        return m.get(ext, 'unknown')


class StaticAnalyzerAgent(BaseAgent):
    """
    运行Semgrep + CodeQL进行安全分析。

    策略:
        1. Semgrep: 轻量模式匹配, 快速 → always run
        2. CodeQL:  语义分析, 深度但慢 → optional (default off)
        3. 并行运行 + 结果合并去重 + severity过滤

    Usage:
        analyzer = StaticAnalyzerAgent(config={"use_codeql": False})
        result = analyzer.run({"files": ["main.py", "auth.py"]})
    """

    def __init__(self, config: Optional[Dict] = None,
                 knowledge_graph: Any = None, llm_client: Any = None):
        super().__init__(config, knowledge_graph, llm_client)

        # 从config解析设置
        self.use_semgrep = self.config.get("use_semgrep", True)
        self.use_codeql = self.config.get("use_codeql", False)   # 默认关
        self.severity_threshold = self.config.get(
            "severity_threshold",
            self.config.get("reporting", {}).get("severity_filter", "low")
        )
        self.min_severity = self.config.get("min_severity", self.severity_threshold)
        self.scan_timeout = self.config.get("scan_timeout", 600)

        # Semgrep settings
        self.semgrep_rules = self.config.get("semgrep_rules", "default")
        self.semgrep_timeout = self.config.get("semgrep_timeout", self.scan_timeout)
        # CodeQL settings
        self.codeql_queries = self.config.get("codeql_queries")
        self.codeql_timeout = self.config.get("codeql_timeout", self.scan_timeout * 2)

        # ---- Initialize runners ----
        self.sarif_parser = SARIFParser(strict_mode=False)
        self._semgrep: Optional[SemgrepRunner] = None
        self._codeql: Optional[CodeQLRunner] = None

        self._init_runners()

        print(f"[DEBUG] StaticAnalyzerAgent init'd: "
              f"semgrep={self.use_semgrep}, codeql={self.use_codeql}, "
              f"threshold={self.severity_threshold}")

    def _init_runners(self):
        """Lazy init of tool runners with availability checks."""
        if self.use_semgrep:
            try:
                self._semgrep = SemgrepRunner({"timeout": self.semgrep_timeout})
                avail = self._semgrep.is_available()
                print(f"[INFO] Semgrep available: {avail}")
                if not avail:
                    print("[WARN] Semgrep not installed, will be skipped")
            except Exception as e:
                print(f"[ERROR] Semgrep init failed: {e}")
                self._semgrep = None

        if self.use_codeql:
            try:
                self._codeql = CodeQLRunner({"timeout": self.codeql_timeout})
                avail = self._codeql.is_available()
                print(f"[INFO] CodeQL available: {avail}")
                if not avail:
                    print("[WARN] CodeQL not installed, will be skipped")
                    self.use_codeql = False
            except Exception as e:
                print(f"[ERROR] CodeQL init failed: {e}")
                self._codeql = None
                self.use_codeql = False

    # ====================  Abstract Implementations  ====================

    @property
    def agent_name(self) -> str:
        return "StaticAnalyzerAgent"

    @property
    def agent_type(self) -> str:
        return "static_analyzer"

    def run(self, task: Any) -> AgentResult:
        """
        Run static analysis.

        Args:
            task: str (single file), list of paths, dict with 'files'/'target_path',
                  FileTask, or BatchTask.

        Returns:
            AgentResult with all findings
        """
        print(f"\n{'='*60}")
        print(f"[StaticAnalyzer] Starting analysis...")
        print(f"{'='*60}")

        t0 = time.time()
        all_results: List[AgentResult] = []
        scan_dir = None

        try:
            # 1. 解析输入 → 文件列表
            file_list = self._extract_file_list(task)
            if not file_list:
                return AgentResult(
                    success=False,
                    errors=["No files to analyze"],
                    agent_name=self.agent_name,
                    duration=time.time() - t0,
                )

            print(f"[StaticAnalyzer] {len(file_list)} file(s) to analyze")

            # 2. 确定扫描目录
            scan_dir = self._determine_scan_dir(file_list)
            print(f"[StaticAnalyzer] Scan dir: {scan_dir}")

            # 3. 并行运行两个扫描器
            futures = {}
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan") as ex:

                # Semgrep
                if self.use_semgrep and self._semgrep and self._semgrep.is_available():
                    futures["semgrep"] = ex.submit(self._run_semgrep, scan_dir)
                    print("[StaticAnalyzer] Semgrep job submitted")
                else:
                    # semgrep不可用 → 尝试CodeQL兜底
                    if not (self.use_codeql and self._codeql and self._codeql.is_available()):
                        print("[WARN] Semgrep not available and CodeQL also not available")

                # CodeQL
                if self.use_codeql and self._codeql and self._codeql.is_available():
                    futures["codeql"] = ex.submit(self._run_codeql, file_list)
                    print("[StaticAnalyzer] CodeQL job submitted")

                # 如果没有提交任何job
                if not futures:
                    print("[StaticAnalyzer] No scanners available!")
                    return AgentResult(
                        success=True,
                        findings=[],
                        errors=["No analysis tools available. pip install semgrep"],
                        metadata={"warning": "no_scanners_available"},
                        duration=time.time() - t0,
                        agent_name=self.agent_name,
                    )

                # 收集结果
                for tool, future in futures.items():
                    try:
                        res = future.result(timeout=self.scan_timeout * 2)
                        all_results.append(res)
                        if res.findings:
                            print(f"[StaticAnalyzer] {tool}: {len(res.findings)} findings")
                    except FuturesTO:
                        print(f"[ERROR] {tool} timed out!")
                        all_results.append(AgentResult(
                            success=False, errors=[f"{tool} timeout"],
                            agent_name=f"{self.agent_name}/{tool}",
                        ))
                    except Exception as e:
                        print(f"[ERROR] {tool} failed: {e}")
                        all_results.append(AgentResult(
                            success=False, errors=[f"{tool}: {e}"],
                            agent_name=f"{self.agent_name}/{tool}",
                        ))

            # 4. 合并结果
            merged = merge_results(*all_results)
            print(f"[StaticAnalyzer] Merged: {len(merged.findings)} raw findings")

            # 5. 去重
            if merged.findings:
                before = len(merged.findings)
                merged.findings = self.sarif_parser.deduplicate(merged.findings)
                print(f"[StaticAnalyzer] Dedup: {before} → {len(merged.findings)}")

            # 6. Severity过滤
            if merged.findings:
                before = len(merged.findings)
                merged.findings = self._filter_findings(merged.findings, self.severity_threshold)
                print(f"[StaticAnalyzer] Filter: {before} → {len(merged.findings)} "
                      f"(threshold={self.severity_threshold})")

            # 7. 存入knowledge_graph
            if self.knowledge_graph and merged.findings:
                try:
                    self.knowledge_graph.add_findings(merged.findings)
                    print(f"[StaticAnalyzer] {len(merged.findings)} findings → KG")
                except Exception as e:
                    print(f"[WARN] KG write failed: {e}")

            # 8. 最终输出
            elapsed = time.time() - t0
            merged.metadata.update({
                "scan_tools": list(futures.keys()),
                "files_scanned": len(file_list),
                "severity_threshold": self.severity_threshold,
            })
            merged.duration = elapsed
            merged.agent_name = self.agent_name

            self._record_metric("total_findings", len(merged.findings))
            self._record_metric("scan_time", elapsed)
            self._record_metric("files_analyzed", len(file_list))

            self._print_summary(merged)
            return merged

        except Exception as e:
            self._log("error", f"Critical failure: {e}")
            import traceback
            traceback.print_exc()
            return AgentResult(
                success=False,
                errors=[f"Analysis failed: {e}"],
                duration=time.time() - t0,
                agent_name=self.agent_name,
            )

    # ====================  Internal: File Extraction  ====================

    def _extract_file_list(self, task: Any) -> List[str]:
        """Normalize various input formats to a list of file paths."""
        if isinstance(task, str):
            if Path(task).is_dir():
                # Directory → list all code files in it
                return list_files_in_dir(task)
            return [task]
        if isinstance(task, (list, tuple)):
            return [str(f) for f in task]
        if isinstance(task, dict):
            if "files" in task:
                return [str(f) for f in task["files"]]
            if "file_path" in task:
                return [task["file_path"]]
            if "target_path" in task:
                tp = task["target_path"]
                if Path(tp).is_dir():
                    return list_files_in_dir(tp)
                return [tp]
        if isinstance(task, FileTask):
            return [task.file_path]
        if isinstance(task, BatchTask):
            return [f.file_path for f in task.files]
        return [str(task)]

    def _determine_scan_dir(self, file_list: List[str]) -> str:
        """Find common parent dir for scanning."""
        paths = [Path(f) for f in file_list if Path(f).exists()]
        if not paths:
            return "."
        if len(paths) == 1:
            return str(paths[0].parent) if paths[0].is_file() else str(paths[0])

        # 找common prefix
        common = paths[0]
        for p in paths[1:]:
            while not str(p).startswith(str(common)):
                common = common.parent
        print(f"[DEBUG] Common scan dir: {common}")
        return str(common)

    # ====================  Internal: Semgrep Runner  ====================

    def _run_semgrep(self, scan_directory: str) -> AgentResult:
        """Run semgrep and parse results."""
        print(f"[Semgrep] Scanning: {scan_directory}")
        t0 = time.time()

        try:
            if not self._semgrep:
                return AgentResult(
                    success=False, errors=["Semgrep not initialized"],
                    agent_name=f"{self.agent_name}/Semgrep",
                )

            sarif_out = self._semgrep.run(scan_directory, self.semgrep_rules)

            if not sarif_out or not sarif_out.strip():
                print("[Semgrep] Empty output")
                return AgentResult(
                    success=True, findings=[],
                    agent_name=f"{self.agent_name}/Semgrep",
                    duration=time.time() - t0,
                )

            # 检测是否为内部错误SARIF
            try:
                temp = json.loads(sarif_out)
                rr = temp.get("runs", [{}])[0].get("results", [])
                if rr and rr[0].get("ruleId", "").startswith("internal.semgrep."):
                    err_text = rr[0].get("message", {}).get("text", "Semgrep error")
                    print(f"[Semgrep] Internal error: {err_text}")
                    return AgentResult(
                        success=False, errors=[err_text],
                        agent_name=f"{self.agent_name}/Semgrep",
                        duration=time.time() - t0,
                    )
            except json.JSONDecodeError:
                pass  # Not JSON, maybe raw output

            findings = self.sarif_parser.parse_string(sarif_out)

            # Tag source
            for f in findings:
                f["source"] = "semgrep"

            elapsed = time.time() - t0
            print(f"[Semgrep] {len(findings)} findings in {elapsed:.1f}s")

            self._record_metric("semgrep_findings", len(findings))
            self._record_metric("semgrep_time", elapsed)

            return AgentResult(
                success=True, findings=findings,
                metadata={"tool": "Semgrep", "tool_version": self._semgrep.get_version() or "?"},
                duration=elapsed, agent_name=f"{self.agent_name}/Semgrep",
            )

        except Exception as e:
            print(f"[Semgrep] FAILED: {type(e).__name__}: {e}")
            return AgentResult(
                success=False,
                errors=[f"Semgrep: {e}"],
                agent_name=f"{self.agent_name}/Semgrep",
                duration=time.time() - t0,
            )

    # ====================  Internal: CodeQL Runner  ====================

    def _run_codeql(self, file_list: List[str]) -> AgentResult:
        """Run CodeQL analysis."""
        print(f"[CodeQL] Analyzing {len(file_list)} file(s)...")
        t0 = time.time()

        try:
            if not self._codeql or not self._codeql.is_available():
                return AgentResult(
                    success=False, errors=["CodeQL not available"],
                    agent_name=f"{self.agent_name}/CodeQL",
                )

            # Group by language
            by_lang: Dict[str, List[str]] = {}
            for fp in file_list:
                lang = detect_language(str(fp))
                if lang != "unknown":
                    by_lang.setdefault(lang, []).append(str(fp))

            print(f"[CodeQL] Languages: {list(by_lang.keys())}")

            supported = set(self._codeql.get_supported_languages())
            all_f = []

            for lang, files in by_lang.items():
                if lang not in supported:
                    print(f"[CodeQL] Skip unsupported: {lang}")
                    continue

                # Process one representative dir per language
                # (limit: avoid exploding the pipeline)
                for fp in files[:5]:
                    try:
                        d = str(Path(fp).parent)
                        sarif = self._codeql.create_and_analyze(
                            d, lang, self.codeql_queries
                        )
                        if sarif:
                            parsed = self.sarif_parser.parse_string(sarif)
                            for pf in parsed:
                                pf["source"] = "codeql"
                            all_f.extend(parsed)
                            print(f"[CodeQL] {Path(fp).name}: {len(parsed)} findings")
                    except Exception as e:
                        print(f"[CodeQL] Error on {fp}: {e}")
                        continue

            elapsed = time.time() - t0
            print(f"[CodeQL] {len(all_f)} findings in {elapsed:.1f}s")

            self._record_metric("codeql_findings", len(all_f))
            return AgentResult(
                success=True, findings=all_f,
                metadata={"tool": "CodeQL"},
                duration=elapsed, agent_name=f"{self.agent_name}/CodeQL",
            )

        except Exception as e:
            print(f"[CodeQL] FAILED: {type(e).__name__}: {e}")
            return AgentResult(
                success=False,
                errors=[f"CodeQL: {e}"],
                agent_name=f"{self.agent_name}/CodeQL",
                duration=time.time() - t0,
            )

    # ====================  Internal: Post-processing  ====================

    def _filter_findings(self, findings: List[Dict],
                         threshold: str) -> List[Dict]:
        """Filter findings by severity threshold."""
        if not findings:
            return []
        result = [f for f in findings
                  if severity_gte(f.get("severity", "info"), threshold)]
        dropped = len(findings) - len(result)
        if dropped:
            print(f"[Filter] Dropped {dropped} below {threshold}")
        return result

    def _print_summary(self, result: AgentResult):
        """Print human-readable analysis summary."""
        print(f"\n{'─'*50}")
        print(f"  STATIC ANALYSIS SUMMARY")
        print(f"{'─'*50}")
        print(f"  Status   : {'PASS' if result.success else 'FAILED'}")
        print(f"  Findings : {len(result.findings)}")
        print(f"  Errors   : {len(result.errors)}")
        print(f"  Duration : {result.duration:.2f}s")

        if result.findings:
            sev = Counter(f.get("severity", "?") for f in result.findings)
            print(f"  By Severity:")
            for level in ["critical", "high", "medium", "low", "info"]:
                c = sev.get(level, 0)
                if c:
                    bar = "█" * min(c, 30)
                    print(f"    {level:8s}: {c:4d} {bar}")

            # Top rules
            rules = Counter(f.get("rule_id", "?") for f in result.findings)
            print(f"  Top Rules:")
            for rule, cnt in rules.most_common(5):
                # truncate long rule_ids
                short_rule = rule if len(rule) < 60 else rule[:57] + "..."
                print(f"    {short_rule}: {cnt}")

        if result.errors:
            print(f"  Errors (first 3):")
            for err in result.errors[:3]:
                print(f"    - {str(err)[:100]}")

        print(f"{'─'*50}\n")

    # ====================  Convenience Methods  ====================

    def analyze_single_file(self, file_path: str) -> AgentResult:
        """Quick analysis of a single file."""
        return self.run(file_path)

    def analyze_batch(self, batch: BatchTask) -> AgentResult:
        """Analyze a pre-built batch."""
        return self.run(batch)


# ==============  Module-level Helpers  ==============


def list_files_in_dir(directory: str) -> List[str]:
    """Quickly list code files in a directory."""
    exts = {'.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rb', '.php'}
    result = []
    for ext in exts:
        for fp in Path(directory).rglob(f'*{ext}'):
            result.append(str(fp))
    return result


def quick_analyze(file_path: str, **kwargs) -> AgentResult:
    """One-shot analysis of a file."""
    agent = StaticAnalyzerAgent(config=kwargs)
    return agent.run(file_path)


def analyze_project(root_path: str, config: Dict = None) -> AgentResult:
    """
    End-to-end project analysis (scheduler + analyzer).

    Internally calls SchedulerAgent for file discovery, then
    StaticAnalyzerAgent for scanning.
    """
    print(f"[INFO] Full project analysis: {root_path}")

    try:
        from .scheduler import SchedulerAgent
        scheduler = SchedulerAgent(config=config or {})
        sched_result = scheduler.run({"root_path": root_path})
        if not sched_result.success:
            return sched_result

        analyzer = StaticAnalyzerAgent(config=config or {})
        all_f = []
        for bdata in sched_result.metadata.get("batches", []):
            batch = BatchTask(
                files=[FileTask(**fd) for fd in bdata["files"]],
                batch_id=bdata.get("batch_id", ""),
            )
            result = analyzer.run(batch)
            all_f.extend(result.findings)

        return AgentResult(
            success=True, findings=all_f,
            metadata={"project": root_path},
            agent_name="ProjectAnalyzer",
        )
    except ImportError:
        # Fallback: direct file analysis
        analyzer = StaticAnalyzerAgent(config=config or {})
        return analyzer.run(root_path)


# ==============  Self-test  ==============
if __name__ == "__main__":
    print("=" * 60)
    print("  StaticAnalyzerAgent Self-Test")
    print("=" * 60 + "\n")

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        # Create a test file with known issues
        test_file = Path(td) / "insecure.py"
        test_file.write_text("""\
import os
import pickle

PASSWORD = "hardcoded_secret_123"

def run_command(user_input):
    # Should trigger: subprocess injection, eval
    os.system("echo " + user_input)
    result = eval(user_input)
    data = pickle.loads(user_input)
    return result
""", encoding="utf-8")

        print(f"Test file: {test_file}\n")
        print(f"Content:\n{test_file.read_text()}\n")

        config = {
            "use_semgrep": True,
            "use_codeql": False,
            "severity_threshold": "low",
        }

        agent = StaticAnalyzerAgent(config=config)

        # NOTE: test will only produce findings if semgrep is installed
        if agent._semgrep and agent._semgrep.is_available():
            print("--- Running Semgrep scan ---")
            result = agent.run(str(test_file))
            print(f"Result: {result}")
        else:
            print("Semgrep not installed, skipping actual scan.")
            print("  Install: pip install semgrep")

        # Test filter
        print("\n--- Testing filter ---")
        sample = [
            {"rule_id": "r1", "severity": "critical"},
            {"rule_id": "r2", "severity": "high"},
            {"rule_id": "r3", "severity": "medium"},
            {"rule_id": "r4", "severity": "low"},
            {"rule_id": "r5", "severity": "info"},
        ]
        filtered = agent._filter_findings(sample, "medium")
        print(f"Filter (>=medium): {len(filtered)} kept")
        for f in filtered:
            print(f"  {f['rule_id']}: {f['severity']}")

    print("\n[OK] Self-test done\n")
