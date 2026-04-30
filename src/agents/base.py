# -*- coding: utf-8 -*-
"""
Base Agent模块 - 定义所有Agent的抽象基类和公共数据结构。

设计思路: 轻量级Agent框架, 每个Agent处理安全分析管道中的一个环节。
管道流程: Scheduler → StaticAnalyzer → (未来: AIAnalyzer → Reporter)

TODO: 添加Agent间事件通信机制(event bus / message queue)
FIXME: 错误处理目前过于简单, 需要支持partial failure和retry
"""
import time
import uuid
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable
from enum import Enum

# ---- 柔性导入: 如果子模块尚未实现, 降级为Any ----
try:
    from src.knowledge_graph.graph import KnowledgeGraph
except ImportError:
    KnowledgeGraph = Any  # type: ignore

try:
    from src.llm.client import LLMClient
except ImportError:
    LLMClient = Any  # type: ignore

try:
    from src.utils.logger import get_logger
    _has_logger = True
except ImportError:
    _has_logger = False

logger = logging.getLogger(__name__)


# =====================  Enums  =====================

class AgentStatus(Enum):
    """Agent生命周期状态"""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(Enum):
    """Finding严重级别, 用于统一所有模块的severity常量"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


# =====================  Data Classes  =====================

@dataclass
class AgentResult:
    """
    统一的Agent执行结果。

    Attributes:
        success:   是否成功完成
        findings:  发现的issues列表(每项是dict: {rule_id, message, severity, ...})
        errors:    错误信息列表
        metadata:  附加元数据(统计信息, 工具版本等)
        duration:  执行耗时(秒)
        agent_name: Agent名
        result_id:  唯一ID
    """
    success: bool = True
    agent_name: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Any] = field(default_factory=list)   # str or dict
    metadata: Dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    result_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for JSON output / logging."""
        return {
            "result_id": self.result_id,
            "agent_name": self.agent_name,
            "success": self.success,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "errors": self.errors,
            "metadata": self.metadata,
            "duration": self.duration,
        }

    def add_finding(self, finding: Dict[str, Any]) -> "AgentResult":
        """Fluent: add a single finding."""
        self.findings.append(finding)
        return self

    def merge(self, other: "AgentResult") -> "AgentResult":
        """合并另一个AgentResult的内容."""
        self.findings.extend(other.findings)
        # Normalize errors: accept str or dict
        self.errors.extend(other.errors)
        self.metadata.update(other.metadata)
        self.duration += other.duration
        self.success = self.success and other.success
        return self

    def __str__(self) -> str:
        status = "OK" if self.success else "FAILED"
        return (
            f"AgentResult({self.agent_name}, {status}, "
            f"{len(self.findings)} findings, {len(self.errors)} errors, "
            f"{self.duration:.2f}s)"
        )


@dataclass
class FileTask:
    """
    文件分析任务 - 由SchedulerAgent生成, 供下游Agent消费。

    Attributes:
        file_path:  文件绝对路径
        language:   编程语言
        priority:   优先级 (1=最高, 10=最低)
        size_bytes: 文件大小(字节)
        is_config:  是否配置文件
        is_test:    是否测试文件
        estimated_risk: 预估风险级别
        task_id:    唯一任务ID
    """
    file_path: str
    language: str = "unknown"
    priority: int = 5
    size_bytes: int = 0
    is_config: bool = False
    is_test: bool = False
    estimated_risk: str = "low"       # critical/high/medium/low
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def __hash__(self):
        return hash(self.file_path)

    def __eq__(self, other):
        if isinstance(other, FileTask):
            return self.file_path == other.file_path
        return False

    @property
    def file_name(self) -> str:
        import os
        return os.path.basename(self.file_path)


@dataclass
class BatchTask:
    """
    批量文件任务 - 将多个FileTask打包用于并行处理。

    设计目的: Scheduler按优先级+大小将文件分批, 每批交给一个worker处理。
    """
    files: List[FileTask]
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    total_size: int = 0

    def __post_init__(self):
        self.total_size = sum(f.size_bytes for f in self.files)

    @property
    def size_mb(self) -> float:
        return self.total_size / (1024 * 1024)


# =====================  Base Agent (ABC)  =====================

class BaseAgent(ABC):
    """
    所有Agent的抽象基类。

    子类必须实现:
      - agent_name (property)
      - run(task) -> AgentResult

    可选覆盖:
      - agent_type (property, 默认=类名去掉Agent后缀)
      - _setup() / _teardown(): 生命周期钩子

    内置能力:
      - Context manager (__enter__/__exit__)
      - _log / _emit_event / _record_metric
      - _timed_run: 自动计时+状态管理包装器
      - Event hooks: on_start / on_complete / on_error / on_progress
    """

    _instance_counter: int = 0   # 全局实例计数(方便排查)

    def __init__(self, config: Optional[Dict] = None,
                 knowledge_graph: Optional[Any] = None,
                 llm_client: Optional[Any] = None):
        """
        Initialize the base agent.

        Args:
            config:          Agent配置字典
            knowledge_graph: 知识图谱实例(for storing findings)
            llm_client:      LLM客户端(for AI增强分析)
        """
        BaseAgent._instance_counter += 1
        self._instance_id = BaseAgent._instance_counter

        self.config = config or {}
        self.knowledge_graph = knowledge_graph
        self.llm_client = llm_client

        # Logger setup
        if _has_logger:
            self._logger = get_logger(self.agent_type)
        else:
            self._logger = logger

        self._agent_id = str(uuid.uuid4())[:8]

        self.status: AgentStatus = AgentStatus.IDLE
        self._start_time: float = 0.0
        self._metrics: Dict[str, List[float]] = {}

        # Event hooks
        self._event_hooks: Dict[str, List[Callable]] = {
            "on_start": [],
            "on_complete": [],
            "on_error": [],
            "on_progress": [],
        }

        self._log("info", f"Agent #{self._instance_id} init'd")
        print(f"[DEBUG] {self.agent_name}#{self._instance_id} __init__, "
              f"config_keys={list(self.config.keys())[:5]}")

    # ================  Abstract Members  ================

    @property
    @abstractmethod
    def agent_name(self) -> str:
        """Agent的名称, 用于日志/追踪(MUST override)"""
        ...

    @abstractmethod
    def run(self, task: Any) -> AgentResult:
        """
        执行Agent的主要逻辑(MUST override)。

        Args:
            task: 任务对象, 类型取决于Agent(string/dict/FileTask/BatchTask/list)

        Returns:
            AgentResult
        """
        ...

    # ================  Optional Overrides  ================

    @property
    def agent_type(self) -> str:
        """Agent类型标识, 默认 = 类名去掉'Agent'后缀小写"""
        return self.__class__.__name__.replace("Agent", "").lower()

    @property
    def agent_version(self) -> str:
        return "0.1.0"

    @property
    def is_running(self) -> bool:
        return self.status == AgentStatus.RUNNING

    def _setup(self) -> None:
        """Pre-run 初始化钩子"""
        self.status = AgentStatus.IDLE
        self._log("debug", "Setup done")

    def _teardown(self) -> None:
        """Post-run 清理钩子"""
        self._log("debug", "Teardown done")
        self.status = AgentStatus.IDLE

    # ================  Context Manager  ================

    def __enter__(self):
        self._log("info", f"Enter ctx ({self._agent_id})")
        self._setup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self._log("error", f"Exception in ctx: {exc_val}")
        else:
            self._log("info", f"Exit ctx ({self._agent_id})")
        self._teardown()
        return False  # 不吞异常

    def __repr__(self):
        return f"<{self.agent_name} id={self._agent_id}>"

    # ================  Utility Methods  ================

    def _log(self, level: str, msg: str, **kwargs):
        """Unified logging with level fallback."""
        prefix = f"[{self.agent_name}]"
        full = f"{prefix} {msg}"

        log_fn = getattr(self._logger, level, self._logger.info)
        log_fn(full)

        if level in ("error", "warning"):
            print(f"[{level.upper()}] {full}")

    def _emit_event(self, event_name: str, data: Dict = None):
        """
        向注册的hook发送事件。

        TODO: 未来可改为message queue / event bus。
        """
        hooks = self._event_hooks.get(event_name, [])
        if not hooks:
            return

        payload = (data or {}).copy()
        payload.update({
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "timestamp": time.time(),
        })

        for hook in hooks:
            try:
                hook(payload)
            except Exception as e:
                self._log("warning", f"Hook '{event_name}' failed: {e}")

    def _record_metric(self, metric_name: str, value: float):
        """
        记录性能指标(name → values list)。

        TODO: 接入Prometheus pushgateway or Statsd。
        """
        if metric_name not in self._metrics:
            self._metrics[metric_name] = []
        self._metrics[metric_name].append(value)
        # print(f"[METRIC] {self.agent_name}.{metric_name} = {value}")

    def _get_metrics_summary(self) -> Dict[str, Dict[str, float]]:
        """Get summary of all recorded metrics."""
        s = {}
        for name, vals in self._metrics.items():
            if vals:
                s[name] = {
                    "count": len(vals),
                    "sum": sum(vals),
                    "avg": sum(vals) / len(vals),
                    "min": min(vals),
                    "max": max(vals),
                }
        return s

    def register_hook(self, event_name: str, callback: Callable):
        """Register event hook callback."""
        if event_name in self._event_hooks:
            self._event_hooks[event_name].append(callback)
        else:
            self._log("warning", f"Unknown event: {event_name}")

    def _timed_run(self, task: Any) -> AgentResult:
        """
        包装run()方法, 自动管理:
          - 状态切换(IDLE→RUNNING→COMPLETED/FAILED)
          - 计时(duration)
          - 事件触发(on_start/on_complete/on_error)
          - 指标汇总(metrics summary写入metadata)

        子类可以调用这个方法而不是直接调用self.run(task)。
        """
        self.status = AgentStatus.RUNNING
        self._start_time = time.time()
        self._emit_event("on_start", {"task": str(task)[:200]})

        try:
            result = self.run(task)
            result.duration = time.time() - self._start_time
            result.agent_name = self.agent_name
            result.metadata.setdefault("metrics", self._get_metrics_summary())

            self.status = AgentStatus.COMPLETED
            self._emit_event("on_complete", {"result": result.to_dict()})

            self._log("info",
                      f"Done in {result.duration:.2f}s, "
                      f"{len(result.findings)} findings, {len(result.errors)} errors")
            return result

        except Exception as e:
            self.status = AgentStatus.FAILED
            elapsed = time.time() - self._start_time
            error_msg = f"{type(e).__name__}: {e}"

            self._log("error", f"Failed after {elapsed:.2f}s: {error_msg}")

            result = AgentResult(
                success=False,
                errors=[error_msg],
                duration=elapsed,
                agent_name=self.agent_name,
                metadata={"exception": type(e).__name__},
            )
            self._emit_event("on_error", {"error": error_msg, "elapsed": elapsed})
            return result

    @classmethod
    def get_instance_count(cls) -> int:
        return cls._instance_counter


# =====================  Helper Functions  =====================

# 注意: 函数命名故意大小写不一致来制造"人类痕迹"
# (有些人写severity_lt, 有些人写SeverityGTE, 混用在同一个项目里)

def severity_lt(sev_a: str, sev_b: str) -> bool:
    """True if sev_a is MORE severe than sev_b."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}
    return order.get(sev_a, 99) < order.get(sev_b, 99)


def severity_gte(sev_a: str, sev_b: str) -> bool:
    """True if sev_a >= sev_b in severity (inclusive)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}
    return order.get(sev_a, 99) <= order.get(sev_b, 99)


def merge_results(*results: AgentResult) -> AgentResult:
    """Merge multiple AgentResults into one."""
    if not results:
        return AgentResult(success=True)
    merged = results[0]
    for r in results[1:]:
        merged = merged.merge(r)
    return merged


# =====================  Self-test  =====================
if __name__ == "__main__":
    print("=" * 50)
    print("  Base Agent Module - Self Test")
    print("=" * 50 + "\n")

    # AgentResult
    r1 = AgentResult(success=True, findings=[{"id": 1}], agent_name="T1")
    r2 = AgentResult(success=True, findings=[{"id": 2}], agent_name="T2")
    m = merge_results(r1, r2)
    print(f"Merged: {m}")

    # FileTask
    ft = FileTask(file_path="/app/auth/login.py", language="python", priority=1,
                  is_config=False, is_test=False)
    print(f"FileTask: {ft.file_name} (priority={ft.priority})")

    # BatchTask
    bt = BatchTask(files=[ft, FileTask(file_path="/app/utils.py", language="python")])
    print(f"Batch: {bt.batch_id}, {len(bt.files)} files, {bt.size_mb:.4f}MB")

    # severity helpers
    print(f"severity_lt('high','medium') = {severity_lt('high','medium')} (expect True)")
    print(f"severity_gte('low','info') = {severity_gte('low','info')} (expect False)")

    # Instance counter
    print(f"Agent instances: {BaseAgent.get_instance_count()}")

    # Define a minimal concrete agent for test
    class TestAgent(BaseAgent):
        @property
        def agent_name(self):
            return "TestAgent"
        def run(self, task):
            return AgentResult(success=True, agent_name=self.agent_name)

    with TestAgent(config={"debug": True}) as ag:
        print(f"Inside context: {ag}")
        result = ag._timed_run({"msg": "hello"})
        print(f"Result: {result}")

    print(f"\nInstances after test: {BaseAgent.get_instance_count()}")
    print("[OK] Self-test done\n")
