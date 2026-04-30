# -*- coding: utf-8 -*-
"""管线管理器 — Agent执行序列管理"""
import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable


@dataclass
class StageResult:
    stage_name: str = ""
    agent_type: str = ""
    duration: float = 0.0
    findings_count: int = 0
    errors: List[str] = field(default_factory=list)
    success: bool = True


class PipelineContext:
    """管线上下文 — 在Stage之间传递状态"""
    def __init__(self):
        self.state: Dict[str, Any] = {}
        self.stage_results: List[StageResult] = []
        self.findings: List[dict] = []
        self.fixes: List[dict] = []
        self.errors: List[dict] = []
        self.metadata: Dict[str, Any] = {}

    def get(self, key: str, default=None):
        return self.state.get(key, default)

    def set(self, key: str, value):
        self.state[key] = value

    def add_finding(self, finding: dict):
        self.findings.append(finding)

    def add_fix(self, fix: dict):
        self.fixes.append(fix)

    def add_error(self, error: dict):
        self.errors.append(error)

    def to_dict(self) -> dict:
        return {
            "findings_count": len(self.findings),
            "fixes_count": len(self.fixes),
            "errors_count": len(self.errors),
            "stages": [sr.__dict__ for sr in self.stage_results],
        }


class Pipeline:
    """用户可配置Agent执行管线"""

    def __init__(self, name: str = "default"):
        self.name = name
        self._stages: Dict[str, dict] = {}  # name -> {agent, condition, depends_on}
        self._order: List[str] = []         # 执行顺序

    def add_stage(self, name: str, agent, condition: Callable = None,
                  depends_on: List[str] = None):
        """添加管线阶段"""
        self._stages[name] = {
            "agent": agent,
            "condition": condition or (lambda ctx: True),  # 默认总是执行
            "depends_on": depends_on or [],
        }
        if name not in self._order:
            self._order.append(name)

    def get_stage(self, name: str):
        return self._stages.get(name, {}).get("agent")

    def execute(self, initial_task: dict = None) -> PipelineContext:
        """顺序执行所有阶段"""
        ctx = PipelineContext()
        ctx.set("task", initial_task or {})

        print(f"[Pipeline] '{self.name}' 开始执行 ({len(self._stages)}个阶段)")

        for stage_name in self._order:
            stage = self._stages[stage_name]
            agent = stage["agent"]
            condition = stage["condition"]

            # 条件检查
            if not condition(ctx):
                print(f"[Pipeline] 跳过阶段: {stage_name} (条件不满足)")
                continue

            print(f"[Pipeline] 执行阶段: {stage_name} ({agent.agent_name})")
            t0 = time.perf_counter()

            try:
                # 构建当前阶段需要的task数据
                task_data = ctx.state.copy()
                # 把findings传进去(下一阶段需要)
                if ctx.findings:
                    task_data["findings"] = ctx.findings

                result = agent.run(task_data)

                # 记录结果
                sr = StageResult(
                    stage_name=stage_name,
                    agent_type=agent.agent_type,
                    duration=time.perf_counter() - t0,
                    findings_count=len(result.findings),
                    errors=[e.get("error", str(e)) for e in result.errors],
                    success=result.success,
                )
                ctx.stage_results.append(sr)

                # 合并findings
                for f in result.findings:
                    ctx.add_finding(f)

                # 合并errors
                for e in result.errors:
                    ctx.add_error(e)

                # 更新state
                ctx.state[f"{stage_name}_result"] = result

            except Exception as e:
                sr = StageResult(
                    stage_name=stage_name,
                    agent_type=agent.agent_type,
                    duration=time.perf_counter() - t0,
                    success=False,
                    errors=[str(e)],
                )
                ctx.stage_results.append(sr)
                ctx.add_error({"stage": stage_name, "error": str(e)})
                print(f"[Pipeline] 阶段失败: {e}")
                # FIXME: 失败后是否继续执行后续阶段? 目前是继续
                continue

        print(f"[Pipeline] '{self.name}' 执行完成")
        return ctx

    def execute_parallel(self, stage_tasks: List[Dict[str, Any]]) -> List[dict]:
        """并行执行多个Agent(同一级别)"""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(stage_tasks)) as executor:
            futures = {}
            for st in stage_tasks:
                agent = st["agent"]
                task_data = st.get("task_data", {})
                future = executor.submit(agent.run, task_data)
                futures[future] = st.get("name", agent.agent_name)

            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results.append({"name": name, "result": result})
                except Exception as e:
                    results.append({"name": name, "error": str(e)})

        return results

    def reset(self):
        """清空管线阶段"""
        self._stages.clear()
        self._order.clear()
