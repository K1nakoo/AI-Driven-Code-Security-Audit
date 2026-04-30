# -*- coding: utf-8 -*-
"""任务队列 - 优先级队列，线程安全"""
import uuid
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Task:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: str = ""                     # scan, analyze, fix, verify
    data: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5                  # 1-10, 10最高
    status: TaskStatus = TaskStatus.PENDING
    agent_type: str = ""               # 目标Agent类型
    retries: int = 0
    max_retries: int = 3
    parent_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "priority": self.priority,
            "status": self.status.value,
            "agent_type": self.agent_type,
            "retries": self.retries,
            "created_at": self.created_at,
        }


@dataclass
class TaskStats:
    total: int = 0
    pending: int = 0
    running: int = 0
    done: int = 0
    failed: int = 0
    skipped: int = 0


class TaskQueue:
    """线程安全的优先级任务队列"""

    def __init__(self, max_size: int = 10000):
        self._queue: List[Task] = []
        self._lock = threading.Lock()
        self._max_size = max_size
        self._completed_tasks: List[Task] = []  # 历史记录

    def enqueue(self, task: Task) -> bool:
        """添加任务到队列"""
        with self._lock:
            if len(self._queue) >= self._max_size:
                print(f"[TaskQueue] 队列已满 ({self._max_size})")
                return False
            self._queue.append(task)
            # 按优先级降序+时间升序
            self._queue.sort(key=lambda t: (-t.priority, t.created_at))
            return True

    def dequeue(self) -> Optional[Task]:
        """取出最高优先级任务"""
        with self._lock:
            if not self._queue:
                return None
            task = self._queue.pop(0)
            task.status = TaskStatus.RUNNING
            task.updated_at = datetime.now().isoformat()
            return task

    def peek(self) -> Optional[Task]:
        """查看但不取出最高优先级任务"""
        with self._lock:
            return self._queue[0] if self._queue else None

    def mark_done(self, task_id: str):
        with self._lock:
            for task in self._queue:
                if task.id == task_id:
                    task.status = TaskStatus.DONE
                    task.updated_at = datetime.now().isoformat()
                    self._queue.remove(task)
                    self._completed_tasks.append(task)
                    return

    def mark_failed(self, task_id: str, error: str = ""):
        with self._lock:
            for task in self._queue:
                if task.id == task_id:
                    task.error = error
                    task.retries += 1
                    if task.retries >= task.max_retries:
                        task.status = TaskStatus.FAILED
                        self._queue.remove(task)
                        self._completed_tasks.append(task)
                    else:
                        task.status = TaskStatus.PENDING  # 重试
                    task.updated_at = datetime.now().isoformat()
                    return

    def mark_skipped(self, task_id: str):
        with self._lock:
            for task in self._queue:
                if task.id == task_id:
                    task.status = TaskStatus.SKIPPED
                    task.updated_at = datetime.now().isoformat()
                    self._queue.remove(task)
                    self._completed_tasks.append(task)
                    return

    def get_stats(self) -> TaskStats:
        with self._lock:
            all_tasks = self._queue + self._completed_tasks
            stats = TaskStats(total=len(all_tasks))
            for t in all_tasks:
                if t.status == TaskStatus.PENDING:
                    stats.pending += 1
                elif t.status == TaskStatus.RUNNING:
                    stats.running += 1
                elif t.status == TaskStatus.DONE:
                    stats.done += 1
                elif t.status == TaskStatus.FAILED:
                    stats.failed += 1
                elif t.status == TaskStatus.SKIPPED:
                    stats.skipped += 1
            return stats

    def get_pending_count(self) -> int:
        return self.get_stats().pending

    def get_all_tasks(self) -> List[Task]:
        with self._lock:
            return list(self._queue) + list(self._completed_tasks)

    def clear_completed(self):
        with self._lock:
            self._completed_tasks.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue)

    def __len__(self):
        return self.size
