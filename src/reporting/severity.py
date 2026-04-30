# -*- coding: utf-8 -*-
"""严重度定义 — 枚举 + 映射 + 颜色"""
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_sarif_level(cls, level_str: str) -> "Severity":
        m = {"error": cls.HIGH, "warning": cls.MEDIUM, "note": cls.LOW, "none": cls.INFO}
        return m.get(level_str.lower(), cls.INFO)

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 0.1:
            return cls.LOW
        return cls.INFO

    @property
    def color(self) -> str:
        """ANSI颜色码"""
        colors = {
            "critical": "\033[1;35m",  # 亮紫
            "high":     "\033[1;31m",  # 亮红
            "medium":   "\033[1;33m",  # 亮黄
            "low":      "\033[1;34m",  # 亮蓝
            "info":     "\033[1;37m",  # 亮灰
        }
        return colors.get(self.value, "\033[0m")

    @property
    def score(self) -> int:
        """数值化评分"""
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


# CVSS分数映射
CVE_SEVERITY_MAP = {
    (0.0, 0.1): Severity.INFO,
    (0.1, 4.0): Severity.LOW,
    (4.0, 7.0): Severity.MEDIUM,
    (7.0, 9.0): Severity.HIGH,
    (9.0, 10.1): Severity.CRITICAL,
}


class SeverityStats:
    """严重度统计"""

    def __init__(self):
        self.counts = {s: 0 for s in Severity}
        self.total = 0

    def add(self, severity: str):
        try:
            self.counts[Severity(severity)] += 1
            self.total += 1
        except ValueError:
            self.counts[Severity.INFO] += 1
            self.total += 1

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            **{s.value: c for s, c in self.counts.items()},
        }
