# -*- coding: utf-8 -*-
"""知识图谱节点定义 — knowledge graph nodes"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict
import uuid


class NodeType(str, Enum):
    FINDING = "finding"       # 漏洞发现
    FILE = "file"             # 被分析的文件
    FIX = "fix"               # 修复操作
    AGENT = "agent"           # Agent执行记录
    SUPPLY_CHAIN = "supply_chain"  # 供应链风险


@dataclass
class KnowledgeNode:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])  # 短ID够用了
    type: NodeType = NodeType.FINDING
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "properties": self.properties,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KnowledgeNode":
        return cls(
            id=data.get("id", ""),
            type=NodeType(data.get("type", "finding")),
            properties=data.get("properties", {}),
            created_at=data.get("created_at", ""),
        )
