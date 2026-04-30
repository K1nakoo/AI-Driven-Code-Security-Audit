# -*- coding: utf-8 -*-
"""知识图谱边 — 节点之间的关系"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class RelationType(str, Enum):
    CONTAINS = "contains"      # 文件包含漏洞
    FIXES = "fixes"            # 修复修复了漏洞
    ANALYZED = "analyzed"      # Agent分析了文件/漏洞
    DEPENDS_ON = "depends_on"  # 依赖关系
    FLOWS_TO = "flows_to"      # 数据流: source→sink
    TRIGGERED_BY = "triggered_by"  # 触发关系
    HAS_SOURCE = "has_source"  # 漏洞有数据源(source)
    HAS_SINK = "has_sink"      # 漏洞有数据汇(sink)


@dataclass
class KnowledgeEdge:
    source_id: str
    target_id: str
    relation_type: RelationType
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type.value,
            "properties": self.properties,
        }

    def __hash__(self):
        return hash((self.source_id, self.target_id, self.relation_type))
