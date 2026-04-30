# -*- coding: utf-8 -*-
"""知识图谱 - 内存中的有向图, 线程安全"""
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Set
from .nodes import KnowledgeNode, NodeType
from .edges import KnowledgeEdge, RelationType


class KnowledgeGraph:
    """Agent共享的有向知识图谱"""

    def __init__(self):
        self._nodes: Dict[str, KnowledgeNode] = {}
        self._edges: List[KnowledgeEdge] = []
        # 邻接表: node_id -> [(目标node_id, edge)]
        self._adj: Dict[str, List[tuple]] = defaultdict(list)
        self._reverse_adj: Dict[str, List[tuple]] = defaultdict(list)
        self._lock = threading.Lock()  # 就一个简单锁, 够了
        # print("[Graph] 知识图谱初始化")  # debug

    def add_node(self, node: KnowledgeNode) -> str:
        """添加节点, 返回节点ID"""
        with self._lock:
            self._nodes[node.id] = node
            return node.id

    def add_edge(self, edge: KnowledgeEdge):
        """添加边"""
        with self._lock:
            if edge.source_id not in self._nodes:
                return  # 源节点不存在就跳过, 不报错
            if edge.target_id not in self._nodes:
                return
            self._edges.append(edge)
            self._adj[edge.source_id].append((edge.target_id, edge))
            self._reverse_adj[edge.target_id].append((edge.source_id, edge))

    def get_node(self, node_id: str) -> Optional[KnowledgeNode]:
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str, direction: str = "out") -> List[tuple]:
        """获取邻居节点: direction='out' 出边, 'in' 入边"""
        if direction == "out":
            return self._adj.get(node_id, [])
        return self._reverse_adj.get(node_id, [])

    def get_nodes_by_type(self, node_type: NodeType) -> List[KnowledgeNode]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def get_findings_for_file(self, file_path: str) -> List[KnowledgeNode]:
        """通过文件名(properties里的file_path)查找相关的finding节点"""
        results = []
        for node in self._nodes.values():
            if node.type == NodeType.FINDING and node.properties.get("file_path") == file_path:
                results.append(node)
        return results

    def get_fixes_for_finding(self, finding_id: str) -> List[KnowledgeNode]:
        """找某个漏洞的所有修复节点"""
        fixes = []
        for target_id, edge in self._adj.get(finding_id, []):
            if edge.relation_type == RelationType.FIXES:
                node = self._nodes.get(target_id)
                if node and node.type == NodeType.FIX:
                    fixes.append(node)
        return fixes

    def get_all_findings(self) -> List[KnowledgeNode]:
        return self.get_nodes_by_type(NodeType.FINDING)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "nodes": [n.to_dict() for n in self._nodes.values()],
                "edges": [e.to_dict() for e in self._edges],
            }

    @classmethod
    def from_dict(cls, data: dict) -> "KnowledgeGraph":
        graph = cls()
        for ndata in data.get("nodes", []):
            graph.add_node(KnowledgeNode.from_dict(ndata))
        for edata in data.get("edges", []):
            graph.add_edge(KnowledgeEdge(
                source_id=edata["source_id"],
                target_id=edata["target_id"],
                relation_type=RelationType(edata["relation_type"]),
                properties=edata.get("properties", {}),
            ))
        return graph

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def clear(self):
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._adj.clear()
            self._reverse_adj.clear()

    def add_files(self, file_tasks: list):
        """便捷方法 - 从scheduler批量添加文件节点"""
        for ft in file_tasks:
            node = KnowledgeNode(
                type=NodeType.FILE,
                properties=ft if isinstance(ft, dict) else {
                    "file_path": getattr(ft, "file_path", ""),
                    "language": getattr(ft, "language", "unknown"),
                    "priority": getattr(ft, "priority", 5),
                },
            )
            self.add_node(node)

    def add_findings(self, findings: list):
        """便捷方法 - 从analyzer批量添加finding节点"""
        for f in findings:
            node = KnowledgeNode(
                type=NodeType.FINDING,
                properties=f,
            )
            self.add_node(node)

    # FIXME: 考虑支持子图查询, 目前太简陋
