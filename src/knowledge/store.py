# -*- coding: utf-8 -*-
"""知识图谱持久化存储 — JSON序列化"""
import json
import os
from pathlib import Path
from typing import Optional
from .graph import KnowledgeGraph

# 自动保存间隔(变更次数)
AUTO_SAVE_THRESHOLD = 50


class GraphStore:
    """知识图谱的持久层"""

    def __init__(self, auto_save: bool = True):
        self._graph: Optional[KnowledgeGraph] = None
        self._save_path: Optional[str] = None
        self._change_count = 0
        self._auto_save = auto_save

    def attach(self, graph: KnowledgeGraph, save_path: Optional[str] = None):
        """绑定一个KnowledgeGraph实例"""
        self._graph = graph
        self._save_path = save_path

    def save(self, graph: KnowledgeGraph, path: str):
        """保存到JSON文件"""
        data = graph.to_dict()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[GraphStore] 已保存到 {path}")  # debug

    def load(self, path: str) -> KnowledgeGraph:
        """从JSON加载"""
        if not os.path.exists(path):
            print(f"[GraphStore] 文件不存在: {path}")
            return KnowledgeGraph()

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        graph = KnowledgeGraph.from_dict(data)
        print(f"[GraphStore] 加载完成: {graph.node_count}节点, {graph.edge_count}边")
        return graph

    def auto_save(self, path: Optional[str] = None):
        """防抖自动保存"""
        self._change_count += 1
        if self._change_count >= AUTO_SAVE_THRESHOLD and self._graph and self._save_path:
            self.save(self._graph, self._save_path)
            self._change_count = 0

    def export_nodes(self, graph: KnowledgeGraph, node_type: str = None) -> list:
        """导出特定类型的节点"""
        nodes = graph._nodes.values()
        if node_type:
            nodes = [n for n in nodes if n.type.value == node_type]
        return [n.to_dict() for n in nodes]
