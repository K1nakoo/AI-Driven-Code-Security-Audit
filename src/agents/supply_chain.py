# -*- coding: utf-8 -*-
"""供应链安全Agent — 依赖漏洞扫描 + typosquatting检测"""
import os
import json
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseAgent, AgentResult
from ..knowledge.nodes import KnowledgeNode, NodeType


class SupplyChainAgent(BaseAgent):
    """检查项目依赖安全性: 已知CVE、版本过时、依赖混淆"""

    @property
    def agent_name(self) -> str:
        return "SupplyChainAgent"

    def __init__(self, config=None, knowledge_graph=None, llm_client=None):
        super().__init__(config, knowledge_graph, llm_client)
        self.sc_config = config.get("supply_chain", {}) if config else {}

    def run(self, task) -> AgentResult:
        target = task.get("target_path", ".")
        start_t = time.perf_counter()

        self._log("info", f"开始供应链扫描: {target}")

        all_deps = []
        dependency_files = self._detect_dependency_files(target)
        self._log("info", f"检测到 {len(dependency_files)} 个依赖文件")

        findings = []
        errors = []

        for dep_file in dependency_files:
            try:
                deps = self._parse_dependencies(dep_file)
                all_deps.extend(deps)
            except Exception as e:
                errors.append({"file": dep_file, "error": str(e)})

        # 检查每个依赖项
        for dep in all_deps:
            try:
                result = self._check_dependency(dep, target)
                if result:
                    findings.append(result)
            except Exception as e:
                self._log("warning", f"检查依赖失败 {dep.get('name')}: {e}")

        # 存知识图谱
        if self.knowledge_graph:
            for f in findings:
                node = KnowledgeNode(
                    type=NodeType.SUPPLY_CHAIN,
                    properties={
                        "package": f.get("package", ""),
                        "version": f.get("version", ""),
                        "cve_id": f.get("cve_id", ""),
                        "severity": f.get("severity", "info"),
                        "type": f.get("type", "dependency"),
                    },
                )
                self.knowledge_graph.add_node(node)

        duration = time.perf_counter() - start_t
        self._log("info", f"供应链扫描完成: {len(findings)} 个风险")

        return AgentResult(
            success=True,
            agent_name=self.agent_name,
            findings=findings,
            errors=errors,
            metadata={
                "dependency_files": len(dependency_files),
                "total_deps": len(all_deps),
                "risks_found": len(findings),
            },
            duration=duration,
        )

    def _detect_dependency_files(self, path: str) -> List[str]:
        """发现项目依赖文件"""
        patterns = [
            "requirements.txt",
            "requirements/*.txt",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "pyproject.toml",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "go.mod",
            "go.sum",
            "Gemfile",
            "Gemfile.lock",
            "Cargo.toml",
            "Cargo.lock",
            "composer.json",
            "composer.lock",
        ]

        found = []
        base = Path(path)
        for pattern in patterns:
            if "*" in pattern:
                found.extend(str(p) for p in base.glob(pattern))
            else:
                fp = base / pattern
                if fp.exists():
                    found.append(str(fp))

        return found

    def _parse_dependencies(self, file_path: str) -> List[Dict]:
        """解析依赖文件"""
        if file_path.endswith("requirements.txt"):
            return self._parse_requirements(file_path)
        elif file_path.endswith("package.json"):
            return self._parse_package_json(file_path)
        elif file_path.endswith("go.mod"):
            return self._parse_go_mod(file_path)
        elif file_path.endswith("pyproject.toml"):
            return self._parse_pyproject(file_path)
        return []

    def _parse_requirements(self, file_path: str) -> List[Dict]:
        """解析pip requirements.txt"""
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # 处理各种格式: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg
                    pkg = line.split("==")[0].split(">=")[0].split("~=")[0].split("<")[0].split("!=")[0].strip()
                    ver = ""
                    if "==" in line:
                        ver = line.split("==")[1].split(";")[0].strip()
                    deps.append({"name": pkg, "version": ver, "ecosystem": "pypi", "file": file_path})
        except Exception as e:
            print(f"[SupplyChain] 解析requirements失败: {e}")
        return deps

    def _parse_package_json(self, file_path: str) -> List[Dict]:
        """解析npm package.json"""
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for dep_type in ("dependencies", "devDependencies"):
                for name, version in data.get(dep_type, {}).items():
                    clean_ver = version.lstrip("^~>=<")
                    deps.append({
                        "name": name,
                        "version": clean_ver,
                        "ecosystem": "npm",
                        "dep_type": dep_type,
                        "file": file_path,
                    })
        except Exception as e:
            print(f"[SupplyChain] 解析package.json失败: {e}")
        return deps

    def _parse_go_mod(self, file_path: str) -> List[Dict]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                in_require = False
                for line in f:
                    line = line.strip()
                    if line.strip() == "require (":
                        in_require = True
                        continue
                    if in_require and line == ")":
                        in_require = False
                        continue
                    if in_require and line:
                        parts = line.split()
                        if len(parts) >= 2:
                            deps.append({
                                "name": parts[0],
                                "version": parts[1],
                                "ecosystem": "go",
                                "file": file_path,
                            })
        except Exception as e:
            print(f"[SupplyChain] 解析go.mod失败: {e}")
        return deps

    def _parse_pyproject(self, file_path: str) -> List[Dict]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            # 简单的TOML解析(偷懒不用toml库)
            import re
            in_deps = False
            for line in content.split("\n"):
                if "[tool.poetry.dependencies]" in line or "[project.dependencies]" in line:
                    in_deps = True
                    continue
                if in_deps and line.strip().startswith("["):
                    in_deps = False
                    continue
                if in_deps:
                    m = re.match(r'(\w[\w-]*)\s*=\s*["\'](.+?)["\']', line.strip())
                    if m:
                        deps.append({
                            "name": m.group(1),
                            "version": m.group(2).lstrip("^~>=<*"),
                            "ecosystem": "pypi",
                            "file": file_path,
                        })
        except Exception as e:
            print(f"[SupplyChain] 解析pyproject失败: {e}")
        return deps

    def _check_dependency(self, dep: dict, project_path: str) -> Optional[dict]:
        """检查单个依赖项的安全性"""
        name = dep.get("name", "")
        version = dep.get("version", "")
        ecosystem = dep.get("ecosystem", "pypi")

        # 1. 尝试 pip-audit
        if ecosystem == "pypi":
            return self._scan_python_dep(name, version)
        # 2. 尝试 npm audit
        elif ecosystem == "npm":
            return self._scan_node_dep(name, version, project_path)

        # 3. 依赖混淆检测(通用)
        confusion = self._check_dependency_confusion(name)
        if confusion:
            return confusion

        return None

    def _scan_python_dep(self, name: str, version: str) -> Optional[dict]:
        """pip-audit检查Python依赖"""
        # 尝试运行pip-audit
        try:
            result = subprocess.run(
                ["pip-audit", "--format", "json", "--requirement", "requirements.txt"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                audit_data = json.loads(result.stdout)
                for vuln in audit_data.get("dependencies", []):
                    if vuln.get("name") == name:
                        return {
                            "package": name,
                            "version": version,
                            "severity": "high",
                            "cve_id": vuln.get("vulns", [{}])[0].get("id", "unknown"),
                            "description": str(vuln.get("vulns", [{}])[0].get("description", "")),
                            "fix_version": vuln.get("vulns", [{}])[0].get("fix_versions", []),
                            "type": "known_vulnerability",
                        }
        except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
            pass  # pip-audit not available

        # 基础检查: 版本是否为空
        if not version:
            return {
                "package": name,
                "version": "unknown",
                "severity": "medium",
                "cve_id": "",
                "description": f"依赖 {name} 未指定版本(可能安装到最新版存在未知风险)",
                "type": "unpinned_version",
            }

        return None

    def _scan_node_dep(self, name: str, version: str, project_path: str) -> Optional[dict]:
        """npm audit检查Node.js依赖"""
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True, timeout=120,
                cwd=project_path,
            )
            if result.returncode != 0:
                # npm audit有告警时exit code非0
                audit = json.loads(result.stdout)
                advisories = audit.get("advisories", {})
                for adv_id, adv in advisories.items():
                    if adv.get("module_name") == name:
                        return {
                            "package": name,
                            "version": version,
                            "severity": adv.get("severity", "medium"),
                            "cve_id": adv.get("cves", [""])[0],
                            "description": adv.get("title", ""),
                            "fix_version": adv.get("patched_versions", ""),
                            "type": "known_vulnerability",
                        }
        except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
            pass

        return None

    def _check_dependency_confusion(self, package_name: str) -> Optional[dict]:
        """依赖混淆/typosquatting检测"""
        # 检查是否有拼写相似的知名包
        known_packages = {
            "requests", "flask", "django", "numpy", "pandas", "pytorch", "tensorflow",
            "express", "react", "lodash", "axios", "moment", "jquery",
        }

        name_lower = package_name.lower()
        # 检查是否和知名包只有1-2字符差异
        for known in known_packages:
            if name_lower == known:
                break
            if self._levenshtein(name_lower, known) <= 2:
                return {
                    "package": package_name,
                    "version": "",
                    "severity": "critical",
                    "cve_id": "",
                    "description": f"疑似依赖混淆: {package_name} 与知名包 {known} 相似(编辑距离={self._levenshtein(name_lower, known)})",
                    "type": "dependency_confusion",
                }

        return None

    def _levenshtein(self, s1: str, s2: str) -> int:
        """简单的编辑距离"""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                # 插入/删除/替换
                curr.append(min(
                    prev[j + 1] + 1,      # 插入
                    curr[j] + 1,            # 删除
                    prev[j] + (c1 != c2),   # 替换
                ))
            prev = curr
        return prev[-1]
