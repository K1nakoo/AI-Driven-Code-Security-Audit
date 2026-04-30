# -*- coding: utf-8 -*-
"""
Scheduler Agent - 管道第一阶段: 文件发现 + 智能优先级调度

职责:
  1. 扫描项目目录, 发现所有代码文件
  2. 按安全关键度排序(配置文件/认证模块/数据库访问优先)
  3. 分批次输出 FileTask 列表供下游Agent并行消费

优先级规则:
  P1 (最高): 配置文件 + 密钥(.env, config.py, .pem等)
  P2:       认证/授权模块(auth.py, login.py, oauth等)
  P3:       数据库相关(models.py, db.py, query.py等)
  P4:       安全敏感工具(crypto, hashlib, subprocess等)
  P5-7:     普通业务代码(按语言)
  P8-9:     工具脚本/测试文件
  P10:      文档/其他

TODO: 支持增量扫描(git diff检测变更文件)
FIXME: 大项目(>10000文件)扫描可能需要优化, 当前O(n)能接受但可更好
"""

import os
import time
from collections import Counter
from dataclasses import asdict
from fnmatch import fnmatch
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# ---- 导入base模块 ----
from .base import BaseAgent, AgentResult, FileTask, BatchTask

# ---- 柔性导入 FileScanner (如果还没实现, 使用fallback) ----
try:
    from ..utils.file_scanner import FileScanner, scan_directory, detect_language
    _HAS_FILESCANNER = True
except ImportError:
    _HAS_FILESCANNER = False
    print("[WARN] FileScanner not available, using built-in fallback")

    def scan_directory(path: str, **kwargs) -> List[Path]:
        """内置fallback: 递归遍历常用代码扩展名"""
        exts = {'.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rb',
                '.php', '.cs', '.c', '.cpp', '.h', '.hpp', '.swift', '.rs',
                '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf',
                '.env', '.sh', '.bat', '.ps1', '.sql', '.html', '.css'}
        result = []
        for ext in exts:
            result.extend(Path(path).rglob(f'*{ext}'))
        return result

    def detect_language(file_path: str) -> str:
        """内置fallback: 扩展名 → language"""
        ext = Path(file_path).suffix.lower()
        mapping = {
            '.py': 'python', '.pyx': 'python', '.pyi': 'python',
            '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript',
            '.java': 'java', '.kt': 'kotlin', '.groovy': 'groovy',
            '.go': 'go', '.rb': 'ruby', '.rs': 'rust',
            '.php': 'php', '.cs': 'csharp',
            '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.hpp': 'cpp',
            '.swift': 'swift', '.sql': 'sql',
            '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json',
            '.toml': 'toml', '.ini': 'config', '.cfg': 'config',
            '.env': 'config', '.sh': 'shell', '.bat': 'shell',
            '.html': 'html', '.css': 'css',
        }
        return mapping.get(ext, 'unknown')


# ====================  Priority Patterns  ====================

# CRITICAL: 密钥/凭证/配置 (P1)
CRITICAL_PATTERNS = [
    '*.env', '*.env.*', '.env*', '*secret*', '*credential*',
    '*config*.py', '*settings*.py', '*config*.yaml', '*config*.yml',
    '*config*.json', '*config*.toml',
    'application*.yml', 'application*.yaml', 'application*.properties',
    'appsettings*.json', 'web.config',
    'Dockerfile*', 'docker-compose*.yml', '*.dockerfile',
    '.gitlab-ci.yml', 'Jenkinsfile', 'Makefile',
    '*/.github/workflows/*.yml', '*/.github/workflows/*.yaml',
    '*.pem', '*.key', '*.p12', '*.pfx', '*.jks', '*.keystore',
]

# HIGH: 认证/授权/加密 (P2)
HIGH_PATTERNS = [
    '*auth*', '*login*', '*logout*', '*register*', '*signup*',
    '*password*', '*session*', '*token*', '*jwt*', '*oauth*', '*sso*',
    '*permission*', '*rbac*', '*role*', '*access*control*', '*acl*',
    '*crypto*', '*cipher*', '*encrypt*', '*decrypt*', '*hash*',
    '*signature*', '*verify*', '*ssl*', '*tls*', '*certificate*',
    '*csrf*', '*xss*', '*sanitize*', '*validate*', '*escape*',
]

# MEDIUM: 数据库/输入/网络/模板 (P3-P4)
MEDIUM_PATTERNS = [
    '*model*', '*schema*', '*migration*', '*db*', '*database*',
    '*orm*', '*query*', '*repository*', '*dao*', '*dal*',
    '*upload*', '*download*', '*import*', '*export*',
    '*serialize*', '*deserialize*', '*parse*', '*unmarshal*',
    '*request*', '*response*', '*fetch*', '*api*', '*client*',
    '*template*', '*view*', '*render*', '*jinja*', '*ejs*',
    '*subprocess*', '*exec*', '*eval*', '*shell*', '*cmd*',
]

# LOW: 测试文件降级用
TEST_INDICATORS = [
    'test_', '_test.', '/tests/', '/test/', '__test__',
    'spec.', '_spec.', '-test.', '-spec.',
    'conftest.py', 'setup.py', '__init__.py',
]


class SchedulerAgent(BaseAgent):
    """
    管道调度器: 扫描项目 → 创建FileTask → 按优先级分批。

    Usage:
        scheduler = SchedulerAgent(config={"batch_size": 10})
        result = scheduler.run({"root_path": "./myproject"})
        batches = result.metadata["batches"]
    """

    def __init__(self, config: Optional[Dict] = None,
                 knowledge_graph: Any = None, llm_client: Any = None):
        super().__init__(config, knowledge_graph, llm_client)

        # 解析配置
        self.batch_size = self.config.get("batch_size", 10)
        self.max_batch_bytes = self.config.get("max_batch_bytes", 10 * 1024 * 1024)
        self.ignore_tests = self.config.get("ignore_tests", False)
        self.ignore_patterns = self.config.get("ignore_patterns", [
            '.git', '__pycache__', 'node_modules', '.venv', 'venv',
            'dist', 'build', '.tox', '.mypy_cache', '.pytest_cache',
            '.codeql', 'bower_components', '.idea', '.vscode',
        ])
        self.debug = self.config.get("debug", False)

        # 初始化scanner
        self.scanner = None
        if _HAS_FILESCANNER:
            self.scanner = FileScanner(
                exclude_dirs=self.ignore_patterns,
                exclude_patterns=self.config.get("exclude_patterns"),
            )

        print(f"[DEBUG] SchedulerAgent init'd, batch_size={self.batch_size}")

    # ====================  Abstract Implementations  ====================

    @property
    def agent_name(self) -> str:
        return "SchedulerAgent"

    @property
    def agent_type(self) -> str:
        return "scheduler"

    def run(self, task: Any) -> AgentResult:
        """
        Execute file discovery and scheduling.

        Args:
            task: str (root_path) | dict {'root_path':..., 'files':[...]}
                  | FileTask | BatchTask

        Returns:
            AgentResult with file tasks in metadata["batches"]
        """
        print(f"\n{'='*60}")
        print(f"[SchedulerAgent] File Discovery Start")
        print(f"{'='*60}")

        t0 = time.time()

        try:
            # 1. 解析输入
            root, files = self._parse_task(task)
            print(f"[SchedulerAgent] Root={root}, pre_files={len(files)}")

            # 2. 发现文件
            if files:
                paths = [Path(f) if isinstance(f, str) else f for f in files]
            elif root:
                paths = self._discover_files(root)
            else:
                return AgentResult(
                    success=False, errors=["No root or file list"],
                    agent_name=self.agent_name,
                )

            print(f"[SchedulerAgent] Found {len(paths)} files")

            # 3. 创建FileTask + 优先级排序
            file_tasks = self._create_tasks(paths)
            file_tasks = self._apply_priorities(file_tasks)
            self._sort_by_priority(file_tasks)

            print(f"[SchedulerAgent] {len(file_tasks)} tasks created")
            if self.debug:
                self._print_priority_dist(file_tasks)

            # 4. 分批
            batches = self._batch_tasks(file_tasks)
            print(f"[SchedulerAgent] {len(batches)} batches")

            # 5. 存入知识图谱 (if available)
            if self.knowledge_graph:
                try:
                    self.knowledge_graph.add_files(
                        [asdict(ft) for ft in file_tasks]
                    )
                except Exception as e:
                    print(f"[WARN] KG write failed: {e}")

            elapsed = time.time() - t0
            self._record_metric("files", len(file_tasks))
            self._record_metric("batches", len(batches))
            self._record_metric("scan_time", elapsed)

            return AgentResult(
                success=True,
                findings=[],
                metadata={
                    "total_files": len(file_tasks),
                    "total_batches": len(batches),
                    "batches": [self._batch_to_dict(b) for b in batches],
                    "priority_distribution": self._priority_dist(file_tasks),
                    "languages": list(set(t.language for t in file_tasks)),
                    "scan_duration": elapsed,
                },
                duration=elapsed,
                agent_name=self.agent_name,
            )

        except Exception as e:
            elapsed = time.time() - t0
            self._log("error", f"Schedule failed: {e}")
            import traceback
            traceback.print_exc()
            return AgentResult(
                success=False,
                errors=[str(e)],
                duration=elapsed,
                agent_name=self.agent_name,
            )

    # ====================  Internal: Discovery  ====================

    def _parse_task(self, task: Any) -> Tuple[Optional[str], List[str]]:
        """Parse flexible task formats."""
        if isinstance(task, str):
            return task, []
        if isinstance(task, dict):
            return task.get("root_path") or task.get("root", ""), \
                   task.get("files") or task.get("file_list", [])
        if isinstance(task, FileTask):
            return None, [task.file_path]
        if isinstance(task, BatchTask):
            return None, [f.file_path for f in task.files]
        return None, []

    def _discover_files(self, root: str) -> List[Path]:
        """Discover code files in project dir."""
        root_p = Path(root)
        if not root_p.exists():
            raise FileNotFoundError(f"Root not found: {root}")

        if self.scanner:
            return self.scanner.scan_directory(str(root_p))

        # Fallback
        all_files = scan_directory(str(root_p))
        filtered = []
        for f in all_files:
            f_str = str(f)
            if any(pat in f_str for pat in self.ignore_patterns):
                continue
            filtered.append(f)
        return filtered

    # ====================  Internal: Task Creation  ====================

    def _create_tasks(self, paths: List[Path]) -> List[FileTask]:
        """Convert Path objects to FileTask objects."""
        tasks = []
        skipped = 0
        MAX_FILE = 2 * 1024 * 1024  # 2 MB

        for p in paths:
            try:
                if not p.exists():
                    skipped += 1
                    continue

                size = p.stat().st_size
                if size > MAX_FILE:
                    if self.debug:
                        print(f"[DEBUG] Skip large: {p.name} ({size/1024/1024:.1f}MB)")
                    skipped += 1
                    continue
                if size == 0:
                    skipped += 1
                    continue

                lang = detect_language(str(p))
                is_test = self._is_test_file(str(p))
                is_cfg = self._is_config_file(str(p))

                if self.ignore_tests and is_test:
                    skipped += 1
                    continue

                tasks.append(FileTask(
                    file_path=str(p.absolute()),
                    language=lang,
                    priority=5,  # placeholder
                    size_bytes=size,
                    is_config=is_cfg,
                    is_test=is_test,
                    estimated_risk=self._estimate_risk(str(p), lang),
                ))
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Task create fail: {p} ({e})")
                skipped += 1

        if skipped:
            print(f"[SchedulerAgent] Skipped {skipped} files")
        return tasks

    # ====================  Internal: Prioritization  ====================

    def _apply_priorities(self, tasks: List[FileTask]) -> List[FileTask]:
        """Assign priority scores based on security relevance."""
        for task in tasks:
            fpath = task.file_path.lower()
            fname = Path(task.file_path).name.lower()
            prio = 5  # default medium

            # P1: critical patterns
            if self._matches_any(fpath, CRITICAL_PATTERNS):
                prio = 1
            # P2: high-priority
            elif self._matches_any(fpath, HIGH_PATTERNS):
                prio = 2
            # P3: medium
            elif self._matches_any(fpath, MEDIUM_PATTERNS):
                prio = 3
            # P4: config files
            elif task.is_config:
                prio = 4
            # P5-P8: language-based
            elif task.language in ("python", "javascript", "typescript", "java"):
                prio = 6
            elif task.language in ("go", "rust", "cpp", "csharp", "ruby"):
                prio = 7
            # P9: test files
            elif task.is_test:
                prio = 9
            else:
                prio = 8

            # FIXME: 应该基于estimated_risk微调priority
            # if task.estimated_risk == "critical":
            #     prio = max(1, prio - 2)

            task.priority = prio

        return tasks

    def _calc_priority(self, file_path: str) -> int:
        """
        [DEPRECATED] Old-style priority calc.
        Kept for backwards compat with code that calls scheduler._calc_priority().
        """
        path_lower = file_path.lower()
        fname = Path(file_path).name.lower()
        prio = 3
        for kw in ("auth", "login", "password", "admin", "token", "config"):
            if kw in fname:
                prio = 8
                break
        if any(p in fname for p in ("config", "settings", ".env")):
            prio = max(prio, 6)
        if "test" in fname:
            prio = min(prio, 2)
        return min(prio, 10)

    def _sort_by_priority(self, tasks: List[FileTask]):
        """Sort in-place: lowest priority number first, then by size."""
        tasks.sort(key=lambda t: (t.priority, t.size_bytes))
        if self.debug and tasks:
            print(f"[DEBUG] Top 3:")
            for t in tasks[:3]:
                print(f"  P{t.priority}: {Path(t.file_path).name} ({t.language})")

    # ====================  Internal: Batching  ====================

    def _batch_tasks(self, tasks: List[FileTask]) -> List[BatchTask]:
        """Group tasks into batches respecting size limits."""
        batches: List[BatchTask] = []
        current: List[FileTask] = []
        cur_bytes = 0

        for t in tasks:
            would_exceed = (
                len(current) >= self.batch_size or
                (cur_bytes + t.size_bytes) > self.max_batch_bytes
            )
            if would_exceed and current:
                batches.append(BatchTask(files=list(current)))
                current = []
                cur_bytes = 0

            current.append(t)
            cur_bytes += t.size_bytes

        if current:
            batches.append(BatchTask(files=list(current)))

        # Summary
        for b in batches:
            langs = {f.language for f in b.files}
            print(f"  Batch {b.batch_id}: {len(b.files)} files, "
                  f"{b.size_mb:.2f}MB, langs={langs}")

        return batches

    def batch_files(self, file_tasks: List[FileTask],
                    batch_size: int = 10) -> List[List[FileTask]]:
        """[COMPAT] Old API: return list-of-lists instead of BatchTask."""
        return [file_tasks[i:i+batch_size] for i in range(0, len(file_tasks), batch_size)]

    # ====================  Internal: Heuristics  ====================

    def _matches_any(self, path: str, patterns: List[str]) -> bool:
        """Check if path matches any fnmatch pattern."""
        fname = Path(path).name.lower()
        for pat in patterns:
            if fnmatch(fname, pat.lower()) or fnmatch(path, pat.lower()):
                return True
        return False

    def _is_config_file(self, path: str) -> bool:
        p = Path(path)
        ext = p.suffix.lower()
        name = p.name.lower()
        config_exts = {'.yaml', '.yml', '.json', '.toml', '.ini', '.cfg',
                       '.conf', '.env', '.properties'}
        if ext in config_exts:
            return True
        if name in ('dockerfile', 'makefile', '.gitignore', '.gitattributes'):
            return True
        if 'config' in name or 'settings' in name:
            return True
        return False

    def _is_test_file(self, path: str) -> bool:
        """Detect test files using common patterns."""
        pl = path.lower()
        nl = Path(path).name.lower()
        for ind in TEST_INDICATORS:
            if ind in pl or ind in nl:
                return True
        return False

    def _estimate_risk(self, path: str, language: str) -> str:
        """Heuristic risk estimation based on file name/path."""
        pl = path.lower()
        critical = ['eval', 'exec', 'subprocess', 'os.system', 'shell',
                    'command', 'deserialize', 'pickle']
        high = ['sql', 'query', 'input', 'request', 'redirect', 'cookie',
                'session', 'upload']
        for kw in critical:
            if kw in pl:
                return "critical"
        for kw in high:
            if kw in pl:
                return "high"
        return "low"

    # ====================  Internal: Output Helpers  ====================

    def _batch_to_dict(self, batch: BatchTask) -> Dict:
        return {
            "batch_id": batch.batch_id,
            "files": [asdict(f) for f in batch.files],
            "total_bytes": batch.total_size,
            "size_mb": round(batch.size_mb, 2),
        }

    def _priority_dist(self, tasks: List[FileTask]) -> Dict[int, int]:
        dist = Counter(t.priority for t in tasks)
        return dict(sorted(dist.items()))

    def _print_priority_dist(self, tasks: List[FileTask]):
        dist = self._priority_dist(tasks)
        print("[DEBUG] Priority distribution:")
        for p in sorted(dist):
            bar = "#" * min(dist[p], 40)
            print(f"  P{p:2d}: {dist[p]:4d} {bar}")


# =====================  Module Convenience  =====================


def quick_schedule(root_path: str, **kwargs) -> List[FileTask]:
    """One-shot scheduling for a project directory."""
    agent = SchedulerAgent(config=kwargs)
    result = agent.run({"root_path": root_path})
    if result.success and result.metadata.get("batches"):
        all_f = []
        for bd in result.metadata["batches"]:
            for fd in bd.get("files", []):
                all_f.append(FileTask(**fd))
        return all_f
    return []


# =====================  Self-test  =====================
if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("  SchedulerAgent Self-Test")
    print("=" * 60 + "\n")

    with tempfile.TemporaryDirectory() as td:
        # Create sample project structure
        files = [
            "app/config.py",
            "app/auth/login.py",
            "app/auth/oauth.py",
            "app/models/user.py",
            "app/models/db.py",
            "app/utils/helpers.py",
            "app/utils/crypto.py",
            ".env",
            "Dockerfile",
            "tests/test_auth.py",
            "tests/test_models.py",
        ]
        for f in files:
            fp = Path(td) / f
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text("# test file\n", encoding="utf-8")

        scheduler = SchedulerAgent(config={
            "debug": True,
            "ignore_tests": True,
            "batch_size": 5,
        })
        result = scheduler.run({"root_path": td})

        print(f"\nResult: success={result.success}")
        md = result.metadata
        print(f"  Files: {md.get('total_files')}")
        print(f"  Batches: {md.get('total_batches')}")
        print(f"  Priority: {md.get('priority_distribution')}")
        print(f"  Languages: {md.get('languages')}")

        for bd in md.get("batches", []):
            names = [Path(fd["file_path"]).name for fd in bd["files"]]
            print(f"  Batch {bd['batch_id']}: {names}")

    print("\n[OK] Self-test done\n")
