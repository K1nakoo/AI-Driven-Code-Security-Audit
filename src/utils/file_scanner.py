# -*- coding: utf-8 -*-
"""文件扫描器 - 目录遍历 + 语言分类"""
import os
from pathlib import Path
from typing import List, Optional

# 语言 → 扩展名映射
LANGUAGE_EXTENSIONS = {
    "python": [".py", ".pyw", ".pyx"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java", ".kt", ".groovy"],
    "go": [".go"],
    "php": [".php", ".phtml"],
    "ruby": [".rb"],
    "rust": [".rs"],
    "c": [".c", ".h"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".hxx"],
    "csharp": [".cs"],
}

# 默认排除目录
DEFAULT_EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", "vendor", "target", ".next",
    "out", ".idea", ".vscode", ".pytest_cache", ".mypy_cache",
    "bower_components", ".eggs", "*.egg-info",
}

DEFAULT_EXCLUDE_PATTERNS = [
    "*.min.js", "*.min.css", "*.bundle.js", "*.generated.*",
    "*.spec.js", "*.test.js", "*.spec.ts", "*.test.ts",
]

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB 跳过


class FileScanner:
    """扫描目录树，返回文件列表"""

    def __init__(self, exclude_dirs=None, exclude_patterns=None, max_size=MAX_FILE_SIZE):
        self.exclude_dirs = exclude_dirs or DEFAULT_EXCLUDE_DIRS
        self.exclude_patterns = exclude_patterns or DEFAULT_EXCLUDE_PATTERNS
        self.max_size = max_size

    def scan_directory(self, path: str) -> List[str]:
        """递归扫描目录，返回全部代码文件路径"""
        path = Path(path)
        files = []

        if path.is_file():
            if self._should_scan(path):
                return [str(path)]
            return []

        for root, dirs, filenames in os.walk(str(path)):
            # 过滤排除目录
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs and not d.startswith(".")]

            for fname in filenames:
                fpath = Path(root) / fname
                if self._should_scan(fpath):
                    files.append(str(fpath))

        # print(f"[FileScanner] 扫描完成: {len(files)}个文件")  # debug
        return sorted(files)

    def _should_scan(self, filepath: Path) -> bool:
        """判断文件是否应该被扫描"""
        # 跳过过大文件
        try:
            if filepath.stat().st_size > self.max_size:
                # print(f"[FileScanner] 跳过过大文件: {filepath.name}")
                return False
        except OSError:
            return False

        # 检查排除模式
        from fnmatch import fnmatch
        for pattern in self.exclude_patterns:
            if fnmatch(filepath.name, pattern):
                return False

        # 检查扩展名
        ext = filepath.suffix.lower()
        for exts in LANGUAGE_EXTENSIONS.values():
            if ext in exts:
                return True

        return False

    def classify_file(self, filepath: str) -> Optional[str]:
        """返回文件语言类型"""
        ext = Path(filepath).suffix.lower()
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            if ext in exts:
                return lang
        # TODO: 支持通过shebang检测脚本语言
        return None

    def get_files_by_language(self, path: str, language: str) -> List[str]:
        """只扫描特定语言的文件"""
        all_files = self.scan_directory(path)
        return [f for f in all_files if self.classify_file(f) == language]

    def batch_by_size(self, files: List[str], batch_size: int = 20) -> List[List[str]]:
        """将文件列表分批"""
        return [files[i:i + batch_size] for i in range(0, len(files), batch_size)]


# 模块级便捷实例
# default_scanner = FileScanner()  # 可能需要不同配置, 先注释掉
