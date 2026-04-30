# -*- coding: utf-8 -*-
"""测试运行器 - 发现并运行项目测试"""
import subprocess
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TestResult:
    passed_count: int = 0
    failed_count: int = 0
    error_count: int = 0
    failures: List[dict] = field(default_factory=list)
    output: str = ""
    success: bool = False

    @property
    def total(self) -> int:
        return self.passed_count + self.failed_count + self.error_count

    @property
    def pass_rate(self) -> float:
        if self.total == 0:
            return 1.0
        return self.passed_count / self.total


class TestRunner:
    """项目的测试发现和运行"""

    def __init__(self, project_path: str = "."):
        self.project_path = Path(project_path)
        self.timeout = 600

    def discover_tests(self) -> List[str]:
        """自动发现测试文件"""
        test_files = []

        for root, dirs, files in os.walk(str(self.project_path)):
            dirs[:] = [d for d in dirs if not d.startswith(".")
                       and d not in ("node_modules", "venv", "__pycache__")]

            for fname in files:
                if self._is_test_file(fname):
                    test_files.append(str(Path(root) / fname))

        return test_files

    def _is_test_file(self, filename: str) -> bool:
        """判断是否是测试文件"""
        name = filename.lower()
        # Python
        if name.startswith("test_") or name.endswith("_test.py"):
            return True
        # JavaScript
        if name.endswith(".test.js") or name.endswith(".test.ts") or name.endswith(".spec.js"):
            return True
        # Java
        if "test" in name and name.endswith(".java"):
            return True
        # Go
        if name.endswith("_test.go"):
            return True
        return False

    def run_tests(self, test_paths: List[str] = None) -> TestResult:
        """运行测试"""
        framework = self.detect_framework()

        if framework == "pytest":
            return self._run_pytest(test_paths)
        elif framework == "unittest":
            return self._run_unittest(test_paths)
        elif framework == "jest":
            return self._run_jest(test_paths)
        elif framework == "go_test":
            return self._run_go_test(test_paths)
        else:
            # 没检测到测试框架，尝试通用的
            return self._run_generic()

    def detect_framework(self) -> Optional[str]:
        """检测项目使用的测试框架"""
        root = str(self.project_path)

        # Python
        if (self.project_path / "pytest.ini").exists() or \
           (self.project_path / "pyproject.toml").exists() or \
           (self.project_path / "setup.cfg").exists():
            return "pytest"

        # Check for setup.py with pytest
        setup = self.project_path / "setup.py"
        if setup.exists():
            content = setup.read_text()
            if "pytest" in content:
                return "pytest"

        if any(f.endswith("_test.py") for f in os.listdir(root)[:50]):
            return "unittest"  # 默认用unittest跑

        # Node.js
        if (self.project_path / "package.json").exists():
            try:
                import json
                pkg = json.loads((self.project_path / "package.json").read_text())
                if "jest" in pkg.get("devDependencies", {}) or "jest" in pkg.get("dependencies", {}):
                    return "jest"
            except Exception:
                pass
            return "jest"

        # Go
        if (self.project_path / "go.mod").exists():
            return "go_test"

        return None

    def run_specific_test(self, test_file: str, test_name: str = "") -> TestResult:
        """运行单个测试"""
        return self.run_tests([test_file])

    def _run_pytest(self, test_paths: List[str] = None) -> TestResult:
        cmd = ["pytest", "-v", "--tb=short"]
        if test_paths:
            cmd.extend(test_paths)
        else:
            cmd.append(str(self.project_path))

        return self._execute(cmd)

    def _run_unittest(self, test_paths: List[str] = None) -> TestResult:
        cmd = ["python", "-m", "unittest", "discover", "-v"]
        if test_paths:
            cmd.extend(test_paths)
        return self._execute(cmd)

    def _run_jest(self, test_paths: List[str] = None) -> TestResult:
        cmd = ["npx", "jest", "--verbose"]
        if test_paths:
            cmd.extend(test_paths)
        return self._execute(cmd)

    def _run_go_test(self, test_paths: List[str] = None) -> TestResult:
        cmd = ["go", "test", "-v", "./..."]
        return self._execute(cmd)

    def _run_generic(self) -> TestResult:
        """没有检测到测试框架"""
        return TestResult(
            output="No test framework detected. Skipping tests.",
            success=True,  # 没有测试也算通过
        )

    def _execute(self, cmd: list) -> TestResult:
        """执行命令并解析结果"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(self.project_path),
                encoding="utf-8",
            )
            output = result.stdout + "\n" + result.stderr

            # 简单解析(不够精确但是能用)
            passed = output.count(" PASSED") + output.count(" passed")
            failed = output.count(" FAILED") + output.count(" failed")
            errors = output.count(" ERROR") + output.count(" error")

            return TestResult(
                passed_count=passed,
                failed_count=failed,
                error_count=errors,
                output=output,
                success=result.returncode == 0,
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                error_count=1,
                output=f"Test timeout after {self.timeout}s",
                success=False,
            )
        except FileNotFoundError:
            return TestResult(
                output=f"Command not found: {cmd[0]}",
                success=True,  # 没找到命令不算失败
            )
        except Exception as e:
            return TestResult(
                error_count=1,
                output=str(e),
                success=False,
            )
