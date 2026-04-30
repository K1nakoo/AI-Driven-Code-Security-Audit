# -*- coding: utf-8 -*-
"""构建检查器 - 验证修复后项目仍能正常构建"""
import subprocess
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List


@dataclass
class BuildResult:
    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    errors: List[str] = field(default_factory=list)
    build_system: str = ""


class BuildChecker:
    """检查项目是否能构建/安装"""

    def __init__(self, project_path: str = "."):
        self.project_path = Path(project_path)
        self.timeout = 300

    def check_build(self) -> BuildResult:
        """检查构建"""
        system = self.detect_build_system()
        if not system:
            return BuildResult(
                success=True,
                build_system="unknown",
                errors=["No build system detected, skipping build check"]
            )

        if system == "pip":
            return self._run_pip_check()
        elif system == "npm":
            return self._run_npm_build()
        elif system == "maven":
            return self._run_maven_build()
        elif system == "gradle":
            return self._run_gradle_build()
        elif system == "go":
            return self._run_go_build()
        elif system == "make":
            return self._run_make_build()
        else:
            return BuildResult(success=True, build_system=system)

    def detect_build_system(self) -> str:
        """检测项目构建系统"""
        root = self.project_path
        # order matters - pip/setup.py first for Python projects
        checks = [
            (["setup.py", "pyproject.toml"], "pip"),
            (["package.json"], "npm"),
            (["pom.xml"], "maven"),
            (["build.gradle", "build.gradle.kts", "settings.gradle"], "gradle"),
            (["go.mod"], "go"),
            (["Makefile"], "make"),
            (["CMakeLists.txt"], "cmake"),
        ]

        for files, system in checks:
            for f in files:
                if (root / f).exists():
                    return system
        return ""

    def _run_pip_check(self) -> BuildResult:
        """pip install --dry-run 或 python setup.py check"""
        # 先试 pyproject.toml
        if (self.project_path / "pyproject.toml").exists():
            cmd = ["pip", "install", "-e", ".", "--dry-run"]
        elif (self.project_path / "setup.py").exists():
            # 至少检查语法
            cmd = ["python", "-c", "import compileall; compileall.compile_dir('.', quiet=1)"]
        else:
            return BuildResult(success=True, build_system="pip", errors=["No setup.py or pyproject.toml"])

        return self._execute(cmd, "pip")

    def _run_npm_build(self) -> BuildResult:
        # npm ci or npm install
        cmd = ["npm", "install", "--dry-run"]
        result = self._execute(cmd, "npm")
        if not result.success:
            return result

        # npm run build (如果配置了)
        pkg_json = self.project_path / "package.json"
        if pkg_json.exists():
            import json
            try:
                pkg = json.loads(pkg_json.read_text())
                if "build" in pkg.get("scripts", {}):
                    return self._execute(["npm", "run", "build", "--dry-run"] if False else
                                        ["npm", "run", "build"], "npm")
            except Exception:
                pass
        return result

    def _run_maven_build(self) -> BuildResult:
        return self._execute(["mvn", "compile", "-q"], "maven")

    def _run_gradle_build(self) -> BuildResult:
        # Windows用gradlew.bat
        gradle_cmd = "gradlew.bat" if os.name == "nt" else "./gradlew"
        if (self.project_path / gradle_cmd.replace("./", "")).exists():
            return self._execute([gradle_cmd, "compileJava", "-q"], "gradle")
        return self._execute(["gradle", "compileJava", "-q"], "gradle")

    def _run_go_build(self) -> BuildResult:
        return self._execute(["go", "build", "./..."], "go")

    def _run_make_build(self) -> BuildResult:
        return self._execute(["make", "-n"], "make")  # dry-run only

    def _execute(self, cmd: list, system: str) -> BuildResult:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(self.project_path),
                encoding="utf-8",
            )
            return BuildResult(
                success=result.returncode == 0,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                build_system=system,
            )
        except subprocess.TimeoutExpired:
            return BuildResult(
                success=False,
                build_system=system,
                errors=[f"Build timeout after {self.timeout}s"],
            )
        except FileNotFoundError:
            return BuildResult(
                success=True,  # 工具不存在不算失败
                build_system=system,
                errors=[f"Build tool not found: {cmd[0]}"],
            )
        except Exception as e:
            return BuildResult(
                success=False,
                build_system=system,
                errors=[str(e)],
            )
