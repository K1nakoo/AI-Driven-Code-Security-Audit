# -*- coding: utf-8 -*-
"""Git操作封装 — 分支创建、提交、回滚"""
import subprocess
import os
import uuid
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass


@dataclass
class GitCommitResult:
    success: bool
    commit_hash: str = ""
    branch_name: str = ""
    error: str = ""
    message: str = ""


class GitOperator:
    """管理Git操作 - 修复用"""

    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path).resolve()
        self._git = "git"
        self._author_name = os.environ.get("GIT_AUTHOR_NAME", "AI Audit Bot")
        self._author_email = os.environ.get("GIT_AUTHOR_EMAIL", "ai-audit@example.com")

    def is_repo(self) -> bool:
        """检查是否在git仓库中"""
        try:
            result = self._run(["rev-parse", "--git-dir"])
            return result.returncode == 0
        except Exception:
            return False

    def is_clean(self) -> bool:
        """检查工作区是否干净"""
        result = self._run(["status", "--porcelain"])
        return result.stdout.strip() == ""

    def current_branch(self) -> str:
        result = self._run(["branch", "--show-current"])
        return result.stdout.strip()

    def create_branch(self, fix_id: str = None) -> str:
        """创建修复分支"""
        fix_id = fix_id or str(uuid.uuid4())[:8]
        branch_name = f"ai-fix/{fix_id}"

        # FIXME: 如果分支已存在怎么办? 暂时忽略
        result = self._run(["checkout", "-b", branch_name])
        if result.returncode != 0:
            print(f"[Git] 创建分支失败: {result.stderr}")

        return branch_name

    def stage_file(self, file_path: str):
        """git add 文件"""
        self._run(["add", str(file_path)])

    def stage_all(self):
        """git add 所有改动"""
        self._run(["add", "-A"])

    def commit(self, message: str, files: List[str] = None) -> GitCommitResult:
        """提交改动"""
        if files:
            for f in files:
                self.stage_file(f)

        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = self._author_name
        env["GIT_AUTHOR_EMAIL"] = self._author_email
        env["GIT_COMMITTER_NAME"] = self._author_name
        env["GIT_COMMITTER_EMAIL"] = self._author_email

        result = self._run(
            ["commit", "-m", message],
            env=env,
        )

        if result.returncode == 0:
            commit_hash = self._get_head_hash()
            return GitCommitResult(
                success=True,
                commit_hash=commit_hash,
                branch_name=self.current_branch(),
                message=message,
            )

        return GitCommitResult(
            success=False,
            error=result.stderr,
            message=message,
        )

    def revert_changes(self, files: List[str] = None):
        """回滚改动 (git checkout)"""
        if files:
            self._run(["checkout", "--"] + files)
        else:
            self._run(["checkout", "."])

        # 也清理untracked文件(可选, 危险, 先注释)
        # self._run(["clean", "-fd"])

    def discard_branch(self, base_branch: str = None):
        """放弃当前分支, 切回base"""
        if base_branch is None:
            base_branch = "main"
        # 先去检测main和master
        self._run(["checkout", base_branch])

    def get_diff(self) -> str:
        """获取当前diff"""
        result = self._run(["diff", "--cached"])
        return result.stdout

    def get_status(self) -> str:
        result = self._run(["status", "--short"])
        return result.stdout

    def create_pull_request(self, base_branch: str = "main") -> dict:
        """创建PR (需要GitHub CLI - gh)"""
        # TODO: 实际对接GitHub API
        branch = self.current_branch()
        try:
            result = subprocess.run(
                ["gh", "pr", "create", "--base", base_branch,
                 "--head", branch, "--title", f"AI Fix: {branch}",
                 "--body", "Auto-generated security fix by AI Audit Agent."],
                capture_output=True, text=True, timeout=30,
                cwd=str(self.repo_path),
            )
            return {"success": result.returncode == 0, "output": result.stdout, "branch": branch}
        except Exception as e:
            return {"success": False, "error": str(e), "branch": branch}

    def _get_head_hash(self) -> str:
        result = self._run(["rev-parse", "HEAD"])
        return result.stdout.strip()[:8]

    def _run(self, args: list, env: dict = None) -> subprocess.CompletedProcess:
        """执行git命令"""
        cmd = [self._git] + args
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(self.repo_path),
                env=env or os.environ,
            )
        except subprocess.TimeoutExpired:
            print(f"[Git] 超时: {' '.join(cmd)}")
            # 返回一个假的result
            result = subprocess.CompletedProcess(cmd, -1, stdout="", stderr="timeout")
            return result
        except Exception as e:
            print(f"[Git] 错误: {e}")
            result = subprocess.CompletedProcess(cmd, -1, stdout="", stderr=str(e))
            return result
