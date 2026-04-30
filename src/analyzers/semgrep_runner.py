# -*- coding: utf-8 -*-
"""
Semgrep Runner模块 - 封装Semgrep CLI调用
确保semgrep可用, 提供便捷的扫描接口。

依赖: semgrep CLI (https://semgrep.dev/)
安装: pip install semgrep  或  brew install semgrep

TODO: 支持自定义规则目录路径
FIXME: Windows上subprocess timeout行为不稳定, 可能需要用threading兜底
"""
import subprocess
import shutil
import json
import os
import time
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

# ====================  Rule Presets  ====================

# 详细规则列表，语义化命名
DEFAULT_RULES = [
    "p/python",           # Python安全规则
    "p/javascript",       # JS/TS安全规则
    "p/security-audit",   # 安全审计专项
]

# OWASP Top 10 快速扫描
QUICK_RULES = [
    "p/owasp-top-ten",
]

# experimental: 激进规则集(含实验规则, 误报率高)
# EXPERIMENTAL_RULES = [
#     "p/r2c-security-audit",
#     "p/secrets",
#     "p/supply-chain",
# ]

# 名字到规则列表的映射
RULE_PRESETS = {
    "default": DEFAULT_RULES,
    "quick": QUICK_RULES,
    "python": ["p/python", "p/flask", "p/django"],
    "javascript": ["p/javascript", "p/typescript", "p/react"],
    "all": ["p/security-audit", "p/secrets", "p/supply-chain"],
    # TODO: 添加更多presets
    # "java": ["p/java", "p/spring"],
    # "go": ["p/golang"],
}


class SemgrepRunner:
    """
    封装semgrep CLI, 提供统一的扫描接口。

    Usage:
        runner = SemgrepRunner()
        if runner.is_available():
            sarif = runner.run("./src", rules_config="quick")
    """

    _SEMGREP_CMD = "semgrep"
    _DEFAULT_TIMEOUT = 300   # 默认超时5分钟

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", self._DEFAULT_TIMEOUT)
        self.verbose = self.config.get("verbose", False)

        self._semgrep_path: Optional[str] = None
        self._available: Optional[bool] = None
        self._version: str = "unknown"

        self._find_semgrep()
        if self._semgrep_path:
            self._version = self._get_version()
            print(f"[INFO] Semgrep found: {self._semgrep_path} (v{self._version})")
        else:
            print("[WARN] semgrep 未安装!")

    # ====================  Core Methods  ====================

    def is_available(self) -> bool:
        """检查semgrep是否安装且可用(缓存结果)"""
        if self._available is not None:
            return self._available

        if not self._semgrep_path or not Path(self._semgrep_path).exists():
            self._available = False
            return False

        try:
            r = subprocess.run(
                [self._semgrep_path, "--version"],
                capture_output=True, text=True, timeout=10
            )
            self._available = (r.returncode == 0)
        except Exception:
            self._available = False

        print(f"[DEBUG] semgrep available: {self._available}")
        return self._available

    def run(self, target_path: str, rules_config: str = "default",
            output_format: str = "sarif", extra_args: List[str] = None) -> Optional[str]:
        """
        运行semgrep扫描, 返回SARIF JSON字符串。

        Args:
            target_path: 目标文件或目录
            rules_config: "default"/"quick"/自定义规则路径
            output_format: 固定"sarif"
            extra_args: 额外CLI参数

        Returns:
            SARIF JSON字符串; 不可用时返回含错误信息的SARIF
        """
        print(f"[SemgrepRunner] ====== Scan Start ======")
        print(f"[SemgrepRunner] Target: {target_path}, Config: {rules_config}")

        target = Path(target_path)
        if not target.exists():
            msg = f"Target不存在: {target_path}"
            print(f"[ERROR] {msg}")
            return self._format_error(msg, "TARGET_NOT_FOUND")

        if not self.is_available():
            install_msg = self._get_install_instructions()
            print(f"[ERROR] semgrep not available\n{install_msg}")
            return self._format_error(install_msg, "SEMGREP_NOT_INSTALLED")

        # Resolve rules
        resolved = self._resolve_rules(rules_config)
        print(f"[DEBUG] Resolved rules: {resolved}")

        # Build command
        cmd = [self._semgrep_path, "scan"]
        for rule in resolved:
            cmd.extend(["--config", rule])
        cmd.extend(["--sarif", "--output", "-"])    # stdout
        cmd.append("--metrics=off")                 # 禁用遥测
        if self.verbose:
            cmd.append("--verbose")
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(str(target))

        print(f"[DEBUG] CMD: {' '.join(cmd)}")

        # Execute
        t0 = time.time()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout,
                encoding="utf-8", errors="replace",
                env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
            )
            elapsed = time.time() - t0

            print(f"[SemgrepRunner] Done in {elapsed:.1f}s, exit={result.returncode}")
            out_len = len(result.stdout) if result.stdout else 0
            err_len = len(result.stderr) if result.stderr else 0
            print(f"[SemgrepRunner] stdout={out_len}B, stderr={err_len}B")

            if result.returncode in (0, 1):
                # 0=无发现, 1=有发现 — 都是正常
                if result.returncode == 0:
                    print("[SemgrepRunner] Scan clean (0 findings)")
                else:
                    print(f"[SemgrepRunner] Findings detected (exit 1)")

                if result.stderr and self.verbose:
                    print(f"[SemgrepRunner] stderr: {result.stderr[:300]}")

                return result.stdout if result.stdout.strip() else self._empty_sarif()

            elif result.returncode == 2:
                print(f"[ERROR] Semgrep fatal error: {result.stderr[:500]}")
                return self._format_error(result.stderr[:300], "SEMGREP_FATAL")
            else:
                print(f"[WARN] Unknown exit code: {result.returncode}")
                return self._format_error(f"Exit code {result.returncode}", "UNKNOWN_EXIT")

        except subprocess.TimeoutExpired:
            print(f"[ERROR] Timed out after {self.timeout}s")
            return self._format_error(f"Timeout ({self.timeout}s)", "TIMEOUT")
        except FileNotFoundError:
            msg = "semgrep binary vanished mid-run"
            print(f"[ERROR] {msg}")
            self._available = False
            return self._format_error(msg, "SEMGREP_GONE")
        except Exception as e:
            print(f"[ERROR] Unexpected: {type(e).__name__}: {e}")
            logger.exception("semgrep run error")
            return self._format_error(str(e), "UNEXPECTED")

    # ====================  Convenience Methods  ====================

    def scan_file(self, file_path: str, rules_config: str = "quick") -> Optional[str]:
        """扫描单个文件(便捷封装)"""
        return self.run(file_path, rules_config)

    def scan_directory(self, dir_path: str, rules_config: str = "default") -> Optional[str]:
        """扫描整个目录"""
        return self.run(dir_path, rules_config)

    def get_version(self) -> Optional[str]:
        """返回已安装semgrep版本号(semgrep --version)"""
        if not self.is_available():
            return None
        return self._version

    # ====================  Internal Helpers  ====================

    def _find_semgrep(self):
        """在PATH / 环境变量 / 常见路径中定位semgrep"""
        env_path = os.environ.get("SEMGREP_PATH", "")
        if env_path and Path(env_path).exists():
            self._semgrep_path = env_path
            return

        found = shutil.which(self._SEMGREP_CMD)
        if found:
            self._semgrep_path = found
            return

        # 常见安装路径(Windows + Linux)
        for p in [
            r"C:\codeql\codeql\..\..\semgrep\semgrep.exe",
            r"C:\Program Files\Semgrep\semgrep.exe",
            "/usr/local/bin/semgrep",
            "/opt/semgrep/semgrep",
        ]:
            if Path(p).exists():
                self._semgrep_path = p
                return

        self._semgrep_path = None
        print("[DEBUG] semgrep not found in PATH")

    def _get_version(self) -> str:
        try:
            r = subprocess.run([self._semgrep_path, "--version"],
                               capture_output=True, text=True, timeout=10)
            return r.stdout.strip()
        except Exception as e:
            print(f"[WARN] _get_version failed: {e}")
            return "unknown"

    def _resolve_rules(self, rules_config: str) -> List[str]:
        """从preset名 → 实际规则列表"""
        if not rules_config:
            return self.PRESETS["default"]
        if rules_config in self.PRESETS:     # ← inconsistent: 用了self.PRESETS而非全局RULE_PRESETS
            return RULE_PRESETS[rules_config]
        if "," in rules_config:
            return [r.strip() for r in rules_config.split(",")]
        return [rules_config]

    def _empty_sarif(self, message: str = "No findings") -> str:
        """生成空SARIF"""
        return json.dumps({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Semgrep", "version": self._version}},
                "results": [],
                "invocations": [{
                    "executionSuccessful": True,
                    "toolExecutionNotifications": [
                        {"message": {"text": message}}
                    ],
                }],
            }],
        }, indent=2)

    def _format_error(self, message: str, error_code: str) -> str:
        """把错误包装成伪SARIF, 方便下游统一解析"""
        return json.dumps({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "Semgrep", "version": self._version}},
                "results": [{
                    "ruleId": f"internal.semgrep.{error_code.lower()}",
                    "level": "error",
                    "message": {"text": message},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "N/A"},
                            "region": {"startLine": 0, "startColumn": 0},
                        }
                    }],
                }],
            }],
        }, indent=2)

    def _get_install_instructions(self) -> str:
        """返回semgrep安装指南(中英混合)"""
        return "\n".join([
            "Semgrep未安装。请参考以下方式安装:",
            "",
            "  # pip (推荐):",
            "  pip install semgrep",
            "",
            "  # Homebrew (macOS/Linux):",
            "  brew install semgrep",
            "",
            "  # Docker:",
            "  docker run -v \"$(pwd):/src\" returntocorp/semgrep semgrep --config=auto",
            "",
            "  # 官网: https://semgrep.dev/docs/getting-started/",
            "",
            "安装后确保 'semgrep' 在PATH中可见。",
        ])

    # FIXME: 重试逻辑未经充分测试, 临时性问题处理可能不完善
    def run_with_retry(self, target_path: str, rules_config: str = "default",
                       max_retries: int = 2) -> Optional[str]:
        """带重试的扫描: 处理临时性网络/超时"""
        last_err = None
        for attempt in range(max_retries + 1):
            try:
                result = self.run(target_path, rules_config)
                if result:
                    # 检查是不是伪SARIF错误
                    try:
                        parsed = json.loads(result)
                        rr = parsed.get("runs", [{}])[0].get("results", [])
                        if rr and rr[0].get("ruleId", "").startswith("internal.semgrep."):
                            err_text = rr[0].get("message", {}).get("text", "")
                            print(f"[WARN] Attempt {attempt+1}: internal error, retrying...")
                            last_err = err_text
                            time.sleep(2)
                            continue
                    except json.JSONDecodeError:
                        pass
                return result
            except Exception as e:
                print(f"[WARN] Attempt {attempt+1} failed: {e}")
                last_err = str(e)
                time.sleep(2)

        return self._format_error(
            f"All {max_retries+1} attempts failed. Last: {last_err}",
            "RETRY_EXHAUSTED"
        )

    # Backwards compat: expose PRESETS as class attr (old code used SemgrepRunner.PRESETS)
    PRESETS = RULE_PRESETS


# ==============  Module-level helpers  ==============


def quick_scan(target: str) -> Optional[str]:
    """一键快速扫描(OWASP Top 10)"""
    return SemgrepRunner().run(target, "quick")


# ==============  Self-test  ==============
if __name__ == "__main__":
    print("=== SemgrepRunner Self-Test ===\n")
    runner = SemgrepRunner()

    if runner.is_available():
        print(f"Version: {runner.get_version()}")
        print("Semgrep is ready. Use runner.run('./target/', 'quick') to scan.")
    else:
        print("Semgrep not installed.")
        print(runner._get_install_instructions())

    # Test empty SARIF
    print("\n--- Empty SARIF ---")
    print(runner._empty_sarif("test")[:200])
