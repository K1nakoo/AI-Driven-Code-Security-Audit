# -*- coding: utf-8 -*-
"""
CodeQL Runner模块 - 封装 CodeQL CLI 调用

CodeQL是语义级代码分析引擎, 需要两步:
  1. database create (创建代码数据库)
  2. database analyze (运行查询)

文档: https://codeql.github.com/docs/codeql-cli/

FIXME: 数据库创建非常慢(特别是C/C++/Java), 需要增量创建策略
TODO: 支持自定义.ql查询文件
"""
import subprocess
import shutil
import json
import os
import tempfile
import time
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

# ====================  Query Suite Presets  ====================

# 标准查询套件(按语言)
LANGUAGE_QUERY_SUITES = {
    "python":     "codeql/python-queries",
    "javascript": "codeql/javascript-queries",
    "typescript": "codeql/javascript-queries",       # TS复用JS queries
    "java":       "codeql/java-queries",
    "go":         "codeql/go-queries",
    "cpp":        "codeql/cpp-queries",
    "csharp":     "codeql/csharp-queries",
    "ruby":       "codeql/ruby-queries",
    # experimental: 以下语言不稳定
    # "rust":  "codeql/rust-queries",
    # "swift": "codeql/swift-queries",
}

# 安全扩展套件(更激进, 适合审计)
QUICK_QUERY_SUITES = {
    "python":     "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
}


class CodeQLRunner:
    """封装CodeQL CLI, 提供 database create + analyze 流程"""

    _CODEQL_CMD = "codeql"
    _DB_TIMEOUT = 600    # 创建数据库超时 10 min
    _ANALYZE_TIMEOUT = 300  # 分析超时 5 min

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", self._DB_TIMEOUT)
        self._codeql_path: Optional[str] = None
        self._available: Optional[bool] = None
        self._db_cache: Dict[str, str] = {}   # target_path → db_path缓存

        self._init_path()
        if self._codeql_path:
            print(f"[INFO] CodeQL found: {self._codeql_path}")
        else:
            print("[WARN] CodeQL CLI not found")

    # ====================  Public API  ====================

    def is_available(self) -> bool:
        """检查CodeQL CLI是否可用(缓存结果)"""
        if self._available is not None:
            return self._available

        if not self._codeql_path:
            self._available = False
            return False

        try:
            r = subprocess.run([self._codeql_path, "version"],
                               capture_output=True, text=True, timeout=15)
            self._available = (r.returncode == 0)
            if self._available:
                print(f"[CodeQL] version: {r.stdout.strip().split(chr(10))[0]}")
        except Exception:
            self._available = False

        return self._available

    def create_database(self, target_path: str, language: str,
                        db_name: str = None) -> Optional[str]:
        """
        为源代码创建CodeQL数据库。

        Args:
            target_path: 源代码目录路径
            language: 编程语言(python/javascript/java/go/cpp)
            db_name: 数据库名, 默认自动生成

        Returns:
            数据库目录路径, 失败返回None
        """
        print(f"[CodeQL] ====== DB Create: {target_path} [{language}] ======")

        if not self.is_available():
            print("[ERROR] CodeQL not available")
            return None

        target = Path(target_path)
        if not target.exists():
            print(f"[ERROR] Target not found: {target_path}")
            return None

        # 确定数据库存储位置
        if not db_name:
            safe = target.name.replace(" ", "_").replace("-", "_")
            db_name = f"codeql_db_{safe}_{language}"

        db_dir = Path(target_path) / ".codeql" / db_name
        try:
            db_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            db_dir = Path(tempfile.gettempdir()) / "codeql_dbs" / db_name
            db_dir.mkdir(parents=True, exist_ok=True)

        print(f"[CodeQL] DB dir: {db_dir}")

        try:
            r = self._run_cmd([
                "database", "create", str(db_dir),
                "--language", language,
                "--source-root", str(target),
            ], timeout=self._DB_TIMEOUT)

            if r.returncode != 0:
                print(f"[ERROR] DB create failed (exit={r.returncode})")
                print(f"[ERROR] {r.stderr[:500]}")
                # 编译型语言提示
                if language in ("cpp", "csharp", "java") and "build" in r.stderr.lower():
                    print("[HINT] 编译型语言可能需要 --command 指定build")
                return None

            dbp = str(db_dir.absolute())
            print(f"[CodeQL] DB created: {dbp}")

            # Cache
            self._db_cache[target_path] = dbp
            return dbp

        except subprocess.TimeoutExpired:
            print(f"[ERROR] DB create timed out ({self._DB_TIMEOUT}s)")
            return None
        except Exception as e:
            print(f"[ERROR] DB create error: {type(e).__name__}: {e}")
            logger.exception("codeql create_database")
            return None

    def analyze(self, database_path: str, query_suite: str = None,
                language: str = None) -> Optional[str]:
        """
        对已创建的数据库执行分析查询。

        Args:
            database_path: 数据库目录
            query_suite: 查询套件名(不指定则根据language选择)
            language: 自动选择query_suite

        Returns:
            SARIF JSON字符串, 失败返回 None
        """
        print(f"[CodeQL] ====== Analyze: {database_path} ======")

        if not self.is_available():
            return self._error_sarif("CodeQL not available", "NOT_AVAILABLE")

        if not Path(database_path).exists():
            return self._error_sarif(f"DB not found: {database_path}", "DB_MISSING")

        # Resolve query suite
        if not query_suite and language:
            query_suite = QUICK_QUERY_SUITES.get(language,
                          LANGUAGE_QUERY_SUITES.get(language))
        if not query_suite:
            query_suite = "codeql/python-queries"
            print(f"[WARN] No query suite, default: {query_suite}")

        print(f"[CodeQL] Query suite: {query_suite}")

        # Output to temp file
        sarif_tmp = None
        try:
            fd, sarif_tmp = tempfile.mkstemp(suffix=".sarif")
            os.close(fd)

            r = self._run_cmd([
                "database", "analyze", str(database_path),
                query_suite,
                "--format=sarif-latest",
                f"--output={sarif_tmp}",
                # 减少输出大小(对于大型项目很重要)
                "--no-sarif-add-file-contents",
                "--no-sarif-add-snippets",
            ], timeout=self._ANALYZE_TIMEOUT)

            if r.returncode != 0:
                print(f"[ERROR] Analyze failed (exit={r.returncode})")
                print(f"[ERROR] {r.stderr[:500]}")
                return self._error_sarif(r.stderr[:300], "ANALYZE_FAILED")

            content = Path(sarif_tmp).read_text(encoding="utf-8")
            print(f"[CodeQL] SARIF generated: {len(content)} bytes")

            # 验证JSON有效性
            try:
                json.loads(content)
            except json.JSONDecodeError:
                print("[WARN] Corrupt SARIF, wrapping")
                content = self._error_sarif("Invalid SARIF output", "CORRUPT_SARIF")

            return content

        except subprocess.TimeoutExpired:
            return self._error_sarif(f"Timeout ({self._ANALYZE_TIMEOUT}s)", "TIMEOUT")
        except Exception as e:
            logger.exception("codeql analyze")
            return self._error_sarif(str(e), "UNEXPECTED")
        finally:
            if sarif_tmp and Path(sarif_tmp).exists():
                try:
                    Path(sarif_tmp).unlink()
                except Exception:
                    pass

    def create_and_analyze(self, target_path: str, language: str,
                          query_suite: str = None) -> Optional[str]:
        """
        一站式: 创建数据库 + 执行分析。

        Returns:
            SARIF JSON字符串
        """
        print(f"[CodeQL] ===== Full Pipeline: {target_path} [{language}] =====")
        t0 = time.time()

        db_path = self.create_database(target_path, language)
        if not db_path:
            return self._error_sarif("DB creation failed", "DB_CREATE_FAILED")

        sarif = self.analyze(db_path, query_suite, language)

        print(f"[CodeQL] Pipeline done in {time.time()-t0:.1f}s")
        return sarif

    def get_supported_languages(self) -> List[str]:
        """返回支持的语言列表"""
        return list(LANGUAGE_QUERY_SUITES.keys())

    def get_version(self) -> Optional[str]:
        """codeql --version"""
        if not self.is_available():
            return None
        try:
            r = subprocess.run([self._codeql_path, "--version"],
                               capture_output=True, text=True, timeout=10)
            return r.stdout.strip().split("\n")[0]
        except Exception:
            return None

    def cleanup_database(self, target_path: str) -> bool:
        """清理缓存的数据库"""
        if target_path in self._db_cache:
            dbp = self._db_cache.pop(target_path)
            try:
                shutil.rmtree(dbp)
                print(f"[CodeQL] Cleaned: {dbp}")
                return True
            except Exception as e:
                print(f"[WARN] Cleanup failed: {e}")
                return False
        return True

    # ====================  Backwards compat aliases  ====================

    def run_full_pipeline(self, target_path: str, language: str) -> Optional[str]:
        """Old alias for create_and_analyze"""
        return self.create_and_analyze(target_path, language)

    def scan_file_simple(self, file_path: str, language: str = "python") -> Optional[str]:
        """单文件扫描(实际扫描文件所在目录)"""
        return self.create_and_analyze(os.path.dirname(file_path), language)

    # ====================  Internals  ====================

    def _init_path(self):
        """查找codeql可执行文件"""
        env = os.environ.get("CODEQL_HOME", "")
        if env:
            c = Path(env) / self._CODEQL_CMD
            if c.exists():
                self._codeql_path = str(c)
                return

        found = shutil.which(self._CODEQL_CMD)
        if found:
            self._codeql_path = found
            return

        # 常见安装位置fallback
        for p in [
            r"C:\codeql\codeql\codeql.exe",
            r"C:\Program Files\CodeQL\codeql.exe",
            "/usr/local/bin/codeql",
            "/opt/codeql/codeql",
        ]:
            if Path(p).exists():
                self._codeql_path = p
                return

        self._codeql_path = None

    def _run_cmd(self, args: List[str], timeout: int = None,
                 cwd: str = None) -> subprocess.CompletedProcess:
        """统一执行codeql命令"""
        cmd = [self._codeql_path] + args
        print(f"[DEBUG] $ {' '.join(cmd)}")
        timeout = timeout or self.timeout
        return subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=cwd,
        )

    def _error_sarif(self, message: str, code: str) -> str:
        """生成错误伪SARIF"""
        return json.dumps({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": f"internal.codeql.{code.lower()}",
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


# ==============  Module-level convenience  ==============

def check_codeql_installed() -> bool:
    """快速检测CodeQL是否安装"""
    return CodeQLRunner().is_available()


# ==============  Self-test  ==============
if __name__ == "__main__":
    print("=== CodeQLRunner Self-Test ===\n")
    runner = CodeQLRunner()
    if runner.is_available():
        print(f"  Version: {runner.get_version()}")
        print(f"  Supported languages: {runner.get_supported_languages()}")
    else:
        print("  CodeQL not installed.")
        print("  Download: https://github.com/github/codeql-cli-binaries/releases")
    print("\n[OK] Self-test done\n")
