# -*- coding: utf-8 -*-
"""
SARIF Parser模块 - 解析SARIF v2.1.0格式的安全扫描结果
支持Semgrep和CodeQL输出的SARIF格式，标准化为内部finding格式。

TODO: 未来支持SARIF v2.2.0
FIXME: 嵌套graphs的支持不完整(第~420行的逻辑需要重写)
"""
import json
import hashlib
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


# SARIF severity → 内部severity映射
# error通常对应严重问题，warning则是中危
SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

# FIXME: 映射不够精确，后续需根据rule内容微调
# 某些工具的warning实际应该映射为high(比如CodeQL security queries)
# 考虑从rule的properties.security-severity字段读取更精确的值

# experimental: 更细粒度的2级映射
# SEVERITY_MAP_V2 = {
#     "error":  {"default": "high",     "security": "critical"},
#     "warning":{"default": "medium",   "security": "high"},
#     "note":   {"default": "low"},
#     "none":   {"default": "info"},
# }
# def _map_severity_v2(level, kind="default"):
#     return SEVERITY_MAP_V2.get(level, {}).get(kind, "info")


class SARIFParser:
    """
    解析SARIF v2.1.0 JSON输出, 标准化为内部finding格式

    核心职责:
      - parse_file(path)      -> 从文件解析SARIF
      - parse_string(json_str) -> 从JSON字符串解析
      - deduplicate(findings)  -> 基于(rule_id, file_path, line)去重
      - get_statistics(findings) -> 生成统计信息

    内部finding dict格式:
      {
        rule_id, message, severity, file_path, line, column,
        end_line, end_column, code_snippet, tool_name,
        raw_level, kind, is_suppressed, fingerprint, related_locations
      }

    Usage:
        parser = SARIFParser()
        findings = parser.parse_file("./scan_results.sarif")
        unique = parser.deduplicate(findings)
    """

    def __init__(self, strict_mode: bool = False):
        """
        Initialize the SARIF parser.

        Args:
            strict_mode: True时缺失字段raise异常; False用默认值填充
        """
        self.strict_mode = strict_mode
        self._parsed_count = 0   # 累计解析数量(生命周期总计)
        self._error_count = 0    # 累计错误数
        self._cache: Dict[str, Dict[str, Any]] = {}  # 文件级缓存, key=file://abs_path

        print(f"[DEBUG] SARIFParser initialized, strict_mode={strict_mode}")
        logger.info(f"SARIFParser created (strict={strict_mode})")

    # ====================  Main API  ====================

    def parse_file(self, path: str) -> List[Dict[str, Any]]:
        """
        从文件路径解析SARIF。

        内部使用缓存: 同一文件如果mtime没变就不会重复解析。

        Args:
            path: SARIF JSON文件路径

        Returns:
            List of normalized finding dicts

        Raises:
            FileNotFoundError: 文件不存在
        """
        print(f"[DEBUG] parse_file called with path={path}")
        file_path = Path(path)

        if not file_path.exists():
            msg = f"SARIF文件不存在: {path}"
            print(f"[ERROR] {msg}")
            raise FileNotFoundError(msg)

        # 缓存命中检查
        cache_key = f"file://{file_path.absolute()}"
        mtime = file_path.stat().st_mtime
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if cached.get("_mtime") == mtime:
                print(f"[DEBUG] Cache hit for {path}")
                return cached["findings"]

        # 读取文件
        try:
            raw_content = file_path.read_text(encoding='utf-8')
            print(f"[DEBUG] Read {len(raw_content)} bytes from {path}")
        except UnicodeDecodeError as e:
            print(f"[WARN] UTF-8 decode failed, fallback latin-1: {e}")
            raw_content = file_path.read_text(encoding='latin-1')

        # 空文件快速返回
        if not raw_content.strip():
            print(f"[INFO] Empty file: {path}")
            return []

        findings = self.parse_string(raw_content)

        # 更新缓存
        self._cache[cache_key] = {"_mtime": mtime, "findings": findings}
        return findings

    def parse_string(self, json_str: str) -> List[Dict[str, Any]]:
        """
        从JSON字符串解析SARIF结果。

        这是核心解析方法, parse_file也最终调用它。

        Args:
            json_str: SARIF v2.1.0格式的JSON字符串

        Returns:
            List of normalized finding dicts
        """
        findings: List[Dict[str, Any]] = []

        # 1. JSON解析
        try:
            sarif_data = json.loads(json_str)
        except json.JSONDecodeError as e:
            error_msg = f"JSON解析失败: {e}"
            logger.error(error_msg)
            print(f"[ERROR] {error_msg}")
            self._error_count += 1
            if self.strict_mode:
                raise
            return findings

        # 2. 版本验证
        version = sarif_data.get("version", "unknown")
        schema_uri = sarif_data.get("$schema", "")
        print(f"[DEBUG] SARIF version={version}, schema={schema_uri[:80]}...")

        if version != "2.1.0":
            print(f"[WARN] Expected v2.1.0, got {version}, 尝试兼容模式...")
        if schema_uri and "sarif-2.1.0" not in schema_uri and schema_uri != "":
            print(f"[WARN] Unrecognized schema: {schema_uri}")

        # 3. 遍历runs
        runs: List[Dict] = sarif_data.get("runs", [])
        if not runs:
            print("[INFO] 0 runs in SARIF, 返回空结果")
            return findings

        print(f"[DEBUG] Processing {len(runs)} run(s)")

        for run_idx, run in enumerate(runs):
            print(f"[DEBUG] --- Run {run_idx + 1}/{len(runs)} ---")
            tool_name = self._extract_tool_name(run)
            rules_index = self._build_rules_index(run)
            artifacts_index = self._build_artifacts_index(run)

            results = run.get("results", [])
            if not results:
                print(f"[DEBUG] Run {run_idx} has no results")
                continue

            for result_idx, result in enumerate(results):
                try:
                    finding = self._normalize_result(
                        result, run, tool_name, rules_index, artifacts_index
                    )
                    findings.append(finding)
                except Exception as e:
                    print(f"[WARN] result[{result_idx}] normalize failed: {e}")
                    self._error_count += 1
                    if self.strict_mode:
                        raise

        self._parsed_count += len(findings)
        print(f"[INFO] Parsed {len(findings)} findings (lifetime: {self._parsed_count})")
        return findings

    # ====================  Internal Parsing Helpers  ====================

    def _extract_tool_name(self, run: Dict) -> str:
        """从run对象提取工具名 + 版本号"""
        driver = run.get("tool", {}).get("driver", {})
        name = driver.get("fullName") or driver.get("name") or "unknown-tool"
        version = driver.get("semanticVersion") or driver.get("version", "")
        if version:
            name = f"{name}@{version}"
        print(f"[DEBUG] Tool detected: {name}")
        return name

    def _build_rules_index(self, run: Dict) -> Dict[str, Dict]:
        """构建 ruleId -> rule对象的索引(用于获取security-severity等)"""
        index: Dict[str, Dict] = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rid = rule.get("id", "")
            if rid:
                index[rid] = rule
        # 也扫描extensions中的rules
        for ext in driver.get("extensions", []):
            for rule in ext.get("rules", []):
                rid = rule.get("id", "")
                if rid:
                    index[rid] = rule
        return index

    def _build_artifacts_index(self, run: Dict) -> Dict[int, Dict]:
        """构建artifact索引(用于URI resolution)"""
        return {i: a for i, a in enumerate(run.get("artifacts", []))}

    def _normalize_result(
        self,
        result: Dict,
        run: Dict,
        tool_name: str,
        rules_index: Dict[str, Dict],
        artifacts_index: Dict[int, Dict],
    ) -> Dict[str, Any]:
        """
        将单个SARIF result标准化为内部格式。

        核心映射:
          SARIF ruleId           → internal rule_id
          SARIF message.text     → internal message
          SARIF level + kind     → internal severity
          SARIF locations[0]     → file_path / line / column / code_snippet
        """

        # ---- rule_id ----
        rule_id = result.get("ruleId", "")
        if not rule_id:
            # 可能通过ruleIndex引用
            rule_idx = result.get("ruleIndex")
            if isinstance(rule_idx, int):
                driver = run.get("tool", {}).get("driver", {})
                rules = driver.get("rules", [])
                if 0 <= rule_idx < len(rules):
                    rule_id = rules[rule_idx].get("id", f"rule-index-{rule_idx}")
        if not rule_id:
            rule_id = "unknown-rule"

        # ---- message ----
        message = self._extract_message(result)

        # ---- severity ----
        raw_level = result.get("level", "warning")
        kind = result.get("kind", "")
        severity = self._map_severity(raw_level, kind, rule_id, rules_index)

        # ---- location ----
        file_path, line, column, end_line, end_column, code_snippet = \
            self._extract_location(result, artifacts_index)

        # ---- suppressions ----
        is_suppressed = len(result.get("suppressions", [])) > 0
        if is_suppressed:
            print(f"[DEBUG] Suppressed finding: {rule_id}")

        # ---- fingerprints ----
        fingerprints = result.get("partialFingerprints", {})

        # ---- related locations ----
        related_locations = []
        for rl in result.get("relatedLocations", []):
            phys = rl.get("physicalLocation", {})
            art = phys.get("artifactLocation", {})
            reg = phys.get("region", {})
            related_locations.append({
                "file_path": self._normalize_uri(art.get("uri", "")),
                "line": reg.get("startLine", 0),
                "message": (rl.get("message", {}) or {}).get("text", ""),
            })

        # ---- Build finding dict ----
        finding = {
            "rule_id": rule_id,
            "message": message,
            "severity": severity,
            "file_path": file_path,
            "line": line,
            "column": column,
            "end_line": end_line if end_line is not None else line,  # fallback
            "end_column": end_column,           # might be None
            "code_snippet": code_snippet,
            "tool_name": tool_name,
            "raw_level": raw_level,
            "kind": kind,
            "is_suppressed": is_suppressed,
            "fingerprint": fingerprints.get("primary", ""),
            "related_locations": related_locations,
            "_raw": result if self.strict_mode else {},
        }

        # 太吵了, 先注释掉
        # print(f"[TRACE] {finding['rule_id']}@{finding['file_path']}:{finding['line']} [{finding['severity']}]")

        return finding

    def _extract_message(self, result: Dict) -> str:
        """提取人类可读消息。支持: str / {text} / {markdown} / {id+arguments}"""
        msg = result.get("message", {})

        if isinstance(msg, str):
            return msg

        if isinstance(msg, dict):
            text = msg.get("text", "")
            if text:
                return text
            md = msg.get("markdown", "")
            if md:
                return md.replace("`", "").replace("**", "").strip()
            # template message
            mid = msg.get("id", "")
            args = msg.get("arguments", [])
            if mid and args:
                return f"{mid}({', '.join(str(a) for a in args)})"
            return mid or "no message"

        print(f"[WARN] Unexpected message type: {type(msg)}")
        return str(msg)

    def _extract_location(
        self, result: Dict, artifacts_index: Dict[int, Dict]
    ) -> Tuple[str, int, int, Optional[int], Optional[int], str]:
        """提取位置: (file_path, line, column, end_line, end_column, code_snippet)"""
        file_path = ""
        line = 1
        column = 1
        end_line = None
        end_column = None
        code_snippet = ""

        locations = result.get("locations", [])
        if not locations:
            return file_path, line, column, end_line, end_column, code_snippet

        primary = locations[0]
        phys = primary.get("physicalLocation", {})

        # URI
        art = phys.get("artifactLocation", {})
        file_path = art.get("uri", "")
        art_idx = art.get("index")
        if not file_path and art_idx is not None:
            artifact = artifacts_index.get(art_idx, {})
            file_path = artifact.get("location", {}).get("uri", "")

        file_path = self._normalize_uri(file_path)

        # Region
        region = phys.get("region", {})
        line = region.get("startLine", 1)
        column = region.get("startColumn", 1)
        end_line = region.get("endLine")
        end_column = region.get("endColumn")

        # Code snippet
        code_snippet = (region.get("snippet", {}) or {}).get("text", "")
        if not code_snippet:
            code_snippet = (phys.get("contextRegion", {}) or {}).get("text", "")

        return file_path, line, column, end_line, end_column, code_snippet

    def _normalize_uri(self, uri: str) -> str:
        """标准化URI: file:///C:/... → C:/..., %20 → ' ', 等"""
        if not uri:
            return ""
        if uri.startswith("file://"):
            uri = uri[7:]
        # Windows fix: /C:/xxx → C:/xxx
        if (uri.startswith("/") and len(uri) > 3
                and uri[2] == ":" and uri[1].isalpha()):
            uri = uri[1:]
        uri = uri.replace("%20", " ").replace("%2F", "/")
        return uri

    def _map_severity(self, level: str, kind: str, rule_id: str,
                      rules_index: Dict[str, Dict]) -> str:
        """
        将SARIF level映射为内部severity(含安全性调整)。

        策略:
          1. 基本映射: error→high, warning→medium, note→low, none→info
          2. kind="fail" 且 level="error" → "critical"
          3. 如果rule有security-severity属性 → 用它覆盖 (CodeQL风格, 0.0-10.0)
        """
        normalized = level.lower().strip()
        severity = SEVERITY_MAP.get(normalized, "info")

        # kind="fail" 通常是确定漏洞 → 升级
        if kind == "fail" and normalized == "error":
            severity = "critical"

        # CodeQL的security-severity
        if rule_id and rule_id in rules_index:
            props = rules_index[rule_id].get("properties", {})
            ss = props.get("security-severity")
            if ss is not None:
                try:
                    ss = float(ss)
                    if ss >= 9.0:
                        severity = "critical"
                    elif ss >= 7.0:
                        severity = "high"
                    elif ss >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
                except (ValueError, TypeError):
                    pass  # 非数值, 忽略

        return severity

    # ====================  Post-processing  ====================

    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        基于(rule_id, file_path, line)去重, 保留首次出现的记录。

        注意事项:
          - 不同工具报告相同位置但不同rule_id → 保留
          - 同一行多列相同规则命中 → 只保留第一条 (可接受的精度损失)
        """
        if not findings:
            return []

        print(f"[INFO] Dedup: {len(findings)} findings → ", end="")

        seen: Set[Tuple] = set()
        deduped = []
        dup_count = 0

        for f in findings:
            key = (f.get("rule_id", ""), f.get("file_path", ""), f.get("line", 0))

            # experimental: 加入column提高精确度
            # key = (f.get("rule_id", ""), f.get("file_path", ""), f.get("line", 0), f.get("column", 0))

            if key not in seen:
                seen.add(key)
                deduped.append(f)
            else:
                dup_count += 1

        print(f"{len(deduped)} unique ({dup_count} dup removed)")
        return deduped

    def filter_by_severity(self, findings: List[Dict],
                           min_severity: str) -> List[Dict]:
        """按最低严重度过滤(返回>=min_severity的finding)"""
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order.get(min_severity, 0)
        result = [f for f in findings
                  if order.get(f.get("severity", "info"), 0) >= threshold]
        print(f"[FILTER] {len(findings)} → {len(result)} (threshold={min_severity})")
        return result

    def get_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """统计findings分布: by severity / by tool / by rule / by file"""
        stats: Dict[str, Any] = {
            "total": len(findings),
            "by_severity": {},
            "by_tool": {},
            "by_rule": {},
            "by_file": {},
            "suppressed": 0,
        }
        for f in findings:
            sev = f.get("severity", "unknown")
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

            tool = f.get("tool_name", "unknown")
            stats["by_tool"][tool] = stats["by_tool"].get(tool, 0) + 1

            rule = f.get("rule_id", "unknown")
            stats["by_rule"][rule] = stats["by_rule"].get(rule, 0) + 1

            fp = f.get("file_path", "unknown")
            stats["by_file"][fp] = stats["by_file"].get(fp, 0) + 1

            if f.get("is_suppressed"):
                stats["suppressed"] += 1

        return stats

    def clear_cache(self) -> None:
        self._cache.clear()
        print("[DEBUG] Cache cleared")


# ==============  Module-level conveniences  ==============


def parse_sarif_file(filepath: str) -> List[Dict[str, Any]]:
    """一键解析SARIF文件"""
    return SARIFParser().parse_file(filepath)


def find_sarif_files(directory: str) -> List[str]:
    """递归查找*.sarif 和 *.sarif.json 文件"""
    sarif_files = []
    root = Path(directory)
    if root.exists():
        for f in root.rglob("*.sarif"):
            sarif_files.append(str(f))
        for f in root.rglob("*.sarif.json"):
            sarif_files.append(str(f))
    return sarif_files


def merge_sarif_files(*paths: str) -> List[Dict[str, Any]]:
    """合并多个SARIF文件的findings并去重"""
    p = SARIFParser()
    all_f = []
    for fp in paths:
        all_f.extend(p.parse_file(fp))
    return p.deduplicate(all_f)


# ==============  Self-test  ==============
if __name__ == "__main__":
    print("=" * 60)
    print("  SARIF Parser - Self Test")
    print("=" * 60 + "\n")

    sample = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Semgrep",
                    "fullName": "Semgrep OSS",
                    "version": "1.67.0",
                    "rules": [{
                        "id": "python.lang.security.audit.eval",
                        "shortDescription": {"text": "eval() detected"},
                        "properties": {"security-severity": "8.5"},
                    }],
                }
            },
            "artifacts": [
                {"location": {"uri": "file:///home/user/project/main.py"}}
            ],
            "results": [
                {
                    "ruleId": "python.lang.security.audit.eval",
                    "ruleIndex": 0,
                    "level": "error",
                    "message": {"text": "eval() used on user input"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/main.py"},
                            "region": {
                                "startLine": 42, "startColumn": 5,
                                "endLine": 42, "endColumn": 20,
                                "snippet": {"text": "eval(user_input)"},
                            },
                        }
                    }],
                },
                {
                    "ruleId": "python.lang.security.audit.eval",
                    "ruleIndex": 0,
                    "level": "warning",
                    "message": {"text": "exec() detected"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/utils.py"},
                            "region": {
                                "startLine": 15, "startColumn": 1,
                                "snippet": {"text": "exec(code_str)"},
                            },
                        }
                    }],
                },
                {
                    "ruleId": "generic.secrets.detected",
                    "level": "note",
                    "message": {"text": "Hardcoded password"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/config.py"},
                            "region": {
                                "startLine": 3, "startColumn": 10,
                                "snippet": {"text": 'PASSWORD = "secret123"'},
                            },
                        }
                    }],
                },
            ],
        }]
    }

    parser = SARIFParser(strict_mode=False)
    findings = parser.parse_string(json.dumps(sample))

    print(f"Parsed {len(findings)} findings:\n")
    for i, f in enumerate(findings, 1):
        print(f"  [{i}] {f['rule_id']} [{f['severity']}]")
        print(f"      {f['file_path']}:{f['line']}:{f['column']}")
        print(f"      msg: {f['message'][:60]}")
        print(f"      code: {f.get('code_snippet', 'N/A')}")
        print()

    # Dup test
    dup = dict(findings[0])
    findings.append(dup)
    dedup = parser.deduplicate(findings)
    print(f"Dedup: {len(findings)} → {len(dedup)} (expect 3)")

    # stats
    stats = parser.get_statistics(dedup)
    print(f"\nStats: total={stats['total']}, by_severity={stats['by_severity']}")
    print("[OK] Self-test done\n")
