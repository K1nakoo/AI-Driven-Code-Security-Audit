# -*- coding: utf-8 -*-
"""JSON报告模板"""
import json
from datetime import datetime
from typing import Dict, Any, List


class JSONReportTemplate:
    """生成结构化的JSON安全审计报告"""

    @staticmethod
    def render(audit_result) -> Dict[str, Any]:
        """渲染为JSON数据结构"""
        findings = getattr(audit_result, "findings", [])
        fixes = getattr(audit_result, "fixes", [])
        sc_findings = getattr(audit_result, "supply_chain_findings", [])

        # 严重度分布
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report = {
            "metadata": {
                "report_type": "AI Code Security Audit",
                "version": "0.1.0",
                "timestamp": datetime.now().isoformat(),
                "target": getattr(audit_result, "target", ""),
                "duration_seconds": round(getattr(audit_result, "duration", 0), 2),
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "false_positives_estimated": len(
                    [f for f in findings if f.get("is_false_positive")]
                ),
                "supply_chain_risks": len(sc_findings),
                "fixes_generated": len(fixes),
            },
            "findings": [
                {
                    "rule_id": f.get("rule_id", ""),
                    "severity": f.get("severity", "info"),
                    "confidence": f.get("confidence", 0.5),
                    "file_path": f.get("file_path", ""),
                    "line": f.get("line", 1),
                    "message": f.get("message", ""),
                    "code_snippet": f.get("code_snippet", ""),
                    "tool": f.get("tool_name", f.get("source", "")),
                    "is_false_positive": f.get("is_false_positive", False),
                    "data_flow": f.get("data_flow", {}),
                    "exploit_scenario": f.get("exploit_scenario", ""),
                    "remediation": f.get("remediation", ""),
                    "analysis": f.get("deep_analysis", {}),
                }
                for f in findings
            ],
            "fixes_applied": [
                {
                    "diff": fix.get("diff", ""),
                    "method": fix.get("method", "none"),
                    "confidence": fix.get("confidence", 0.0),
                    "explanation": fix.get("explanation", ""),
                }
                for fix in fixes
            ],
            "supply_chain": [
                {
                    "package": sc.get("package", ""),
                    "version": sc.get("version", ""),
                    "severity": sc.get("severity", "info"),
                    "cve_id": sc.get("cve_id", ""),
                    "description": sc.get("description", ""),
                    "fix_version": sc.get("fix_version", ""),
                }
                for sc in sc_findings
            ],
            "pipeline_trace": getattr(audit_result, "pipeline_trace", []),
            "errors": getattr(audit_result, "errors", []),
        }

        return report

    @staticmethod
    def to_json_string(audit_result, pretty: bool = True) -> str:
        """序列化为JSON字符串"""
        data = JSONReportTemplate.render(audit_result)
        return json.dumps(data, ensure_ascii=False, indent=2 if pretty else None)
