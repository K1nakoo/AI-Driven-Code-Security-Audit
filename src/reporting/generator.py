# -*- coding: utf-8 -*-
"""报告生成器 — JSON/HTML/Markdown"""
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from .templates.json_template import JSONReportTemplate
from .templates.html_template import HTMLReportTemplate


class ReportGenerator:
    """生成安全审计报告"""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, audit_result, format: str = "json") -> str:
        """生成报告内容"""
        if format == "json":
            return JSONReportTemplate.to_json_string(audit_result, pretty=True)
        elif format == "html":
            return HTMLReportTemplate.render(audit_result)
        elif format == "markdown":
            return self._generate_markdown(audit_result)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def save_report(self, audit_result, output_path: str = None,
                    format: str = "json") -> str:
        """保存报告到文件，返回文件路径"""
        content = self.generate(audit_result, format)
        ext_map = {"json": ".json", "html": ".html", "markdown": ".md"}

        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"audit_report_{ts}{ext_map.get(format, '.json')}"
            output_path = str(self.output_dir / fname)

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"[Report] 已保存: {output_path}")
        return output_path

    def generate_summary(self, audit_result) -> str:
        """生成CLI友好的文本摘要"""
        findings = getattr(audit_result, "findings", [])
        sc = getattr(audit_result, "supply_chain_findings", [])
        fixes = getattr(audit_result, "fixes", [])
        duration = getattr(audit_result, "duration", 0)

        sev = {}
        for f in findings:
            s = f.get("severity", "info")
            sev[s] = sev.get(s, 0) + 1

        fp_count = len([f for f in findings if f.get("is_false_positive")])

        lines = [
            "=" * 50,
            "  AUDIT SUMMARY",
            "=" * 50,
            f"  Duration    : {duration:.1f}s",
            f"  Findings    : {len(findings)}",
        ]
        for level in ("critical", "high", "medium", "low", "info"):
            if sev.get(level):
                lines.append(f"    {level:8s}: {sev[level]}")
        if fp_count:
            lines.append(f"  False Pos   : ~{fp_count}")
        lines.extend([
            f"  Supply Chain: {len(sc)} risks",
            f"  Fixes       : {len(fixes)} generated",
            "=" * 50,
        ])
        return "\n".join(lines)

    def compare_reports(self, before, after) -> dict:
        """对比修复前后的报告"""
        bf = getattr(before, "findings", [])
        af = getattr(after, "findings", [])
        return {
            "before": len(bf),
            "after": len(af),
            "fixed": max(0, len(bf) - len(af)),
            "new": max(0, len(af) - len(bf)),
        }

    def _generate_markdown(self, audit_result) -> str:
        """生成Markdown报告"""
        findings = getattr(audit_result, "findings", [])
        target = getattr(audit_result, "target", "")

        md = f"# AI Code Security Audit Report\n\n"
        md += f"**Target:** `{target}`\n\n"
        md += f"**Date:** {datetime.now().isoformat()}\n\n"
        md += f"## Findings ({len(findings)})\n\n"

        for f in findings:
            sev = f.get("severity", "info")
            md += f"### [{sev.upper()}] {f.get('rule_id', '')}\n"
            md += f"- **File:** `{f.get('file_path', '')}:{f.get('line', 1)}`\n"
            md += f"- **Message:** {f.get('message', '')}\n"
            rem = f.get('remediation', '')
            if rem:
                md += f"- **Fix:** {rem}\n"
            md += "\n"

        return md
