# -*- coding: utf-8 -*-
"""CLI入口 — argparse命令解析"""
import argparse
import sys
import os
from pathlib import Path

# 确保报src在路径上
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from .formatters import OutputFormatter as Fmt, Fore
from ..orchestrator.workflow import WorkflowOrchestrator
from ..reporting.generator import ReportGenerator
from ..utils.config import load_config


def create_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-audit",
        description="AI-Driven Code Security Audit & Auto-Fix Agent",
        epilog="More info: https://github.com/example/ai-audit",
    )

    # 全局选项
    parser.add_argument("--config", "-c", default=None, help="配置文件路径")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--no-color", action="store_true", help="禁用颜色输出")
    parser.add_argument("--output", "-o", default=None, help="报告输出路径")
    parser.add_argument("--format", "-f", default="json", choices=["json", "html", "markdown"],
                       help="报告格式")

    sub = parser.add_subparsers(dest="command", help="子命令")

    # ---- scan ----
    scan = sub.add_parser("scan", help="完整安全审计(静态+深度+修复)")
    scan.add_argument("--target", "-t", required=True, help="目标项目路径")
    scan.add_argument("--deep", dest="deep", action="store_true", default=True,
                      help="启用LLM深度分析(默认)")
    scan.add_argument("--no-deep", dest="deep", action="store_false",
                      help="禁用LLM深度分析(仅静态扫描)")
    scan.add_argument("--auto-fix", action="store_true", default=False,
                      help="自动应用修复(dangerous!)")
    scan.add_argument("--output", "-o", default=None, help="报告输出路径")

    # ---- quick-scan ----
    quick = sub.add_parser("quick-scan", help="快速静态扫描(无LLM)")
    quick.add_argument("--target", "-t", required=True, help="目标路径")
    quick.add_argument("--output", "-o", default=None)

    # ---- supply-chain ----
    sc = sub.add_parser("supply-chain", help="供应链安全检查")
    sc.add_argument("--target", "-t", required=True, help="目标路径")
    sc.add_argument("--output", "-o", default=None)

    # ---- fix ----
    fix = sub.add_parser("fix", help="生成修复补丁")
    fix.add_argument("--target", "-t", required=True, help="目标路径")
    fix.add_argument("--finding-ids", nargs="*", default=None, help="指定要修复的finding ID")
    fix.add_argument("--dry-run", action="store_true", default=True, help="仅生成补丁不应用(默认)")
    fix.add_argument("--apply", dest="dry_run", action="store_false", help="实际应用修复")

    # ---- verify ----
    verify = sub.add_parser("verify", help="验证已应用的修复")
    verify.add_argument("--target", "-t", required=True, help="目标路径")

    # ---- report ----
    report = sub.add_parser("report", help="从之前的扫描生成报告")
    report.add_argument("--input", "-i", required=True, help="之前的扫描结果JSON")
    report.add_argument("--output", "-o", required=True, help="输出路径")
    report.add_argument("--format", "-f", default="json", choices=["json", "html", "markdown"])

    return parser


def main(args=None):
    parser = create_arg_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 1

    fmt = Fmt(use_color=not parsed.no_color)
    load_config(parsed.config)

    try:
        orchestrator = WorkflowOrchestrator()
    except Exception as e:
        fmt.print_error(f"初始化失败: {e}")
        return 1

    # ---- 执行命令 ----
    if parsed.command == "scan":
        fmt.print_header(f"Full Audit: {parsed.target}")
        result = orchestrator.scan(
            target_path=parsed.target,
            deep_analysis=parsed.deep,
            auto_fix=parsed.auto_fix,
        )
        fmt.print_summary(result)

        # 输出报告
        out = parsed.output or os.path.join("reports", "audit_report.json")
        ReportGenerator().save_report(result, out, parsed.format)
        fmt.print_success(f"报告已保存: {out}")

        if parsed.verbose and result.findings:
            fmt.print_header("Findings Detail")
            for i, f in enumerate(result.findings[:20], 1):
                fmt.print_finding(f, i)
            if len(result.findings) > 20:
                fmt.print_info(f"... and {len(result.findings) - 20} more")

        code = 0 if result.success else 1

    elif parsed.command == "quick-scan":
        fmt.print_header(f"Quick Scan: {parsed.target}")
        result = orchestrator.quick_scan(parsed.target)
        fmt.print_summary(result)

        out = parsed.output or os.path.join("reports", "quick_scan.json")
        ReportGenerator().save_report(result, out, parsed.format)
        fmt.print_success(f"Quick scan done. Report: {out}")
        code = 0

    elif parsed.command == "supply-chain":
        fmt.print_header(f"Supply Chain Check: {parsed.target}")
        result = orchestrator.supply_chain_check(parsed.target)

        if result.supply_chain_findings:
            fmt.print_info(f"Found {len(result.supply_chain_findings)} supply chain risks:")
            for f in result.supply_chain_findings:
                sev = f.get("severity", "info")
                pkg = f.get("package", "?")
                desc = f.get("description", "")[:80]
                print(f"  [{sev.upper()}] {pkg} - {desc}")

        out = parsed.output or os.path.join("reports", "supply_chain.json")
        ReportGenerator().save_report(result, out, parsed.format)
        fmt.print_success(f"Report: {out}")
        code = 0

    elif parsed.command == "fix":
        fmt.print_header(f"Generate Fixes: {parsed.target}")
        # 先做一次快速扫描获取findings
        fmt.print_info("Running quick scan first...")
        scan_result = orchestrator.quick_scan(parsed.target)
        fmt.print_summary(scan_result)

        # 然后尝试修复
        result = orchestrator.fix(
            parsed.target,
            finding_ids=parsed.finding_ids,
            dry_run=parsed.dry_run,
        )

        fmt.print_info(f"Generated {len(result.fixes)} fixes")
        if parsed.dry_run:
            fmt.print_warning("DRY RUN - 未实际修改文件")

        out = parsed.output or os.path.join("reports", "fixes.json")
        ReportGenerator().save_report(result, out, "json")
        code = 0

    elif parsed.command == "verify":
        fmt.print_header(f"Verify Fixes: {parsed.target}")
        result = orchestrator.verify(parsed.target)

        summary = result.summary or {}
        fmt.print_info(f"Verified: {summary.get('passed', 0)}/{summary.get('total_fixes', 0)} passed")
        code = 0 if result.success else 1

    elif parsed.command == "report":
        fmt.print_header(f"Generate Report")
        import json
        with open(parsed.input, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 简单包装成类似WorkflowResult的对象
        class FakeResult:
            findings = data.get("findings", [])
            supply_chain_findings = data.get("supply_chain", [])
            fixes = data.get("fixes_applied", [])
            target = data.get("metadata", {}).get("target", "")
            duration = data.get("metadata", {}).get("duration_seconds", 0)
            errors = data.get("errors", [])
            success = True

        ReportGenerator().save_report(FakeResult(), parsed.output, parsed.format)
        fmt.print_success(f"Report: {parsed.output}")
        code = 0

    else:
        parser.print_help()
        code = 1

    return code


if __name__ == "__main__":
    sys.exit(main())
