# -*- coding: utf-8 -*-
"""CLI输出格式化 — 颜色 + 进度条 + 表格"""
import shutil
import sys
from typing import List, Optional

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False
    # 定义空属性防止AttributeError
    class _Dummy(str):
        def __getattr__(self, _): return ""
    Fore = _Dummy("")
    Style = _Dummy("")

# ANSI后备
RESET = "\033[0m" if not _HAS_COLOR else ""
BOLD = "\033[1m"


def term_width() -> int:
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


class OutputFormatter:
    """CLI美化输出"""

    def __init__(self, use_color: bool = True):
        self.use_color = use_color and _HAS_COLOR

    def c(self, text: str, color: str) -> str:
        """简单的着色"""
        if not self.use_color:
            return text
        return f"{color}{text}{Fore.RESET}"

    def print_header(self, text: str):
        w = min(term_width(), 80)
        print()
        print("=" * w)
        print(f"  {text}")
        print("=" * w)

    def print_success(self, msg: str):
        print(f"{Fore.GREEN}[OK] {msg}{Fore.RESET}")

    def print_error(self, msg: str):
        print(f"{Fore.RED}[ERROR] {msg}{Fore.RESET}", file=sys.stderr)

    def print_warning(self, msg: str):
        print(f"{Fore.YELLOW}[WARN] {msg}{Fore.RESET}")

    def print_info(self, msg: str):
        print(f"{Fore.CYAN}[INFO] {msg}{Fore.RESET}")

    def print_finding(self, finding: dict, index: int = 0):
        """格式化输出一个finding"""
        sev = finding.get("severity", "info")
        sev_colors = {
            "critical": Fore.MAGENTA,
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.BLUE,
            "info": Fore.WHITE,
        }
        color = sev_colors.get(sev, "")

        rule = finding.get("rule_id", "?")[:50]
        msg = finding.get("message", "")[:100]
        line = finding.get("line", 1)
        fpath = finding.get("file_path", "?")
        code = finding.get("code_snippet", "")[:80]

        print(f"  [{index}] {color}[{sev.upper()}]{Fore.RESET} {rule}")
        print(f"      {fpath}:{line}")
        if msg:
            print(f"      {msg}")
        if code:
            print(f"      > {Fore.BLACK + Style.DIM}{code}{Fore.RESET}")

    def print_summary(self, audit_result):
        """打印审计摘要"""
        findings = getattr(audit_result, "findings", [])
        sc = getattr(audit_result, "supply_chain_findings", [])
        fixes = getattr(audit_result, "fixes", [])
        dur = getattr(audit_result, "duration", 0)

        sev = {}
        for f in findings:
            s = f.get("severity", "info")
            sev[s] = sev.get(s, 0) + 1

        print(f"\n{'─'*50}")
        print(f"  Audit Summary")
        print(f"{'─'*50}")
        print(f"  Duration : {dur:.1f}s")
        print(f"  Findings : {len(findings)}")
        for lvl in ("critical", "high", "medium", "low", "info"):
            if sev.get(lvl):
                print(f"    {lvl:8s}: {sev[lvl]}")
        print(f"  SupplyChain: {len(sc)} risks")
        print(f"  Fixes     : {len(fixes)}")
        print(f"{'─'*50}")

    def print_progress(self, stage: str, current: int, total: int):
        """简易进度条"""
        if total <= 0:
            return
        pct = min(current / total, 1.0)
        width = 30
        filled = int(width * pct)
        bar = "█" * filled + "░" * (width - filled)
        print(f"\r  [{stage}] {bar} {current}/{total} ({pct*100:.0f}%)", end="")
        if current >= total:
            print()

    def print_table(self, headers: List[str], rows: List[List[str]]):
        """对齐表格"""
        if not rows:
            return
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))

        # Header
        header_line = "  " + " | ".join(
            h.ljust(col_widths[i]) for i, h in enumerate(headers)
        )
        print(header_line)
        print("  " + "-" * (sum(col_widths) + 3 * (len(headers) - 1)))

        # Rows
        for row in rows:
            line = "  " + " | ".join(
                str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)
            )
            print(line)

    def print_fix_result(self, fix_result: dict):
        """打印修复结果"""
        print(f"\n  {Fore.GREEN}Patch:{Fore.RESET}")
        diff = fix_result.get("diff", fix_result.get("patch", ""))
        if diff:
            # 高亮diff中的+行
            for line in diff.split("\n")[:20]:  # 最多显示20行
                if line.startswith("---") or line.startswith("+++"):
                    print(f"    {Fore.CYAN}{line}{Fore.RESET}")
                elif line.startswith("+"):
                    print(f"    {Fore.GREEN}{line}{Fore.RESET}")
                elif line.startswith("-"):
                    print(f"    {Fore.RED}{line}{Fore.RESET}")
                else:
                    print(f"    {line}")
            if len(diff.split("\n")) > 20:
                print(f"    ... (truncated)")

    def spinner(self, text: str = "Processing"):
        """简单的旋转指示器(generator)"""
        frames = ["|", "/", "-", "\\"]
        i = 0
        while True:
            yield f"\r  {Fore.CYAN}{frames[i]}{Fore.RESET} {text}..."
            i = (i + 1) % 4


# 模块级实例
formatter = OutputFormatter()
