# -*- coding: utf-8 -*-
"""日志模块 - 控制台彩色 + 文件输出"""
import logging
import sys
from pathlib import Path

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = {
        "DEBUG": Fore.CYAN,
        "INFO": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
    }
except ImportError:
    # 没有colorama时退化成纯文本
    COLORS = {}


class ColoredFormatter(logging.Formatter):
    """带颜色的控制台Formatter"""

    def format(self, record):
        if COLORS:
            color = COLORS.get(record.levelname, "")
            record.levelname = f"{color}{record.levelname}{Style.RESET_ALL if hasattr(Style, 'RESET_ALL') else ''}"
            record.msg = f"{color}{str(record.msg)}{Style.RESET_ALL if hasattr(Style, 'RESET_ALL') else ''}"
        return super().format(record)


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """获取命名logger"""
    logger = logging.getLogger(f"audit.{name}")

    if not logger.handlers:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))

        # 控制台handler
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(ColoredFormatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S"
        ))
        logger.addHandler(console)

        # 文件handler(可选)
        log_file = Path("audit.log")
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            ))
            logger.addHandler(fh)
        except (OSError, PermissionError):
            pass  # 文件写入失败不影响使用

    return logger


def setup_logging(level: str = "INFO", log_file: str = None):
    """全局日志初始化"""
    root_logger = get_logger("root", level)
    print(f"[Logger] 日志级别: {level}")  # debug
    return root_logger
