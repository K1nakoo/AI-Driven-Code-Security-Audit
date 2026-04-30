# -*- coding: utf-8 -*-
"""计时工具 - context manager + decorator"""
import time
from functools import wraps


class Timer:
    """上下文管理器计时"""

    def __init__(self, name="Operation"):
        self.name = name
        self.start_time = None
        self.elapsed = 0.0

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.elapsed = time.perf_counter() - self.start_time
        print(f"[Timer] {self.name} 耗时: {self.elapsed:.3f}s")

    # def __call__(self, func):  # 实验: 同时支持decorator用法但有点乱
    #     @wraps(func)
    #     def wrapper(*args, **kwargs):
    #         with self:
    #             return func(*args, **kwargs)
    #     return wrapper


def timed(prefix="func"):
    """装饰器 - 自动打印函数执行时间"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            t0 = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed = time.perf_counter() - t0
            print(f"[Timer] {prefix}::{func.__name__} -> {elapsed:.3f}s")
            return result
        return wrapper
    return decorator
