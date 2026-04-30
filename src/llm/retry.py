# -*- coding: utf-8 -*-
"""LLM调用重试机制 - 指数退避 + 错误处理"""
import time
import random
from functools import wraps
from typing import Type, Tuple


class LLMRateLimitError(Exception):
    """API频率限制"""
    pass


class LLMTimeoutError(Exception):
    """API超时"""
    pass


class LLMAuthError(Exception):
    """认证失败"""
    pass


def retry_on_error(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    max_delay: float = 30.0,
    retryable_errors: Tuple[Type[Exception], ...] = (
        LLMRateLimitError, LLMTimeoutError, ConnectionError, TimeoutError
    ),
):
    """重试装饰器，指数退避 + 随机抖动"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            delay = initial_delay

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_errors as e:
                    last_exception = e
                    if attempt == max_retries:
                        # FIXME: 最后一次重试也失败了，直接抛出
                        raise

                    # 指数退避 + 随机抖动(jitter) 避免惊群效应
                    jitter = random.uniform(0, delay * 0.5)
                    wait_time = delay + jitter
                    print(f"[Retry] {func.__name__} 重试 {attempt+1}/{max_retries}, "
                          f"等待 {wait_time:.1f}s - {e}")
                    time.sleep(wait_time)
                    delay = min(delay * backoff_factor, max_delay)

            # 理论上走不到这
            raise last_exception or RuntimeError("unknown retry error")

        return wrapper
    return decorator


# 测试用
if __name__ == "__main__":
    @retry_on_error(max_retries=2, initial_delay=0.1)
    def test_func():
        raise LLMRateLimitError("测试限制")
    try:
        test_func()
    except LLMRateLimitError:
        print("retry works")  # debug
