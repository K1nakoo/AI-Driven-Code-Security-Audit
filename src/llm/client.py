# -*- coding: utf-8 -*-
"""LLM客户端 - OpenAI兼容接口"""
import os
import json
import time
from typing import Optional, List, Dict, Any, Generator

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    # print("[LLM] openai库未安装, LLM功能不可用")

from .retry import retry_on_error, LLMRateLimitError, LLMTimeoutError, LLMAuthError
from .prompts import DEEP_ANALYZER_SYSTEM, DEEP_ANALYZER_USER


class LLMClient:
    """封装OpenAI兼容API的客户端，支持DeepSeek等兼容接口"""

    def __init__(self, config=None):
        self.config = config or {}
        self.api_key = os.environ.get("LLM_API_KEY", self.config.get("api_key", ""))
        self.api_base = os.environ.get(
            "LLM_API_BASE",
            self.config.get("api_base", "https://api.openai.com/v1"),
        )
        self.model = os.environ.get("LLM_MODEL", self.config.get("model", "gpt-4"))
        self.temperature = float(self.config.get("temperature", 0.1))
        self.max_tokens = int(self.config.get("max_tokens", 4096))

        self._client = None
        if HAS_OPENAI and self.api_key:
            self._client = OpenAI(api_key=self.api_key, base_url=self.api_base)

        # print(f"[LLM] 客户端初始化: model={self.model}, base={self.api_base}")

    @property
    def is_available(self) -> bool:
        return self._client is not None

    @retry_on_error(max_retries=3)
    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = None,
        max_tokens: int = None,
        response_format: Optional[dict] = None,  # 支持JSON mode
    ) -> str:
        """单轮对话"""
        if not self._client:
            return json.dumps({
                "error": "LLM客户端不可用，请设置LLM_API_KEY环境变量",
                "is_vulnerable": False,
                "confidence": 0.0,
            })

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature if temperature is not None else self.temperature,
                "max_tokens": max_tokens or self.max_tokens,
            }
            if response_format:
                kwargs["response_format"] = response_format

            t0 = time.perf_counter()
            response = self._client.chat.completions.create(**kwargs)
            elapsed = time.perf_counter() - t0

            content = response.choices[0].message.content.strip()
            # print(f"[LLM] 耗时 {elapsed:.2f}s, tokens: {response.usage.total_tokens}")  # debug
            return content

        except Exception as e:
            error_str = str(e).lower()
            if "rate" in error_str or "429" in error_str:
                raise LLMRateLimitError(str(e))
            if "timeout" in error_str:
                raise LLMTimeoutError(str(e))
            if "auth" in error_str or "401" in error_str or "403" in error_str:
                raise LLMAuthError(str(e))
            # 其他错误重试
            raise ConnectionError(str(e))  # 会被retry_on_error捕获

    def complete_with_history(self, messages: List[Dict[str, str]], temperature: float = None) -> str:
        """多轮对话(带历史)"""
        if not self._client:
            return json.dumps({"error": "LLM不可用"})

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature or self.temperature,
            "max_tokens": self.max_tokens,
        }

        response = self._client.chat.completions.create(**kwargs)
        return response.choices[0].message.content.strip()

    def stream_complete(self, prompt: str, system_prompt: str = "") -> Generator[str, None, None]:
        """流式输出 - 用于实时展示"""
        if not self._client:
            yield "LLM不可用"
            return

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        stream = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            stream=True,
        )

        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    # --- 专用方法 ---

    def analyze_code(self, code: str, finding: dict, file_path: str = "",
                     language: str = "python") -> Dict[str, Any]:
        """深度分析一个代码漏洞 - 核心方法"""
        import json as json_mod

        user_prompt = DEEP_ANALYZER_USER.format(
            file_path=file_path,
            static_finding=json_mod.dumps(finding, ensure_ascii=False, indent=2),
            code_context=code,
            language=language,
        )

        response = self.complete(
            prompt=user_prompt,
            system_prompt=DEEP_ANALYZER_SYSTEM,
        )

        # 解析JSON响应
        try:
            # 处理可能的markdown包裹
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                response = response.split("```")[1].split("```")[0]
            return json_mod.loads(response)
        except (json_mod.JSONDecodeError, IndexError):
            print(f"[LLM] JSON解析失败, 原始响应: {response[:200]}...")  # debug
            return {
                "error": "JSON解析失败",
                "raw_response": response,
                "is_vulnerable": True,
                "confidence": 0.5,
            }

    def generate_fix(self, finding: dict, original_code: str, language: str = "python") -> Dict[str, Any]:
        """生成修复代码"""
        from .prompts import FIX_GENERATOR_SYSTEM, FIX_GENERATOR_USER
        import json as json_mod

        user_prompt = FIX_GENERATOR_USER.format(
            finding_info=json_mod.dumps(finding, ensure_ascii=False, indent=2),
            original_code=original_code,
            language=language,
        )

        response = self.complete(
            prompt=user_prompt,
            system_prompt=FIX_GENERATOR_SYSTEM,
        )

        try:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                response = response.split("```")[1].split("```")[0]
            return json_mod.loads(response)
        except (json_mod.JSONDecodeError, IndexError):
            return {"error": "JSON解析失败", "confidence": 0.0}

    def analyze_supply_chain(self, deps: list) -> Dict[str, Any]:
        """分析供应链风险"""
        from .prompts import SUPPLY_CHAIN_SYSTEM, SUPPLY_CHAIN_USER
        import json as json_mod

        user_prompt = SUPPLY_CHAIN_USER.format(
            dependency_list=json_mod.dumps(deps, ensure_ascii=False, indent=2),
        )

        response = self.complete(
            prompt=user_prompt,
            system_prompt=SUPPLY_CHAIN_SYSTEM,
        )

        try:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                response = response.split("```")[1].split("```")[0]
            return json_mod.loads(response)
        except (json_mod.JSONDecodeError, IndexError):
            return {"error": "JSON解析失败", "dependencies": []}


# 模块级便捷实例(需要时再初始化)
# _client_cache = None

# def get_llm_client(config=None):
#     global _client_cache
#     if _client_cache is None:
#         _client_cache = LLMClient(config)
#     return _client_cache
