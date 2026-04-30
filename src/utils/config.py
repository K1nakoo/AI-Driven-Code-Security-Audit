# -*- coding: utf-8 -*-
"""
配置管理模块 - 从YAML加载 + 环境变量覆盖
AUDIT_前缀环境变量自动映射到配置项
"""
import os
import json
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    # print("[Config] yaml not available, using JSON for config")  # debug
from typing import Any, Optional


class Config:
    """全局配置单例，点号访问嵌套键"""

    _instance = None
    _config_data = {}

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # print("[Config] 初始化单例")  # debug用
        return cls._instance

    def load(self, config_path: Optional[str] = None):
        """加载YAML配置文件"""
        if config_path is None:
            # 默认从 config/default.yaml 加载
            config_path = Path(__file__).parent.parent.parent / "config" / "default.yaml"

        config_path = Path(config_path)
        if not config_path.exists():
            # TODO: 配置文件不存在时应该用纯默认配置
            print(f"[Config] 警告: 配置文件不存在 {config_path}, 使用默认值")
            self._config_data = {}
            self._apply_env_overrides()
            return

        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        if HAS_YAML:
            self._config_data = yaml.safe_load(content) or {}
        elif config_path.suffix in (".json",):
            self._config_data = json.loads(content)
        else:
            # YAML fallback: try to load as YAML anyway, or use empty dict
            try:
                import yaml as _y
                self._config_data = _y.safe_load(content) or {}
            except ImportError:
                print(f"[Config] yaml/pyyaml not installed, config empty. Run: pip install pyyaml")
                self._config_data = {}

        self._apply_env_overrides()
        print(f"[Config] 已加载配置: {config_path}")  # debug

    def _apply_env_overrides(self):
        """环境变量覆盖 - AUDIT_ 前缀"""
        for key, value in os.environ.items():
            if not key.startswith("AUDIT_"):
                continue
            # AUDIT_LLM_MODEL -> llm.model
            config_key = key[6:].lower().replace("__", ".")
            self._set_nested(config_key, self._convert_value(value))

    def _convert_value(self, value: str) -> Any:
        """智能类型转换"""
        lower = value.lower()
        if lower in ("true", "yes", "1"):
            return True
        if lower in ("false", "no", "0"):
            return False
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        return value

    def get(self, key: str, default: Any = None) -> Any:
        """点号访问: config.get('llm.model')"""
        parts = key.split(".")
        value = self._config_data
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        return value

    def set(self, key: str, value: Any):
        """设置配置值"""
        self._set_nested(key, value)

    def _set_nested(self, key: str, value: Any):
        parts = key.split(".")
        d = self._config_data
        for part in parts[:-1]:
            if part not in d:
                d[part] = {}
            d = d[part]
        d[parts[-1]] = value

    def save(self, path: str):
        """保存配置到文件"""
        with open(path, "w", encoding="utf-8") as f:
            if HAS_YAML:
                yaml.safe_dump(self._config_data, f, allow_unicode=True)
            else:
                json.dump(self._config_data, f, ensure_ascii=False, indent=2)

    def to_dict(self) -> dict:
        return self._config_data

    def keys(self):
        return self._config_data.keys()

    def values(self):
        return self._config_data.values()

    def items(self):
        return self._config_data.items()

    def __contains__(self, key):
        return key in self._config_data

    # 向后兼容 - 直接用属性访问(deprecated, 用get方法)
    # def __getattr__(self, name):
    #     if name in self._config_data:
    #         return self._config_data[name]
    #     raise AttributeError(f"Config has no key '{name}'")


# 模块级实例 - 全局共享
config = Config()


def load_config(config_path: Optional[str] = None):
    """便捷函数: 加载配置"""
    config.load(config_path)
    return config
