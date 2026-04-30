# -*- coding: utf-8 -*-
"""
AI Code Security Audit & Auto-Fix Agent
========================================
Setup configuration for the AI-powered code security auditing tool.

AI驱动的代码安全审计与自动修复工具
"""
import os
import re
from setuptools import setup, find_packages

# 读取版本信息 from src/__init__.py
VERSION_FILE = os.path.join(os.path.dirname(__file__), "src", "__init__.py")
version = "0.1.0"
# 尝试从src/__init__.py读取版本
if os.path.exists(VERSION_FILE):
    with open(VERSION_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    if match:
        version = match.group(1)
        print(f"[setup] 从src/__init__.py读取版本: {version}")

# 读取requirements.txt
REQUIREMENTS_FILE = os.path.join(os.path.dirname(__file__), "requirements.txt")
install_requires = []
if os.path.exists(REQUIREMENTS_FILE):
    with open(REQUIREMENTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # 跳过注释和空行
            if line and not line.startswith("#"):
                install_requires.append(line)

print(f"[setup] 读取到 {len(install_requires)} 个依赖项")

# 读取README (用于LONG_DESCRIPTION)
README_FILE = os.path.join(os.path.dirname(__file__), "README.md")
long_description = ""
if os.path.exists(README_FILE):
    with open(README_FILE, "r", encoding="utf-8") as f:
        long_description = f.read()
        print(f"[setup] README.md 读取完成 ({len(long_description)} 字符)")

setup(
    # 包基本信息
    name="ai-code-audit",
    version=version,
    author="AI Security Team",
    author_email="security@example.com",
    url="https://github.com/example/ai-code-audit",
    description="AI-Driven Code Security Audit & Auto-Fix Agent",
    long_description=long_description,
    long_description_content_type="text/markdown",

    # 包结构
    packages=find_packages(include=["src", "src.*"]),
    package_dir={"": "."},  # src目录作为根

    # Python版本要求
    python_requires=">=3.9",

    # 依赖项
    install_requires=install_requires,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
        "all": [
            "semgrep>=1.0.0",
            "bandit>=1.7.0",
        ],
    },

    # 命令行入口
    entry_points={
        "console_scripts": [
            "ai-audit=src.cli.main:main",
        ],
    },

    # 包含的非Python文件
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.html", "*.css", "*.js"],
        "src.reporting": ["templates/*.html", "templates/*.jinja2"],
    },

    # 不打包的文件
    exclude_package_data={
        "": ["*.pyc", "__pycache__", ".git", ".env"],
    },

    # PyPI分类
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Natural Language :: Chinese (Simplified)",
        "Natural Language :: English",
    ],

    # 关键字 (用于PyPI搜索)
    keywords=[
        "security", "code-audit", "static-analysis",
        "vulnerability-detection", "auto-fix", "saast",
        "code-security", "sql-injection", "xss",
        "AI", "LLM", "deepseek", "openai",
        "cybersecurity", "devsecops",
    ],

    # 项目URLs
    project_urls={
        "Bug Reports": "https://github.com/example/ai-code-audit/issues",
        "Source": "https://github.com/example/ai-code-audit",
        "Documentation": "https://github.com/example/ai-code-audit/docs",
    },
)

print("[setup] setup.py 配置完成!")
