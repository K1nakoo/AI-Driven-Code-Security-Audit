"""
Hardcoded Secrets / 硬编码凭据 检测样本
包含各种硬编码密钥、密码、Token模式
WARNING: 这些是假凭据，但pattern是真实的!!!
"""
import os
import requests

print("[DEBUG] 加载包含硬编码凭据的模块...")

# ========== 数据库凭据 ==========

# PostgreSQL connection string with password
DATABASE_URL = "postgresql://admin:SuperSecret123!@localhost:5432/mydb"

# MySQL 连接字符串 - dev only
MYSQL_CONN = "mysql://root:rootpassword123@127.0.0.1:3306/app_prod"  # hardcoded!

# MongoDB - 包含凭据的连接字符串
MONGO_URI = "mongodb://dbuser:dbpass_2024!@cluster0.mongodb.net/myapp?retryWrites=true"

# Redis - 有时密码是硬编码的
REDIS_URL = "redis://:redis_secret_key_999@localhost:6379/0"

# SQLite (虽然没有密码，但是硬编码路径也是问题)
SQLITE_PATH = "/opt/app/data/users.db"


# ========== API Keys & Tokens ==========

# OpenAI API Key - test only
OPENAI_API_KEY = "sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# GitHub Personal Access Token
GITHUB_TOKEN = "ghp_1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4rS5tU6v"

# GitHub classic token
GITHUB_CLASSIC = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # FIXME: remove before commit

# GitLab Personal Access Token
GITLAB_TOKEN = "glpat-abcdefghijklmnop12345678"

# AWS Access Key (假key，pattern真实)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# TODO: 记得从环境变量读取，不要硬编码

# AWS Session Token
AWS_SESSION_TOKEN = "FQoGZXIvYXdzELH//////////wEaDENG/TOKEN/EXAMPLE1234567890abcdef=="

# Azure Storage Account
AZURE_STORAGE_KEY = "DefaultEndpointsProtocol=https;AccountName=myappstorage;AccountKey=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwx/yz==;EndpointSuffix=core.windows.net"

# Google API Key
GOOGLE_API_KEY = "AIzaSyD-abcdefghijklmnopqrstuvwxyz123456"

# Slack Webhook - 有时是敏感信息泄露
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# SendGrid API Key
SENDGRID_KEY = "SG.abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyz12"

# Stripe keys - test mode
STRIPE_SECRET_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"  # 测试密钥，但仍然敏感
STRIPE_PUBLISHABLE_KEY = "pk_test_TYooMQauvdEDq54NiTphI7jx"

# Twilio credentials
TWILIO_ACCOUNT_SID = "ACabcdef1234567890abcdef1234567890"
TWILIO_AUTH_TOKEN = "1234567890abcdef1234567890abcdef"

# ========== JWT / Encryption Secrets ==========

# JWT Secret - 应该是随机的，不能硬编码
JWT_SECRET = "my-super-secret-jwt-key-2024"  # 硬编码JWT密钥!
JWT_ALGORITHM = "HS256"

# Flask Secret Key - 硬编码
FLASK_SECRET = "hardcoded-flask-secret-do-not-use-in-production"

# Django SECRET_KEY
DJANGO_SECRET = "django-insecure-abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()"

# AES Encryption Key
AES_KEY = b"1234567890123456"  # 128-bit key hardcoded
AES_IV = b"1234567890123456"  # IV 也不应该硬编码

# RSA Private Key (内嵌在代码中的私钥!)
RSA_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS2QF4GqYxHvRU6hH6JBm5pXhKbJP4jE1N3KXDEc5
Ru5V3cL09XjRU7GkHGhjHGFqJ3wEFpOQ0VWER3Bf0GaHdV6EkpM7yQ2R2slN
-----END RSA PRIVATE KEY-----
"""

# Ed25519 Private Key
ED25519_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----"


# ========== 密码 ==========

# Hardcoded passwords
ADMIN_PASSWORD = "admin123!"
DB_PASSWORD = "P@ssw0rd_For_Production_DB"  # 测试环境的测试密码

# Default credentials
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "changeme"  # 部署时需要修改!

# LDAP bind password
LDAP_PASSWORD = "ldap_bind_pass_2024"


# ========== Connection Strings with Credentials ==========

# SQLAlchemy - 连接字符串包含密码
SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://appuser:app_pass_999@db.internal:5432/appdb"

# Cassandra
CASSANDRA_CONN = "cassandra://cassandra_user:cassandra_secret@node1,node2:9042/keyspace1"

# Elasticsearch
ELASTICSEARCH_URL = "https://elastic:elastic_password_123@es-cluster:9200"


# ========== 被注释掉的真实凭据 (不要取消注释!) ==========

# 以下是被注释掉的凭据示例
# 扫描器应该能检测到被注释的凭据也有泄漏风险

# PASSWORD_COMMENTED = "SuperAdmin123"  # 这个密码被注释了，但还是危险

# # 开发时使用的真实key (已废弃)
# # PROD_API_KEY = "pk_live_abcdefghijklmnop"  # 生产key被注释掉了

# # 旧数据库密码 (不再使用)
# # OLD_DB_PASS = "0ld_Db_P@ss_W0rd"


# ========== 通过环境变量读取的正确方式 ==========

def get_api_key():
    """安全地获取API密钥 - 正确做法示例"""
    # GOOD: 从环境变量读取
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("[WARNING] API key not found in environment!")
        # BAD: fallback到硬编码密钥
        api_key = "sk-fallback-hardcoded-key-1234"  # 回退到硬编码很危险!
    return api_key


class DatabaseConfig:
    """数据库配置类 - 混合了安全和危险做法"""

    # 类属性 - 硬编码 (会触发检测)
    DEFAULT_HOST = "localhost"
    DEFAULT_PORT = 5432
    DEFAULT_PASSWORD = "db_class_password_123"  # FIXME: 不应该硬编码

    def __init__(self):
        # 实例属性
        self.host = os.environ.get("DB_HOST", "localhost")  # OK - 环境变量有默认值
        self.password = os.environ.get("DB_PASSWORD", "fallback_pass")  # BAD: 默认密码


# ========== 混淆的凭据 (更难检测) ==========

def get_password():
    """尝试通过变量名混淆密码"""
    p = "s"
    p += "e"
    p += "c"
    p += "r"
    p += "e"
    p += "t"
    # 这种拼凑方式更难被静态分析发现
    return p  # 返回 "secret"


# Base64 encoded password (dGVzdF9wYXNz = "test_pass")
ENCODED_PASS = "dGVzdF9wYXNzd29yZA=="

# 变量名误导
nothing_to_see_here = "real_password_12345"  # Not suspicious at all...


if __name__ == "__main__":
    print("此文件中包含多种硬编码凭据模式!")
    print("用于测试安全扫描器的凭据检测能力")
    print(f"Database URL: {DATABASE_URL}")
    print(f"AWS Key prefix: {AWS_ACCESS_KEY_ID[:10]}...")
    print(f"JWT Secret: {JWT_SECRET[:10]}...")
