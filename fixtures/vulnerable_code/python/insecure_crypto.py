"""
不安全加密实现 样本文件
CWE-327: Use of a Broken or Risky Cryptographic Algorithm
CWE-328: Use of Weak Hash
CWE-329: Generation of Predictable IV
CWE-326: Inadequate Encryption Strength
"""
import hashlib
import random  # BAD: 不应用于加密目的!
import secrets  # GOOD: 加密安全随机数
import hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

print("[CRYPTO] 加载加密模块 - 包含故意的不安全实现")


# ========== CWE-328: 弱哈希算法 ==========

def hash_password_md5(password: str) -> str:
    """使用MD5哈希密码 - 不安全!"""
    # BAD: MD5已破解，易受碰撞攻击
    print(f"[MD5] hashing password...")
    return hashlib.md5(password.encode()).hexdigest()
    # FIXME: 应使用bcrypt, argon2 或至少 SHA-256


def hash_password_sha1(password: str) -> str:
    """SHA-1 也不安全了 (SHAttered攻击)"""
    # BAD: SHA-1 has been broken
    h = hashlib.sha1()
    h.update(password.encode("utf-8"))
    return h.hexdigest()


def double_md5(password: str) -> str:
    """双重MD5 - 并不比单次MD5更安全"""
    # BAD: 双重哈希仍然不安全
    first = hashlib.md5(password.encode()).hexdigest()
    second = hashlib.md5(first.encode()).hexdigest()
    return second


# ========== 安全的密码哈希对比 ==========

def hash_password_secure(password: str) -> str:
    """安全的密码哈希 - 使用SHA-256加盐"""
    # GOOD: SHA-256 + 随机盐
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256()
    hash_obj.update((password + salt).encode("utf-8"))
    return f"{salt}:{hash_obj.hexdigest()}"


def verify_password_secure(stored: str, password: str) -> bool:
    """验证加盐哈希"""
    salt, hash_val = stored.split(":")
    check = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    # GOOD: hmac.compare_digest 防止计时攻击
    return hmac.compare_digest(check, hash_val)


# ========== CWE-329: 可预测的IV ==========

def encrypt_with_fixed_iv(plaintext: bytes) -> bytes:
    """使用固定IV的AES加密 - 不安全!"""
    key = b"1234567890123456"  # 硬编码密钥
    iv = b"0000000000000000"  # BAD: 固定IV (全零)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # pad plaintext to 16 bytes
    pad_len = 16 - (len(plaintext) % 16)
    plaintext = plaintext + bytes([pad_len]) * pad_len

    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct


# ========== CWE-326: 弱密钥长度 ==========

def generate_weak_rsa_key():
    """生成弱RSA密钥 - 1024位不安全"""
    # BAD: 1024-bit RSA 可在合理时间内被破解
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # TOO SMALL! 应该至少2048
        backend=default_backend()
    )
    print("[WARN] 生成的RSA密钥只有1024位!")
    return private_key


def generate_secure_rsa_key():
    """安全的RSA密钥生成 - 对比"""
    # GOOD: 3072-bit for better security
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend()
    )


def encrypt_des(plaintext: bytes, key: bytes) -> bytes:
    """DES加密 - 已废弃的算法"""
    # BAD: DES使用56位密钥，已可通过暴力破解
    from Crypto.Cipher import DES as DES_Cipher

    # DES key must be exactly 8 bytes
    key = key[:8].ljust(8, b"\x00")
    cipher = DES_Cipher.new(key, DES_Cipher.MODE_ECB)
    # pad
    pad_len = 8 - (len(plaintext) % 8)
    plaintext = plaintext + bytes([pad_len]) * pad_len
    return cipher.encrypt(plaintext)


# ========== CWE-327: ECB模式 ==========

def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    """AES-ECB模式 - 不安全!"""
    # BAD: ECB mode reveals patterns in plaintext
    # 相同的明文块产生相同的密文块
    print("[ECB] encrypting with ECB mode...")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding
    pad_len = 16 - (len(plaintext) % 16)
    plaintext = plaintext + bytes([pad_len]) * pad_len

    return encryptor.update(plaintext) + encryptor.finalize()


# ========== CWE-331: 熵不足 ==========

def generate_token_insecure() -> str:
    """使用random模块生成token - 不安全!"""
    # BAD: random模块不适合加密用途
    # Mersenne Twister可以被预测
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    token = "".join(random.choice(chars) for _ in range(32))
    print(f"[random] generated token: {token[:8]}...")
    return token


def generate_token_secure() -> str:
    """安全token生成 - 对比"""
    # GOOD: 使用secrets模块
    import string
    alphabet = string.ascii_lowercase + string.digits
    token = "".join(secrets.choice(alphabet) for _ in range(32))
    return token


def generate_reset_token():
    """密码重置token - 使用不安全的随机"""
    # BAD: 使用当前时间作为种子
    import time
    random.seed(int(time.time()))  # 基于时间的种子可预测
    return hashlib.md5(str(random.random()).encode()).hexdigest()


# ========== 更多不安全模式 ==========

def encrypt_rc4(plaintext: bytes, key: bytes) -> bytes:
    """RC4加密 - 已被证明不安全"""
    # BAD: RC4 has known biases and vulnerabilities
    from Crypto.Cipher import ARC4
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)


def insecure_key_derivation(password: str) -> bytes:
    """不安全的密钥派生"""
    # BAD: 单次MD5不足以派生密钥
    # 应该使用PBKDF2, bcrypt 或 argon2
    return hashlib.md5(password.encode()).digest()


def secure_key_derivation(password: str, salt: bytes = None) -> bytes:
    """安全的密钥派生 - 对比"""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if salt is None:
        salt = os.urandom(16)

    # GOOD: PBKDF2 with 100000 iterations
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # 足够多的迭代次数
        backend=default_backend()
    )
    return salt + kdf.derive(password.encode())


# ========== 不安全的签名验证 ==========

def verify_signature_insecure(message: bytes, signature: bytes, expected: bytes) -> bool:
    """不安全的签名验证 - 易受计时攻击"""
    # BAD: 字符串比较可能在第一个不同字节就返回
    computed_sig = hashlib.sha256(message + b"secret_key").digest()
    return computed_sig == signature  # 计时攻击风险!


def verify_signature_secure(message: bytes, signature: bytes) -> bool:
    """安全的签名验证"""
    computed = hashlib.sha256(message + b"secret_key").digest()
    # GOOD: 恒定时间比较
    return hmac.compare_digest(computed, signature)


# ========== 硬编码密钥 ==========

# 各种硬编码的加密密钥 (同时触发硬编码凭据检测)
HARDCODED_AES_KEY = b"1234567890abcdef"  # 128-bit AES key
HARDCODED_HMAC_KEY = b"my_hmac_secret_key_2024"  # HMAC key
ENCRYPTION_PASSWORD = "P@ssw0rdForEncryption"  # 用于加密的密码

# BAD: 硬编码的素数 (某些加密实现会用到)
RSA_PRIME_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
RSA_PRIME_Q = 0x28CA36A549B5F3B3D62B5CB9A0B3D5B3


if __name__ == "__main__":
    print("=" * 60)
    print("不安全加密实现 测试样本")
    print("包含 CWE-327, CWE-328, CWE-329, CWE-326, CWE-331 示例")
    print("=" * 60)

    # Demo the weak hash
    test_pass = "test_password_123"
    print(f"\nMD5 hash: {hash_password_md5(test_pass)}")
    print(f"Secure hash: {hash_password_secure(test_pass)}")

    # Compare token generation
    print(f"\nInsecure token: {generate_token_insecure()[:16]}...")
    print(f"Secure token: {generate_token_secure()[:16]}...")

    print(f"\nWeak RSA key size: 1024 bits (BAD)")
    print(f"Secure RSA key size: 3072 bits (GOOD)")
