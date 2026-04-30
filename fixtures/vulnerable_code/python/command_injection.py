"""
Command Injection & 危险函数调用 样本
CWE-78: OS Command Injection
CWE-94: Code Injection (eval/exec)
CWE-502: Deserialization of Untrusted Data
CWE-22: Path Traversal
"""
import os
import subprocess
import pickle
import base64
import sys
from flask import Flask, request

app = Flask(__name__)
print("[init] 命令注入测试服务加载完成")


# ========== CWE-78: OS Command Injection ==========

@app.route("/ping")
def ping_vulnerable():
    """经典的ping命令注入"""
    host = request.args.get("host", "127.0.0.1")
    print(f"[CMD-INJ] ping {host}")

    # BAD: os.system 直接拼接用户输入
    os.system("ping -c 1 " + host)
    # 攻击: /ping?host=8.8.8.8;cat /etc/passwd

    # BAD: os.popen 同样是命令注入
    stream = os.popen("nslookup " + host)
    result = stream.read()

    return f"<pre>Ping result:\n{result}</pre>"


@app.route("/ping_safe")
def ping_safe():
    """安全的ping实现 - 对比版"""
    host = request.args.get("host", "127.0.0.1")
    # GOOD: 使用列表参数避免shell注入
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5
        )
        return f"<pre>{result.stdout}</pre>"
    except subprocess.TimeoutExpired:
        return "Timeout", 504


@app.route("/exec_cmd")
def exec_cmd():
    """通用命令执行端点 - 极端危险"""
    cmd = request.args.get("cmd", "")
    print(f"[!!!] 执行命令: {cmd}")
    # BAD: subprocess with shell=True
    # 攻击: /exec_cmd?cmd=rm+-rf+/
    proc = subprocess.call(cmd, shell=True)  # shell=True + 用户输入 = 灾难
    return f"Command exited with code: {proc}"


def backup_file(filename):
    """文件备份函数 - 命令注入"""
    # BAD: 文件名中包含shell元字符
    print(f"备份文件: {filename}")
    os.system(f"cp {filename} {filename}.bak")
    # 攻击: filename = "legit.txt; rm -rf / #"


def convert_video(input_file, output_format="mp4"):
    """视频转换 - 命令注入"""
    # BAD: ffmpeg命令注入
    cmd_line = f"ffmpeg -i {input_file} output.{output_format}"
    print(f"[ffmpeg] {cmd_line}")
    subprocess.Popen(cmd_line, shell=True)


# ========== CWE-94: Code Injection ==========

@app.route("/calculate")
def calculate():
    """eval注入"""
    expression = request.args.get("expr", "1+1")
    print(f"[EVAL] 计算: {expression}")

    # BAD: eval() 执行任意Python代码
    # 攻击: /calculate?expr=__import__('os').system('id')
    try:
        result = eval(expression)  # DANGER!
        return f"Result: {result}"
    except Exception as e:
        return f"Error: {e}"


@app.route("/run_script")
def run_script():
    """exec注入"""
    code = request.args.get("code", "print('hello')")
    print(f"[EXEC] 执行代码: {code[:100]}")

    # BAD: exec() with user input
    local_ns = {}
    # 攻击: /run_script?code=import os; os.system('rm -rf /')
    exec(code, {"__builtins__": __builtins__}, local_ns)
    return "Code executed"


@app.route("/compile_expr")
def compile_expr():
    """compile() 注入 - 同样是代码注入"""
    source = request.args.get("source", "x + 1")
    print(f"[COMPILE] {source}")
    # BAD: compile with user input
    code_obj = compile(source, "<user_input>", "eval")
    result = eval(code_obj, {"x": 10})
    return f"Result: {result}"


# ========== CWE-502: Deserialization ==========

@app.route("/load_data")
def load_data():
    """反序列化漏洞"""
    data_b64 = request.args.get("data", "")
    print(f"[DESER] 反序列化数据...")

    # BAD: pickle.loads 可以执行任意代码
    # 攻击: pickle.loads(base64.b64decode(malicious_payload))
    try:
        raw_data = base64.b64decode(data_b64)
        obj = pickle.loads(raw_data)  # DANGER!
        return f"Loaded: {obj}"
    except Exception as e:
        return f"Deserialization error: {e}"


def load_cache_file(filepath):
    """缓存文件加载 - 反序列化"""
    print(f"[CACHE] 读取缓存: {filepath}")
    with open(filepath, "rb") as f:
        # BAD: 从不可信来源反序列化
        data = pickle.load(f)
    return data


# ========== CWE-22: Path Traversal ==========

@app.route("/read_file")
def read_file():
    """路径遍历 (Path Traversal)"""
    filename = request.args.get("file", "welcome.txt")
    print(f"[PATH-TRAV] 读取文件: {filename}")

    # BAD: 直接使用用户输入作为文件路径
    # 攻击: /read_file?file=../../etc/passwd
    # 攻击: /read_file?file=../../.env
    try:
        with open(filename, "r") as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except FileNotFoundError:
        return f"File not found: {filename}"


@app.route("/download")
def download_file():
    """文件下载 - 路径遍历"""
    path = request.args.get("path", "downloads/readme.txt")
    print(f"[DOWNLOAD] 下载路径: {path}")

    # BAD: 未验证路径是否在允许的目录内
    full_path = os.path.join("/var/www/downloads", path)
    # 攻击: /download?path=../../../etc/shadow
    return open(full_path, "rb").read()


def read_config(section_name):
    """配置读取 - 路径遍历"""
    # BAD: 路径拼接
    config_path = "/app/config/" + section_name + ".ini"
    print(f"读取配置: {config_path}")
    with open(config_path, "r") as f:
        return f.read()
    # 攻击: section_name = "../../etc/passwd"


# ========== 更多危险函数 ==========

@app.route("/admin/backup")
def admin_backup():
    """管理员备份 - 多个漏洞组合"""
    db_name = request.args.get("db", "production")
    backup_dir = request.args.get("dir", "/tmp/backups")

    # BAD: 路径遍历 + 命令注入组合
    backup_path = os.path.join(backup_dir, db_name)
    os.system(f"pg_dump {db_name} > {backup_path}.sql")

    return f"Backup started for {db_name} to {backup_path}"


# ========== 安全的对比实现 ==========

@app.route("/read_file_safe")
def read_file_safe():
    """安全的文件读取"""
    filename = request.args.get("file", "welcome.txt")
    allowed_dir = "/var/www/safe_files"

    # 规范化路径
    full_path = os.path.normpath(os.path.join(allowed_dir, filename))

    # GOOD: 验证路径在允许目录内
    if not full_path.startswith(os.path.normpath(allowed_dir)):
        print(f"[SECURITY] 路径遍历攻击阻止: {filename}")
        return "Access Denied", 403

    try:
        with open(full_path, "r") as f:
            return f"<pre>{f.read()}</pre>"
    except FileNotFoundError:
        return "File not found", 404


# --- 被注释掉的危险代码 (留着提醒) ---
# def ultra_dangerous():
#     user_cmd = input("Enter command: ")
#     os.system(user_cmd)  # 永远不会这样写吧...
#     eval(user_cmd)
#     exec(user_cmd)


if __name__ == "__main__":
    print("Command Injection 测试服务!")
    print("包含 CWE-78, CWE-94, CWE-502, CWE-22 漏洞示例")
    # app.run(debug=True, port=5001)
