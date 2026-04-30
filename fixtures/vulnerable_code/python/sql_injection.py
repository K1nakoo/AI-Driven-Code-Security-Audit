"""
SQL Injection脆弱代码样本 - 用于测试静态扫描Agent
WARNING: 故意包含漏洞，仅用于安全测试！
"""
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# 硬编码数据库连接 - 同时也是硬编码凭据漏洞
DB = sqlite3.connect("test.db")
DB.execute("CREATE TABLE IF NOT EXISTS users (id INT, username TEXT, password TEXT)")
DB.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123')")


@app.route("/login")
def login_vulnerable():
    """故意使用字符串拼接的SQL查询 - SQL注入漏洞"""
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # BAD: 直接拼接SQL - SQL注入风险
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # FIXME: 应该使用参数化查询
    cursor = DB.execute(query)
    user = cursor.fetchone()

    if user:
        return f"Welcome, {username}!"
    return "Login failed"


@app.route("/login_safe")
def login_safe():
    """安全的参数化查询写法"""
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # GOOD: 参数化查询
    cursor = DB.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = cursor.fetchone()

    if user:
        return f"Welcome, {username}!"
    return "Login failed"


@app.route("/user/<user_id>")
def get_user(user_id):
    # BAD: 直接拼接 - SQL注入风险
    print(f"[DEBUG] get_user called with id={user_id}")
    q = "SELECT * FROM users WHERE id=" + user_id
    row = DB.execute(q).fetchone()
    return str(row) if row else "Not found"


# 硬编码的数据库密码
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk-1234567890abcdef1234567890abcdef"  # 硬编码API密钥


def unsafe_concatenation():
    conn = sqlite3.connect("mydb.sqlite")
    user_input = "'; DROP TABLE users; --"
    # BAD
    conn.execute("INSERT INTO logs VALUES ('" + user_input + "')")
    # TODO: 你确定这是安全的吗？
    conn.execute("SELECT * FROM products WHERE name LIKE '%" + user_input + "%'")


def another_vulnerable_query(keyword):
    """更多SQL注入例子 - CWE-89"""
    # BAD: f-string injection
    sql = f"SELECT * FROM items WHERE name = '{keyword}'"
    print(f"执行SQL: {sql}")  # dbg
    return DB.execute(sql).fetchall()


def login_with_dynamic_table(username, password, table):
    """SQL注入 - 表名不可参数化但未做白名单验证"""
    # BAD: 表名直接拼接，无法使用参数化
    query_str = "SELECT * FROM " + table + " WHERE username=? AND password=?"
    print(f"[debug] query_str = {query_str}")
    return DB.execute(query_str, (username, password)).fetchone()


# --- 一些被注释掉的危险代码 ---
# def dangerous_union_injection(user_id):
#     q = "SELECT * FROM users WHERE id=" + user_id + " UNION SELECT * FROM admin"
#     return DB.execute(q).fetchall()


if __name__ == "__main__":
    print("这个文件包含故意性的SQL注入漏洞供扫描测试!")
    app.run(debug=True)  # debug模式也有安全问题
