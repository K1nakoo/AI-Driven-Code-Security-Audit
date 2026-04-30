"""
XSS (Cross-Site Scripting) 脆弱代码样本
包含: Reflected XSS, Stored XSS, DOM-based XSS, Template Injection
WARNING: 仅供安全测试，不要在生产环境运行!!!
"""
from flask import Flask, request, render_template_string, make_response
import html
import json

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key-for-xss-test"  # 硬编码密钥 - 又一个漏洞

# --- 模拟数据库存储评论 ---
_comments_db = []  # 简陋的"数据库"


@app.route("/")
def index():
    """主页 - 包含到各个XSS测试端点的链接"""
    print("[DEBUG] 访问主页面")  # dbg trace
    return """
    <h1>XSS Test Lab</h1>
    <ul>
        <li><a href="/reflect?name=guest">Reflected XSS (reflect)</a></li>
        <li><a href="/search?q=test">Search XSS (search)</a></li>
        <li><a href="/comments">Stored XSS (comments)</a></li>
        <li><a href="/dom">DOM-based XSS Demo (dom)</a></li>
        <li><a href="/template?content=hello">Template Injection (template)</a></li>
        <li><a href="/profile?name=user">Profile Page (profile)</a></li>
    </ul>
    """


# ========== Reflected XSS ==========

@app.route("/reflect")
def reflected_xss():
    """直接回显用户输入 - 反射型XSS (CWE-79)"""
    name = request.args.get("name", "World")
    print(f"[VULN] Reflected XSS with name={name}")
    # BAD: 未转义直接输出用户输入
    return f"<h1>Hello, {name}!</h1>"  # XSS here!


@app.route("/reflect_safe")
def reflected_safe():
    """安全的反射 - 对比版本"""
    name = request.args.get("name", "World")
    # GOOD: html转义
    safe_name = html.escape(name)
    return f"<h1>Hello, {safe_name}!</h1>"


@app.route("/search")
def search_xss():
    """搜索结果页面 - Reflected XSS"""
    query = request.args.get("q", "")
    print(f"搜索查询: {query}")
    # BAD: 直接嵌入搜索结果
    # 攻击示例: /search?q=<script>alert('XSS')</script>
    html_output = "<html><body>"
    html_output += "<h1>搜索结果: " + query + "</h1>"  # XSS
    html_output += "<p>没有找到相关结果</p>"
    html_output += "</body></html>"
    return html_output


# ========== Stored XSS ==========

@app.route("/comments", methods=["GET", "POST"])
def comments():
    """评论系统 - 存储型XSS"""
    if request.method == "POST":
        comment = request.form.get("comment", "")
        author = request.form.get("author", "Anonymous")
        print(f"新评论来自 {author}: {comment[:50]}...")

        # BAD: 不转义直接存储
        _comments_db.append({
            "author": author,
            "comment": comment,  # 存储型XSS - 未转义
            "id": len(_comments_db) + 1
        })
        # TODO: 应该在这里添加html.escape()

    # 渲染评论列表 - BAD: 直接输出存储的内容
    html_out = "<h1>评论区</h1>"
    html_out += '<form method="POST"><input name="author" placeholder="昵称"><br>'
    html_out += '<textarea name="comment" placeholder="评论..."></textarea><br>'
    html_out += '<button type="submit">提交</button></form><hr>'

    for c in _comments_db:
        # stored XSS when rendering
        html_out += f"<div><strong>{c['author']}</strong>: {c['comment']}</div><br>"

    return html_out


# ========== DOM-based XSS ==========

@app.route("/dom")
def dom_xss():
    """DOM-based XSS 演示页面"""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>DOM XSS Demo</title></head>
    <body>
        <h1>DOM-based XSS Demo</h1>
        <div id="output"></div>
        <script>
            // BAD: DOM-based XSS via location.hash
            var hash = location.hash.substring(1);
            document.getElementById("output").innerHTML = hash;
            // 攻击: /dom#<img src=x onerror=alert(1)>

            // Another DOM XSS sink
            var params = new URLSearchParams(location.search);
            var name = params.get('name') || 'Guest';
            document.write('<p>Welcome, ' + name + '</p>');
            // 攻击: /dom?name=<script>alert(document.cookie)</script>
        </script>
    </body>
    </html>
    """


# ========== Template Injection (SSTI) ==========

@app.route("/template")
def template_injection():
    """服务端模板注入 (SSTI) - CWE-1336"""
    content = request.args.get("content", "Hello World")
    print(f"[SSTI] 渲染模板 content={content}")

    # BAD: 使用用户输入作为模板 - SSTI漏洞!
    # 攻击: /template?content={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
    template = "<html><body><h1>" + content + "</h1></body></html>"
    return render_template_string(template)

    # FIXME: 应该使用render_template("template.html", content=content)
    # 而不是render_template_string


@app.route("/template_safe")
def template_safe():
    """安全的模板渲染 - 对比"""
    content = request.args.get("content", "Hello World")
    # GOOD: 将content作为变量传递，不作为模板字符串
    return render_template_string(
        "<html><body><h1>{{ content }}</h1></body></html>",
        content=content
    )


# ========== 更多XSS变体 ==========

@app.route("/profile")
def profile_xss():
    """用户资料页面 - 多种XSS sink"""
    name = request.args.get("name", "User")
    bio = request.args.get("bio", "")

    # BAD: 多处XSS
    header_html = f"<title>{name}'s Profile</title>"

    # BAD: href属性中的javascript:注入
    website = request.args.get("website", "#")
    link_html = f'<a href="{website}">My Website</a>'  # javascript:alert(1)

    # BAD: onclick属性注入
    action = request.args.get("action", "alert('click')")
    button_html = f'<button onclick="{action}">Click Me</button>'

    # BAD: style属性(CSS注入)
    color = request.args.get("color", "black")
    style_html = f'<div style="color: {color}">Colored Text</div>'

    # BAD: meta refresh 重定向XSS
    redirect = request.args.get("redirect", "/")
    meta_html = f'<meta http-equiv="refresh" content="0;url={redirect}">'  # header injection

    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>{meta_html}{header_html}</head>
    <body>
        <h1>Welcome, {name}!</h1>
        <p>Bio: {bio}</p>
        {link_html}
        {button_html}
        {style_html}
        <script>
            // BAD: inline script injection
            var userName = "{name}";  // XSS via JS string breaking
            console.log("Profile of " + userName);
        </script>
    </body>
    </html>
    """
    print(f"[dbg] profile page rendered for {name}")
    return full_html


@app.route("/api/echo")
def api_echo():
    """JSON API - 反射XSS在JSON上下文中"""
    data = request.args.get("data", "")
    # BAD: JSON反射 - 某些情况下可导致XSS
    # 攻击: /api/echo?data=</script><script>alert(1)</script>
    print(f"API echo: data={data}")
    resp = make_response(json.dumps({"echo": data}))
    resp.headers["Content-Type"] = "application/json"
    return resp


@app.after_request
def add_security_headers(response):
    """缺少安全头的示例"""
    # 故意不设置 X-XSS-Protection, Content-Security-Policy
    # 这样XSS就更容易利用了
    response.headers["X-Content-Type-Options"] = "nosniff"
    # TODO: 应该添加CSP头，但暂时没有
    return response


if __name__ == "__main__":
    print("XSS测试服务器启动 - 包含多个故意漏洞!")
    print("请勿在生产环境使用此代码!!!")
    app.run(host="0.0.0.0", port=5000, debug=True)
