/**
 * DOM-based XSS 漏洞样本 - JavaScript
 * 包含各种DOM XSS sink模式
 * WARNING: 仅用于安全测试! 不要在生产环境使用!
 */

// ========== innerHTML XSS (最经典) ==========

function displayUserMessage(userInput) {
    // BAD: innerHTML直接插入用户输入
    console.log("[DEBUG] displaying user message...");
    document.getElementById("msg-box").innerHTML = userInput;
    // 攻击: userInput = '<img src=x onerror=alert("XSS")>'
}

// 被注释掉的危险版本
// function oldDisplayMessage(msg) {
//     // 这个更危险 - 直接eval
//     document.getElementById("output").innerHTML = eval(msg);
// }

function displaySafe(msg) {
    // GOOD: textContent不会解析HTML
    document.getElementById("msg-box").textContent = msg;
}


// ========== document.write XSS ==========

function renderWelcome() {
    // BAD: document.write with location.hash
    var hashValue = location.hash.substring(1);
    print_debug("hash = " + hashValue);
    document.write("<h1>Welcome " + hashValue + "</h1>");
    // 攻击: /page#<script>stealCookies()</script>
}

function loadExternalContent(url) {
    // BAD: 从URL参数读取后直接写入
    var params = new URLSearchParams(location.search);
    var content = params.get("content") || "";
    document.write(content);  // XSS!
}


// ========== eval via URL params ==========

function runCallback() {
    // BAD: eval with URL parameter
    var urlParams = new URLSearchParams(window.location.search);
    var callbackName = urlParams.get("callback");
    console.log("Running callback: " + callbackName);

    // DANGER: eval执行任意JS
    eval(callbackName + "()");
    // 攻击: ?callback=alert(document.cookie)
}

// Another eval pattern
function processData() {
    var jsonStr = location.hash.slice(1);
    print_debug("processing json: " + jsonStr);
    // BAD: eval for JSON parsing (应该用JSON.parse)
    var data = eval("(" + jsonStr + ")");
    return data;
}


// ========== setTimeout / setInterval string args ==========

function delayedExecution() {
    var userCode = new URLSearchParams(location.search).get("code");
    // BAD: setTimeout with string argument executes eval
    setTimeout("console.log('User: " + userCode + "')", 1000);
    // 攻击: ?code=');alert(1);('
}

function periodicCheck() {
    var checkFn = location.hash.substring(1) || "checkStatus()";
    // BAD: setInterval with string arg
    setInterval(checkFn, 5000);
}


// ========== jQuery XSS Sinks ==========

// 假设已经加载了jQuery
function jqueryXSS() {
    // BAD: jQuery html() with untrusted data
    var userName = $("#user-input").val();
    $("#greeting").html("Hello, " + userName);  // XSS!

    // Also BAD: append/prepend with HTML strings
    var bio = new URLSearchParams(location.search).get("bio");
    $(".profile").append("<p>" + bio + "</p>");  // XSS!

    // Also BAD: after/before
    var comment = $("#comment-field").val();
    $(".comments").after("<div>" + comment + "</div>");  // XSS!
}


// ========== React dangerouslySetInnerHTML ==========

// Simulating React component
var UserProfile = {
    render: function() {
        var bio = new URLSearchParams(location.search).get("bio") || "No bio";
        // BAD: dangerouslySetInnerHTML with user input
        return {
            __html: bio  // React会警告，但仍然危险
        };
    }
};

// Another React pattern
function ProfileBadge(props) {
    // BAD: 动态创建包含用户输入的React元素
    var userBadge = props.badge || "";
    return {
        dangerouslySetInnerHTML: {
            __html: "<span class='badge'>" + userBadge + "</span>"
        }
    };
}


// ========== location-based XSS ==========

function redirectUser() {
    // BAD: location redirect with user input
    var targetUrl = new URLSearchParams(location.search).get("redirect");
    console.log("redirecting to: " + targetUrl);
    // 攻击: ?redirect=javascript:alert(document.cookie)
    location.href = targetUrl;
}

function loadIFrame() {
    // BAD: iframe src from URL parameter
    var src = location.hash.substring(1);
    var iframe = document.createElement("iframe");
    iframe.src = src;  // javascript: URL可以执行代码
    document.body.appendChild(iframe);
}


// ========== postMessage XSS ==========

window.addEventListener("message", function(event) {
    // BAD: postMessage without origin validation
    console.log("received message:", event.data);

    // DANGER: 直接使用来自任何源的消息
    document.getElementById("content").innerHTML = event.data.html;

    // 攻击: 攻击者页面发送:
    // iframe.contentWindow.postMessage(
    //   {html: '<img src=x onerror=alert(1)>'}, '*'
    // );
});


// ========== DOM clobbering susceptible code ==========

function checkConfig() {
    // BAD: 使用全局DOM属性可能被DOM clobbering攻击
    if (window.config && window.config.debug) {
        var debugScript = document.getElementById("debug-script");
        if (debugScript) {
            eval(debugScript.textContent);  // 双重危险!
        }
    }
}


// ========== Misc sinks ==========

function cloneNodeXSS(templateId) {
    // BAD: 从URL获取template ID
    var id = templateId || location.hash.substring(1);
    var template = document.getElementById(id);
    if (template) {
        var clone = template.content.cloneNode(true);
        document.body.appendChild(clone);
    }
}

// SVG/ MathML XSS vector
function createSVG(userContent) {
    // BAD: SVG可以包含可执行JS
    var svg = '<svg xmlns="http://www.w3.org/2000/svg">';
    svg += '<script>alert("' + userContent + '")</script>';
    svg += "</svg>";
    document.getElementById("svg-container").innerHTML = svg;
}


// ========== 工具函数 ==========

// print_debug - 调试用
function print_debug(msg) {
    if (typeof DEBUG !== "undefined" && DEBUG) {
        console.log("[XSS-DEBUG] " + msg);
    }
}

// TODO: 需要添加DOMPurify或者CSP来修复这些XSS
// FIXME: 上面所有innerHTML/doc.write都需要清理


// ========== 导出 (for testing) ==========
if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        displayUserMessage: displayUserMessage,
        displaySafe: displaySafe,
        renderWelcome: renderWelcome,
        runCallback: runCallback,
        processData: processData,
        jqueryXSS: jqueryXSS,
        delayedExecution: delayedExecution,
        redirectUser: redirectUser,
        createSVG: createSVG
    };
}
