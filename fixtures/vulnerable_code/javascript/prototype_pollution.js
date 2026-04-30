/**
 * Prototype Pollution 漏洞样本
 * CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
 *
 * 原型污染是一种JavaScript特有的漏洞，攻击者通过修改Object.prototype
 * 来注入恶意属性，影响所有对象的行为。
 *
 * WARNING: 故意包含漏洞，仅用于安全测试！
 */

console.log("[PP-ATTACK] Prototype Pollution test module loaded");


// ========== 1. 不安全的递归合并 (最常见) ==========

function merge_vulnerable(target, source) {
    /**
     * 不安全的深度合并 - 原型污染漏洞
     * 攻击: merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'))
     */
    for (var attr in source) {
        if (typeof target[attr] === "object" && typeof source[attr] === "object") {
            // BAD: 递归合并 __proto__ 属性
            merge_vulnerable(target[attr], source[attr]);
        } else {
            target[attr] = source[attr];
        }
    }
    return target;
}

// Demo of the attack:
// var victim = {};
// merge_vulnerable(victim, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
// console.log({}.polluted);  // "yes" - 所有对象都被污染了!
// TODO: 这个merge函数极度危险


// ========== 2. Object.assign 变体 ==========

function extendVulnerable(target, source) {
    /** 使用Object.assign的不安全扩展 - 同样可以被污染 */
    // BAD: Object.assign 也复制__proto__属性
    return Object.assign(target, source);
    // 攻击: extendVulnerable({}, {"__proto__": {"isAdmin": true}})
}


// ========== 3. 不安全的属性路径设置 ==========

function setByPath(obj, path, value) {
    /**
     * 通过点分隔路径设置属性 - 原型污染
     * 攻击: setByPath({}, "__proto__.isAdmin", true)
     */
    var parts = path.split(".");
    var current = obj;

    print_dbg("setByPath: " + path + " = " + value);

    for (var i = 0; i < parts.length - 1; i++) {
        var key = parts[i];
        // BAD: 没有检查key是否为 __proto__
        if (!(key in current)) {
            current[key] = {};
        }
        current = current[key];
    }

    current[parts[parts.length - 1]] = value;
    return obj;
}


// ========== 4. 从URL参数合并配置 (实际攻击场景) ==========

function loadConfigFromURL() {
    /**
     * 模拟从URL参数加载配置 - 真实攻击场景
     * 攻击URL: /page?config={"__proto__":{"isAdmin":true}}
     */
    var params = new URLSearchParams(window.location.search);
    var configStr = params.get("config") || "{}";
    var userConfig = JSON.parse(configStr);

    var defaultConfig = {
        theme: "light",
        lang: "en",
        debug: false
    };

    // BAD: merge user config without sanitization
    var finalConfig = merge_vulnerable(defaultConfig, userConfig);
    console.log("Merged config:", finalConfig);

    return finalConfig;
}


// ========== 5. Lodash merge 风格漏洞 ==========

// 模拟lodash.merge的漏洞版本
var lodash_like = {
    merge: function(object, source) {
        /** 类似lodash的merge - 历史上存在原型污染 (CVE-2019-10744) */
        function baseMerge(obj, src) {
            for (var key in src) {
                if (typeof src[key] === "object" && src[key] !== null && !Array.isArray(src[key])) {
                    if (!obj[key] || typeof obj[key] !== "object") {
                        obj[key] = {};
                    }
                    baseMerge(obj[key], src[key]);
                } else {
                    obj[key] = src[key];
                }
            }
            return obj;
        }
        // BAD: 没有过滤__proto__, constructor, prototype
        return baseMerge(object, source);
    }
};


// ========== 6. constructor.prototype 攻击 ==========

function cloneVulnerable(obj) {
    /** 不安全的clone - constructor.prototype也能污染 */
    // BAD: constructor.prototype 同样可以污染原型链
    var clone = {};
    for (var key in obj) {
        if (typeof obj[key] === "object" && obj[key] !== null) {
            clone[key] = cloneVulnerable(obj[key]);
        } else {
            clone[key] = obj[key];
        }
    }
    return clone;
    // 攻击: clone({"constructor": {"prototype": {"isAdmin": true}}})
}


// ========== 7. 原型污染的实际影响 ==========

function verifyAdminAccess() {
    /** 演示原型污染如何影响安全检查 */

    // 正常情况
    var normalUser = { name: "user", role: "guest" };

    // 如果Object.prototype被污染了isAdmin = true
    // 那么所有对象都会继承这个属性

    // BAD: 这种检查会被原型污染绕过
    if (normalUser.isAdmin) {
        console.log("[!!!] 权限提升! 用户获得了管理员权限!");
        return true;
    }

    return false;
}


function queryByFilter(userFilter) {
    /** 原型污染影响数据库查询 */
    var baseQuery = { active: true };
    var finalQuery = merge_vulnerable(baseQuery, userFilter);

    // 攻击: 如果原型被污染，查询行为会改变
    console.log("DB Query:", JSON.stringify(finalQuery));
    return finalQuery;
}


// ========== 8. 依赖注入配置合并 (真实场景) ==========

function WebFramework() {
    this.middleware = [];
    this.config = {
        security: {
            cors: true,
            csrf: true,
            rateLimit: 100
        }
    };
}

WebFramework.prototype.loadPlugin = function(plugin) {
    /** 加载插件 - 插件的配置可能被用来污染原型 */
    print_dbg("Loading plugin:", plugin.name);

    // BAD: 从插件合并配置
    if (plugin.config) {
        merge_vulnerable(this.config, plugin.config);
        // 恶意插件可以修改prototype
    }

    if (plugin.middleware) {
        this.middleware.push(plugin.middleware);
    }
};


// ========== 安全的对比实现 ==========

function merge_safe(target, source) {
    /** 安全的深度合并 - 过滤危险属性 */
    var dangerousKeys = ["__proto__", "constructor", "prototype"];

    for (var attr in source) {
        // GOOD: 跳过危险属性
        if (!source.hasOwnProperty(attr)) continue;
        if (dangerousKeys.includes(attr)) {
            console.warn("[SECURITY] Blocked dangerous key:", attr);
            continue;
        }

        if (typeof target[attr] === "object" && target[attr] !== null &&
            typeof source[attr] === "object" && source[attr] !== null &&
            !Array.isArray(source[attr])) {
            merge_safe(target[attr], source[attr]);
        } else {
            target[attr] = source[attr];
        }
    }
    return target;
}


function createSafeObject(source) {
    /** 使用Object.create(null)避免原型污染 */
    // GOOD: 没有原型的对象不会受到污染影响
    var safe = Object.create(null);

    for (var key in source) {
        if (source.hasOwnProperty(key) &&
            key !== "__proto__" &&
            key !== "constructor") {
            safe[key] = source[key];
        }
    }
    return safe;
}


// ========== 更多变体 ==========

// Object.fromEntries变体
function entriesVulnerable(entries) {
    // BAD: Object.fromEntries with __proto__ key
    return Object.fromEntries(entries);
    // 攻击: entries = [["__proto__", {"polluted": true}]]
}

// Spread operator vulnerability
function spreadMerge(target, source) {
    // BAD: spread不会复制__proto__本身但是...
    // 嵌套的prototype属性仍可能被利用
    return { ...target, ...source };
}

// JSON.parse with object construction
function parseJSONConfig(jsonStr) {
    var config = JSON.parse(jsonStr);

    // BAD: 如果config包含__proto__键且后续有merge操作
    if (config.settings) {
        merge_vulnerable(this.defaultSettings, config.settings);
    }

    return config;
}


// ========== 调试函数 ==========

function print_dbg(msg) {
    // Debug print - 可以通过原型污染来劫持!
    console.log("[PP-DEBUG] " + msg);
}

// 已废弃的危险merge实现 - 注释掉但保留了
// function oldDangerousMerge(a, b) {
//     for (var k in b) {
//         a[k] = b[k];  // 太直接了，连递归都不要
//     }
//     return a;
// }


// ========== 可能的利用链演示 ==========

function exploitChainDemo() {
    /**
     * 展示完整的原型污染利用链:
     * 1. merge漏洞引入污染
     * 2. 污染影响安全检查
     * 3. 提权成功
     */

    // Step 1: 通过merge污染原型
    var dummy = {};
    var payload = { "__proto__": { "isAdmin": true, "role": "superuser" } };
    merge_vulnerable(dummy, payload);

    // Step 2: 检查被污染的影响
    console.log("[EXPLOIT] {} has isAdmin?", {}.isAdmin);  // true
    console.log("[EXPLOIT] New object role:", {}.role);     // "superuser"

    // Step 3: 绕过检查
    var guest = { name: "attacker" };
    // isAdmin来自被污染的prototype
    if (guest.isAdmin) {
        console.log("[EXPLOIT] 成功提权! guest.isAdmin =", guest.isAdmin);
    }

    return guest.isAdmin === true;
}


// ========== 导出 ==========
if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        merge_vulnerable: merge_vulnerable,
        merge_safe: merge_safe,
        extendVulnerable: extendVulnerable,
        setByPath: setByPath,
        cloneVulnerable: cloneVulnerable,
        loadConfigFromURL: loadConfigFromURL,
        lodash_like: lodash_like,
        createSafeObject: createSafeObject,
        verifyAdminAccess: verifyAdminAccess,
        exploitChainDemo: exploitChainDemo,
        WebFramework: WebFramework
    };
}

console.log("[PP-READY] All prototype pollution fixtures loaded.");
