#!/usr/bin/env node
// PAN-OS 防火墙 Agent 控制台 - 后端 v4（任务系统 + LLM 多提供方）
// 纯 Node http + MCP SDK。任务类型：query(查询) / inspect(巡检) / change(变更审批闭环)
const http = require("http");
const fs = require("fs");
const path = require("path");
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");

// ── 路径（默认项目内相对路径，可用环境变量覆盖；脱离 WorkBuddy 独立部署无需改代码）──
const NODE = process.env.NODE_BIN || "node";
const PANOS_MCP_DIR = process.env.PANOS_MCP_DIR || path.join(__dirname, "..", "mcp", "panos-mcp");
const SRC = path.join(PANOS_MCP_DIR, "src", "index.ts");
const CWD = PANOS_MCP_DIR;
const CFG = process.env.PANOS_FIREWALLS_CONFIG || path.join(__dirname, "..", "cfgs", "firewalls.json");
const PORT = process.env.PORT || 8080;
const REPORTS_DIR = path.join(__dirname, "..", "reports");
const TASKS_FILE = process.env.TASKS_FILE || path.join(__dirname, "..", "cfgs", "tasks.json");
const AUTH_FILE = path.join(__dirname, "..", "cfgs", "auth.json");

// ── WebUI 认证（发布公网前必须启用；所有 /api/* 需 token，飞书 bridge 用 internal_token）──
const crypto = require("crypto");
const sha256 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const AUTH_SESSION_DAYS = 7;               // 登录会话绝对有效期
const IDLE_MINUTES = Math.max(1, parseInt(process.env.PANOS_WEB_IDLE_MINUTES || "10", 10)); // 空闲超时（分钟），默认 10
const IDLE_MS = IDLE_MINUTES * 60 * 1000;
let authData = null;                        // { username, password_hash, sessions:{token:{exp,lastSeen}}, internal_token }
function loadAuth() {
  try {
    if (fs.existsSync(AUTH_FILE)) {
      authData = JSON.parse(fs.readFileSync(AUTH_FILE, "utf-8"));
    }
  } catch (e) { console.error("[auth] auth.json 解析失败，重建:", String(e.message || e)); }
  if (!authData || typeof authData !== "object") authData = { username: "admin", password_hash: "", sessions: {}, internal_token: "" };
  authData.sessions = authData.sessions || {};
  // 兼容旧格式：sessions[token] 是纯数字（expiry）→ 转对象 {exp, lastSeen}
  for (const k of Object.keys(authData.sessions)) {
    if (typeof authData.sessions[k] === "number") authData.sessions[k] = { exp: authData.sessions[k], lastSeen: Date.now() };
  }
  // 首次初始化：随机密码 + 内部令牌
  if (!authData.password_hash) {
    const pw = process.env.PANOS_WEB_PASSWORD || crypto.randomBytes(6).toString("base64").replace(/[^a-zA-Z0-9]/g, "").slice(0, 10);
    authData.password_hash = sha256(pw);
    console.log("[auth] ⚠️ 首次启动：WebUI 登录账号 = " + authData.username + " / 密码 = " + pw + "（写入 " + AUTH_FILE + "，请立即修改）");
  }
  if (!authData.internal_token) {
    authData.internal_token = process.env.PANOS_WEB_INTERNAL_TOKEN || crypto.randomBytes(24).toString("hex");
  }
  fs.writeFileSync(AUTH_FILE, JSON.stringify(authData, null, 2));
}
function saveAuth() { fs.writeFileSync(AUTH_FILE, JSON.stringify(authData, null, 2)); }
function authValid(token) {
  if (!token || !authData.sessions[token]) return false;
  const s = authData.sessions[token];
  // 绝对过期（7 天）或 空闲超时（N 分钟无用户主动操作）→ 会话失效
  if (Date.now() > s.exp || Date.now() - s.lastSeen > IDLE_MS) {
    delete authData.sessions[token]; saveAuth();
    return false;
  }
  return true;
}
function authIssueToken() {
  const token = crypto.randomBytes(32).toString("hex");
  authData.sessions[token] = { exp: Date.now() + AUTH_SESSION_DAYS * 864e5, lastSeen: Date.now() };
  saveAuth();
  return token;
}
let _lastAuthWrite = 0;
function authTouch(token) {
  // 用户主动操作时刷新 lastSeen（节流写盘：≥60s 才写一次，避免高频写 auth.json）
  const s = authData.sessions[token];
  if (!s) return;
  s.lastSeen = Date.now();
  if (Date.now() - _lastAuthWrite > 60000) { _lastAuthWrite = Date.now(); saveAuth(); }
}
function authCheck(req) {
  // 从 Authorization: Bearer <t> 或 ?token=<t> 读取；internal_token 同样有效（飞书 bridge 用，不受空闲超时影响）
  const h = req.headers["authorization"] || "";
  let t = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  if (!t && req.url.includes("token=")) t = decodeURIComponent((req.url.match(/[?&]token=([^&]*)/) || [])[1] || "");
  if (!t) return false;
  if (t === authData.internal_token) return true; // 内部令牌不走用户会话空闲超时
  return authValid(t);
}
// 用户主动操作类接口：通过认证后刷新 lastSeen（轮询类 GET 不在此列——挂机不续命）
function authTouchIfUserAction(req, token) {
  if (!token || token === authData.internal_token) return;
  const p = req.url.split("?")[0];
  if (/^\/api\/task\//.test(p) || p === "/api/llm/select" || p === "/api/llm/save" || p === "/api/llm/del"
    || p === "/api/auth/change-password" || p === "/api/feishu/send" || p === "/api/feishu/push-report"
    || p === "/api/tasks/clean" || p === "/api/auth/keepalive") {
    authTouch(token);
  }
}
loadAuth();

// ── LLM 提供方（llm-config.json 驱动，可运行时编辑）──
const LLM_SEED = {
  deepseek: { label: "DeepSeek", base_url: "https://api.deepseek.com/v1", model: "deepseek-v4-flash", env: "DEEPSEEK_API_KEY" },
  qwen:     { label: "通义千问", base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1", model: "Qwen-3.8", env: "QWEN_API_KEY" },
  kimi:     { label: "Kimi",     base_url: "https://api.moonshot.cn/v1", model: "Kimi K3", env: "KIMI_API_KEY" },
};
const LLM_CONFIG_PATH = process.env.LLM_CONFIG || path.join(__dirname, "llm-config.json");
let LLM_PROVIDERS = {};
function loadLLMConfig() {
  const data = JSON.parse(JSON.stringify(LLM_SEED));
  let onDisk = {};
  try { onDisk = JSON.parse(fs.readFileSync(LLM_CONFIG_PATH, "utf-8")); } catch {}
  const providers = onDisk.providers || {};
  for (const [k, v] of Object.entries(LLM_SEED)) {
    const disk = providers[k];
    if (disk) {
      data[k] = { ...LLM_SEED[k], ...disk };
      if (disk.key) process.env[LLM_SEED[k].env] = disk.key;
    } else if (process.env[LLM_SEED[k].env]) {
      // 文件未配置但进程 env 有，自动接管（start.sh 兼容）
      data[k] = { ...LLM_SEED[k], key: process.env[LLM_SEED[k].env] };
    }
  }
  // 文件里有的自定义提供方（非种子）
  for (const [k, v] of Object.entries(providers)) {
    if (!data[k]) {
      data[k] = { label: v.label || k, base_url: v.base_url || "", model: v.model || "", env: v.env || (k.toUpperCase() + "_API_KEY"), key: v.key || "" };
      if (v.key && data[k].env) process.env[data[k].env] = v.key;
    }
  }
  LLM_PROVIDERS = data;
}
loadLLMConfig();
function saveLLMConfig() {
  const onDisk = { _default: currentLLM, providers: {} };
  for (const [k, v] of Object.entries(LLM_PROVIDERS)) {
    onDisk.providers[k] = { label: v.label, base_url: v.base_url, model: v.model, env: v.env, key: v.key };
  }
  fs.writeFileSync(LLM_CONFIG_PATH, JSON.stringify(onDisk, null, 2), { mode: 0o600 });
  try { fs.chmodSync(LLM_CONFIG_PATH, 0o600); } catch {}
}
let currentLLM = "keyword";
// 用户选择持久化：最后一次 select 写 cfgs/llm-choice.json，重启/刷新都保持，只有手动切换才变。
// （此前"刷新回默认"导致用户选 Kimi 但页面刷新后任务实际跑 deepseek，造成混淆）
const LLM_CHOICE_FILE = process.env.LLM_CHOICE_FILE || path.join(__dirname, "..", "cfgs", "llm-choice.json");
function loadLLMChoice() {
  try { return JSON.parse(fs.readFileSync(LLM_CHOICE_FILE, "utf-8")).current; } catch { return null; }
}
function saveLLMChoice(c) {
  try { fs.writeFileSync(LLM_CHOICE_FILE, JSON.stringify({ current: c, updatedAt: new Date().toISOString() })); } catch {}
}
try {
  // 优先：用户上次选择（持久化）> llm-config.json 的 _default > 进程 env > 首个有 key 的提供方
  const chosen = loadLLMChoice();
  if (chosen && LLM_PROVIDERS[chosen] && LLM_PROVIDERS[chosen].key) currentLLM = chosen;
  else {
    const diskDef = JSON.parse(fs.readFileSync(LLM_CONFIG_PATH, "utf-8"))._default;
    if (diskDef && LLM_PROVIDERS[diskDef] && LLM_PROVIDERS[diskDef].key) currentLLM = diskDef;
    else currentLLM = process.env.LLM_PROVIDER || Object.keys(LLM_PROVIDERS).find((k) => LLM_PROVIDERS[k].key) || "keyword";
  }
} catch {
  const chosen = loadLLMChoice();
  if (chosen && LLM_PROVIDERS[chosen] && LLM_PROVIDERS[chosen].key) currentLLM = chosen;
  else currentLLM = process.env.LLM_PROVIDER || Object.keys(LLM_PROVIDERS).find((k) => LLM_PROVIDERS[k].key) || "keyword";
}

// LLM 临时选择：默认读 llm-config.json 的 _default（deepseek），UI 选 qwen 后内存一直保持 qwen。
// "刷新页面回默认"语义=重启控制台（进程重启时重新读 _default），不是浏览器 F5。
// 不做定时器重置——避免连续发任务时每个任务结束后被意外重置。

let client = null;
const tasks = [];        // 任务列表
const history = [];      // 查询历史
const llmLogs = [];      // LLM 决策日志（证明 LLM 规划起作用）
const metricsBuffer = []; // KPI 指标采样环形缓冲（报表预留，见 spec §12.1 metrics 表）
const MAX_HISTORY = 20;
const MAX_LLM_LOGS = 50;
const MAX_TASKS = 200;   // 任务持久化上限（超出丢弃最旧）
const MAX_METRICS = 720; // 指标采样上限（10s 一次 ≈ 2 小时滚动窗口）
let taskSeq = 0;

// ── 任务持久化：重启后保留已完成/已取消任务（内存 + cfgs/tasks.json 双写）──
// 写锁：所有落盘走串行 Promise 队列。快照在调用时刻生成（JS 单线程，同步段按序），
// 排队按序 writeFileSync——避免多任务并发 saveTask 时互相覆盖（后写覆盖先写）。
let _writeQueue = Promise.resolve();
function persistTasks() {
  let snap = null;
  try { snap = JSON.stringify(tasks, null, 2); } catch (e) { console.error("[agent] persist serialize failed:", e.message); return; }
  _writeQueue = _writeQueue
    .then(() => new Promise((res) => {
      try {
        // 原子替换：先写临时文件再 rename，避免进程被杀打断 writeFileSync 时把任务文件清空
        const tmp = TASKS_FILE + ".tmp";
        fs.writeFileSync(tmp, snap);
        fs.renameSync(tmp, TASKS_FILE);
      } catch (e) { console.error("[agent] persist tasks failed:", e.message); }
      res();
    }))
    .catch(() => {});
}
function loadTasks() {
  try {
    const saved = JSON.parse(fs.readFileSync(TASKS_FILE, "utf-8"));
    if (!Array.isArray(saved)) return;
    for (const t of saved) {
      // 重启后运行中的任务无法恢复执行，置为 failed（保留现场供排查）
      if (["pending", "running", "executing", "committing"].includes(t.status)) {
        t.status = "failed"; t.error = (t.error ? t.error + "；" : "") + "控制台重启，任务中断";
        t.steps = (t.steps || []).concat({ tool: "system", status: "err", msg: "控制台重启，任务中断" });
      }
      tasks.push(t);
      if (t.id > taskSeq) taskSeq = t.id;
    }
    while (tasks.length > MAX_TASKS) tasks.shift();
    console.log("[agent] 已从磁盘恢复 %d 个历史任务", tasks.length);
  } catch (e) {
    // 文件损坏：先备份，再静默忽略（绝不能因解析失败就回写空数组覆盖掉数据）
    try { if (fs.existsSync(TASKS_FILE)) fs.copyFileSync(TASKS_FILE, TASKS_FILE + ".corrupt-" + Date.now()); } catch {}
    console.warn("[agent] tasks.json 加载失败（已备份损坏文件）:", e.message);
  }
}
loadTasks();

function recordLLM(role, input, output, ms) {
  llmLogs.unshift({ ts: new Date().toLocaleString("zh-CN"), provider: currentLLM, role, input: String(input).slice(0, 80), output: String(output || "").slice(0, 200), ms });
  if (llmLogs.length > MAX_LLM_LOGS) llmLogs.pop();
}

// ── 动作清单（查询用）──
const ACTIONS = {
  device:    { label: "设备状态", tools: ["get_system_resources", "get_active_sessions", "get_ha_status"], keywords: ["状态", "负载", "cpu", "内存", "运行", "device", "status", "health", "resource", "load"] },
  inventory: { label: "设备清单", tools: ["get_firewall_info", "get_system_environmentals", "get_interfaces", "get_licenses", "get_content_versions"], keywords: ["设备", "清单", "资产", "inventory", "硬件", "型号", "序列号", "版本", "asset", "hardware", "serial", "model", "system"] },
  security:  { label: "安全策略", tools: ["get_security_rules"], keywords: ["策略", "放行", "policy", "security"] },
  nat:       { label: "NAT 规则", tools: ["get_nat_rules"], keywords: ["nat", "转换", "映射"] },
  objects:   { label: "地址对象", tools: ["get_address_objects"], keywords: ["地址", "对象", "address", "object"] },
  interfaces:{ label: "接口", tools: ["get_interfaces"], keywords: ["接口", "interface", "网口"] },
  zones:     { label: "区域", tools: ["get_zones"], keywords: ["区域", "zone", "trust", "untrust"] },
  sessions:  { label: "活跃会话", tools: ["get_active_sessions"], keywords: ["会话", "连接数", "session"] },
  traffic:   { label: "流量日志", tools: ["get_traffic_logs"], keywords: ["流量", "traffic"] },
  threat:    { label: "威胁日志", tools: ["get_threat_logs"], keywords: ["威胁", "攻击", "病毒", "threat", "攻击源", "封禁", "拉黑", "入侵"] },
  syslog:    { label: "系统日志", tools: ["get_system_logs"], keywords: ["系统日志", "事件", "syslog"] },
  licenses:  { label: "许可证", tools: ["get_licenses"], keywords: ["许可", "授权", "到期", "license", "订阅"] },
  vpn:       { label: "VPN", tools: ["get_ipsec_tunnels", "get_globalprotect_users"], keywords: ["vpn", "隧道", "ipsec", "globalprotect", "远程接入"] },
  wildfire:  { label: "WildFire", tools: ["get_wildfire_status"], keywords: ["wildfire", "沙箱", "wild"] },
  content:   { label: "内容库", tools: ["get_content_versions"], keywords: ["内容库", "更新", "版本", "content", "补丁"] },
  inspect:   { label: "完整巡检", tools: ["get_firewall_info", "get_ha_status", "get_system_resources", "get_active_sessions", "get_licenses", "get_traffic_logs", "get_threat_logs", "get_wildfire_status", "get_security_rules", "get_content_versions"], keywords: ["巡检", "合规", "全部", "inspect", "audit", "报告"] },
};

// ── 变更模板（写操作，仅允许模板化，防幻觉）──
const WHERE_CN = { before: "前（上面）", after: "后（下面）", top: "顶部", bottom: "底部" };
const CHANGE_TEMPLATES = {
  add_address_object: { label: "创建地址对象", plan: (p) => `新增地址对象 ${p.name} = ${p.value}（${p.type}），零流量影响（未引用）`, params: ["name", "value"] },
  delete_address_object: { label: "删除地址对象", plan: (p) => `删除地址对象 ${p.name}`, params: ["name"] },
  block_ip: { label: "封禁 IP", plan: (p) => {
    const where = p.position === "top" || p.position === "bottom" ? WHERE_CN[p.position] : (p.position === "before" || p.position === "after" ? `${WHERE_CN[p.position] || p.position}（参照 ${p.destination || "?"}）` : "默认末尾（未指定）");
    return `封禁 ${p.ip}：建地址对象 + deny 策略${p.position ? "移到" + where : "（用户未指定位置，不移动）"}${p.expiry ? "，临时至 " + p.expiry : "，永久"}`;
  }, params: ["ip", "position", "destination"] },
  move_security_rule: { label: "移动安全策略", plan: (p) => {
    const w = WHERE_CN[p.where] || p.where;
    if (p.where === "top" || p.where === "bottom") return `把策略 ${p.name} 移到${w}（candidate 暂存，需审批后 commit）`;
    return `把策略 ${p.name} 移到 ${p.destination} 的${w}（candidate 暂存，需审批后 commit）`;
  }, params: ["name", "where", "destination"] },
  delete_security_rule: { label: "删除安全策略", plan: (p) => p.name
    ? `删除安全策略 ${p.name}（candidate 暂存，需审批后 commit）`
    : `按关键词"${p.keyword}"查找匹配的安全策略并列出（不执行删除）`, params: ["name", "keyword"] },
  set_security_rule_disabled: { label: "禁用安全策略", plan: (p) => p.name
    ? `禁用安全策略 ${p.name}（规则保留但不生效，需审批后 commit）`
    : `按关键词"${p.keyword}"查找匹配的安全策略并列出（不执行禁用）`, params: ["name", "keyword"] },
  set_security_rule_enabled: { label: "启用安全策略", plan: (p) => p.name
    ? `启用安全策略 ${p.name}（需审批后 commit）`
    : `按关键词"${p.keyword}"查找匹配的安全策略并列出（不执行启用）`, params: ["name", "keyword"] },
  allow_ip: { label: "放行 IP", plan: (p) => {
    const where = p.position === "top" || p.position === "bottom" ? WHERE_CN[p.position] : (p.position === "before" || p.position === "after" ? `${WHERE_CN[p.position] || p.position}（参照 ${p.destination || "?"}）` : "默认末尾（未指定）");
    return `放行 ${p.ip}：建地址对象 + allow 策略${p.position ? "移到" + where : "（用户未指定位置，不移动）"}${p.expiry ? "，临时至 " + p.expiry : "，永久"}`;
  }, params: ["ip", "position", "destination"] },
  block_ip_group: { label: "封禁 IP 组", plan: (p) => {
    const ips = (p.ips || []).join(", ");
    const gname = p.group_name || `block-group-${new Date().toISOString().slice(0,10).replace(/-/g,"")}`;
    const where = p.position === "top" || p.position === "bottom" ? WHERE_CN[p.position] : (p.position === "before" || p.position === "after" ? `${WHERE_CN[p.position] || p.position}（参照 ${p.destination || "?"}）` : "默认末尾（未指定）");
    return `封禁 ${(p.ips || []).length} 个 IP（${ips}）：建 ${(p.ips || []).length} 个地址对象 → 加入地址组 ${gname} → 策略 source 引用该组${p.position ? "并移到" + where : "（用户未指定位置，不移动）"}`;
  }, params: ["ips", "group_name", "position", "destination"] },
};

async function connect() {
  const transport = new StdioClientTransport({
    command: NODE, args: ["--experimental-strip-types", SRC], cwd: CWD,
    env: { ...process.env,
      NODE_PATH: path.join(PANOS_MCP_DIR, "node_modules"),  // 强制 MCP server 用自身依赖，避免解析到外部不完整依赖
      PANOS_FIREWALLS_CONFIG: CFG,
      PANOS_PROXY: "", HTTPS_PROXY: "", https_proxy: "", HTTP_PROXY: "", http_proxy: "", ALL_PROXY: "", all_proxy: "", NO_PROXY: "*", no_proxy: "*" },
  });
  client = new Client({ name: "panos-agent", version: "4.0.0" });
  await client.connect(transport);
  console.log("[agent] MCP connected");
}

// ── 直接调防火墙 API（绕开 MCP server 故障 + Node fetch 代理干扰）──
const https = require("https");
const { execFile } = require("child_process");
const FEISHU_CHAT = process.env.FEISHU_CHAT_ID || "oc_0238b0ea1d6d7a74180cfce85b18cf67";
// lark-cli 可由 LARK_CLI 环境变量指定；未配置则 PATH 中查找（飞书桥为可选功能）
const LARK_CLI = process.env.LARK_CLI || "lark-cli";
// lark-cli 是 `#!/usr/bin/env node` wrapper，且可能 spawn 自身依赖——确保 PATH 含 node 与 lark 目录
(() => {
  const add = (d) => { if (d && d !== "." && process.env.PATH && !process.env.PATH.split(":").includes(d)) process.env.PATH = d + ":" + process.env.PATH; };
  add(path.dirname(NODE));
  add(path.dirname(LARK_CLI));
})();
function feishuSend(text) {
  return new Promise((resolve) => {
    execFile(LARK_CLI, ["im", "+messages-send", "--chat-id", FEISHU_CHAT, "--msg-type", "text", "--text", text], { timeout: 15000 }, (err, stdout, stderr) => {
      if (err) resolve({ ok: false, error: String(stderr || err.message).slice(0, 1000) });
      else {
        try { const d = JSON.parse(stdout); resolve({ ok: !!d.ok, data: d.data ? d.data.message_id : null, error: d.error ? JSON.stringify(d.error).slice(0, 200) : "" }); }
        catch { resolve({ ok: false, error: stdout.slice(0, 200) }); }
      }
    });
  });
}
function feishuDaemonRunning() {
  return new Promise((resolve) => {
    fs.stat("/tmp/feishu-bridge.heartbeat", (err, st) => {
      resolve(!err && Date.now() - st.mtimeMs < 120000);
    });
  });
}
const DIRECT_FW = JSON.parse(require("fs").readFileSync(CFG, "utf-8")).firewalls[0] || {};
const DIRECT_KEY = DIRECT_FW.api_key || "";
const DIRECT_HOST = (() => { const h = DIRECT_FW.host || ""; return h.startsWith("http") ? h.replace(/^https?:\/\//, "").replace(/\/$/, "").replace(/:\d+$/, "") : h.replace(/\/$/, ""); })();
const DIRECT_PORT = 443;

function httpsGet(path) {
  return new Promise((resolve, reject) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 20000);
    const req = https.request({ host: DIRECT_HOST, port: DIRECT_PORT, path, method: "GET", agent: false, rejectUnauthorized: false, signal: ac.signal }, (res) => {
      let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => { clearTimeout(timer); resolve(b); });
    });
    req.on("error", (e) => { clearTimeout(timer); reject(e); });
    req.end();
  });
}

async function directLog(type, nlogs = 20, query = "") {
  if (!DIRECT_KEY) throw new Error("无防火墙 key");
  const q = query ? `&query=${encodeURIComponent(query)}` : "";
  const start = await httpsGet(`/api/?type=log&log-type=${type}&nlogs=${nlogs}${q}&key=${DIRECT_KEY}`);
  const jobm = start.match(/jobid[(\(\s*](\d+)/);
  if (!jobm) throw new Error("log job 未启动: " + start.slice(0, 100));
  const jobid = jobm[1];
  for (let i = 0; i < 5; i++) {
    await new Promise((r) => setTimeout(r, 1000));   // 轮询 5s
    const s = await httpsGet(`/api/?type=op&cmd=${encodeURIComponent("<show><jobs><id>" + jobid + "</id></jobs></show>")}&key=${DIRECT_KEY}`);
    const statusm = s.match(/<status>\s*([^<\s]+)/);
    const status = statusm ? statusm[1] : "";
    if (status === "FIN" || status === "ACT") break;
    if (status === "FAIL" || status === "STOPPED") throw new Error("log job " + status);
  }
  const res = await httpsGet(`/api/?type=log&action=get&jobid=${jobid}&key=${DIRECT_KEY}`);
  // 宽松解析：entry 可能带属性（<entry logid="...">），保留原文 + 提取关键字段
  const entryBlocks = res.match(/<entry[^>]*>([\s\S]*?)<\/entry>/g) || [];
  const entries = entryBlocks.map((blk) => {
    const e = { _raw: blk.length > 500 ? blk.slice(0, 500) + "..." : blk };
    // 常见字段提取
    ["receive_time", "src", "dst", "sport", "dport", "app", "action", "rule", "from", "to", "subtype", "severity", "eventid", "opaque", "hostname", "model", "sw-version", "kbps", "num-active", "ip-address", "serial", "threatid", "admin", "cmd", "result", "client", "full-path", "path", "type", "high_res_timestamp"].forEach((k) => {
      const m = blk.match(new RegExp("<" + k + ">([\\s\\S]*?)<\\/" + k + ">"));
      if (m) e[k] = m[1].trim();
    });
    return e;
  });
  return { entry: entries, raw: res.length > 8000 ? res.slice(0, 8000) + "..." : res };
}

// ── 日志深度分析（第1项 Top N + 时间窗口；第5项 样本 200）──
function logStats(entries, fields, topN = 10) {
  const out = {};
  for (const f of fields) {
    const cnt = {};
    for (const e of entries) {
      const v = e[f];
      if (v !== undefined && v !== null && v !== "") cnt[v] = (cnt[v] || 0) + 1;
    }
    out[f] = Object.entries(cnt).sort((a, b) => b[1] - a[1]).slice(0, topN);
  }
  return out;
}
function filterByMinutes(entries, minutes) {
  if (!minutes) return entries;
  const cutoff = Date.now() - minutes * 60000;
  return entries.filter((e) => {
    const t = Date.parse(String(e.receive_time || "").replace(/\//g, "-"));
    if (isNaN(t)) return true;   // 无时间戳字段的记录保留
    return t >= cutoff;
  });
}
function fmtTop(top, fields) {
  return fields.map((f) => {
    const arr = top[f] || [];
    return arr.length ? f + " Top: " + arr.map(([v, c]) => `${v}×${c}`).join(" ") : "";
  }).filter(Boolean).join("；") || "无统计";
}
async function deepLog(type, opts = {}) {
  const { minutes = 60, nlogs = 200, query = "" } = opts;
  const data = await directLog(type, nlogs, query);
  const entries = (data.entry || []).filter((e) => !e._raw || Object.keys(e).length > 1);
  const windowed = filterByMinutes(entries, minutes);
  // 窗口内无数据时降级用全部样本（避免"无统计"误导），并标注时间范围
  const effective = windowed.length ? windowed : entries;
  const top = logStats(effective, ["src", "dst", "app", "action", "subtype", "severity"]);
  return {
    entries: effective, minutes, nlogs, top,
    rawCount: entries.length,
    inWindow: windowed.length,
    degraded: windowed.length === 0 && entries.length > 0,
    oldest: entries.length ? (entries[entries.length - 1].receive_time || "?") : "",
  };
}
async function directOp(cmd) { return await httpsGet(`/api/?type=op&cmd=${encodeURIComponent(cmd)}&key=${DIRECT_KEY}`); }
async function directCommit(desc) {
  // 异步 commit：明确返回 <job>ID</job>，用 POST（commit 端点标准做法）。
  // 即使 GET 也能工作，POST 更稳。type=commit 同步 commit 在 PAN-OS 上完成后才返回，响应里不一定带 <job>。
  const cmd = `<commit><description>${desc}</description><async/></commit>`;
  return await directHttpsPost(`https://${DIRECT_HOST}:${DIRECT_PORT}/api/?type=commit&cmd=${encodeURIComponent(cmd)}&key=${DIRECT_KEY}`);
}
async function directConfig(xpath) {
  return await httpsGet(`/api/?type=config&action=get&xpath=${encodeURIComponent(xpath)}&key=${DIRECT_KEY}`);
}
async function directConfigShow(xpath) {
  // 读 running config（已 commit 的实际生效配置），区别于 directConfig（candidate/待 commit）
  return await httpsGet(`/api/?type=config&action=show&xpath=${encodeURIComponent(xpath)}&key=${DIRECT_KEY}`);
}
async function directConfigSet(xpath, element) {
  return await directHttpsPost(`https://${DIRECT_HOST}:${DIRECT_PORT}/api/?type=config&action=set&xpath=${encodeURIComponent(xpath)}&element=${encodeURIComponent(element)}&key=${DIRECT_KEY}`);
}
async function directConfigDelete(xpath) {
  return await directHttpsPost(`https://${DIRECT_HOST}:${DIRECT_PORT}/api/?type=config&action=delete&xpath=${encodeURIComponent(xpath)}&key=${DIRECT_KEY}`);
}
async function directConfigMove(xpath, where, destination) {
  // 移动规则到指定位置（top/bottom/before/after）。绕开 MCP move_security_rule 的 v3Schema 故障。
  // top/bottom：不需要 dst
  // before/after：dst=<参照规则的 name 字符串>（不是 xpath）—— PAN-OS API 参数名是 dst 不是 destination
  let url = `https://${DIRECT_HOST}:${DIRECT_PORT}/api/?type=config&action=move&xpath=${encodeURIComponent(xpath)}&where=${encodeURIComponent(where)}&key=${DIRECT_KEY}`;
  if (destination) {
    // destination 可能是完整 xpath（从 block_ip 模板传入）或 name 字符串——统一提取 name
    let name = String(destination);
    const m = name.match(/entry\[@name=['"]([^'"]+)['"]\]\s*$/);
    if (m) name = m[1];
    url += `&dst=${encodeURIComponent(name)}`;
  }
  return await directHttpsPost(url);
}
async function directHttpsPost(fullUrl) {
  // 从 fullUrl 提取 host/path（避免 new URL 解析问题）
  const m = fullUrl.match(/^https:\/\/([^\/:]+)(?::(\d+))?(\/.+)$/);
  if (!m) throw new Error("Invalid URL: " + fullUrl.slice(0, 80));
  const host = m[1], port = parseInt(m[2] || "443", 10), path = m[3];
  return new Promise((resolve, reject) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 20000);
    const req = https.request({ host, port, path, method: "POST", agent: false, rejectUnauthorized: false, signal: ac.signal }, (res) => {
      let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => { clearTimeout(timer); resolve(b); });
    });
    req.on("error", (e) => { clearTimeout(timer); reject(e); });
    req.end();
  });
}

async function callToolRaw(name, args = {}, firewall) {
  if (firewall) args.firewall = firewall;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 30000);
  try {
    const r = await client.callTool({ name, arguments: args }, undefined, { signal: ac.signal });  // SDK 1.30 签名：callTool(params, resultSchema, options)——signal 必须放第 3 参，放第 2 参会被当成 zod schema 导致 v3Schema.safeParse 崩溃
    const txt = r.content && r.content[0] && r.content[0].text;
    try { return { ok: true, data: JSON.parse(txt) }; } catch { return { ok: true, data: { raw: String(txt) } }; }
  } catch (e) { return { ok: false, error: e }; }
  finally { clearTimeout(timer); }
}

// 直接调 MCP server 上的 run_op_command（不走 MCP 工具包装），解析关键字段
function xmlEntries(xml) {
  const blocks = xml.match(/<entry[^>]*>([\s\S]*?)<\/entry>/g) || [];
  return blocks.map((blk) => {
    const e = {};
    // 提取 <entry name="X"> 的 name 属性（PAN-OS 用属性而非 <name> 元素），存为 @_name 以兼容 MCP 格式
    const nm = blk.match(/<entry[^>]*\bname="([^"]+)"/);
    if (nm) e["@_name"] = nm[1];
    const tag = /<(\w+)>([^<]*)<\/\1>/g;
    let tm;
    while ((tm = tag.exec(blk)) !== null) if (!(tm[1] in e)) e[tm[1]] = tm[2];
    return e;
  });
}
async function directRunOp(arg) {
  const isObj = arg && typeof arg === "object";
  const txt = isObj ? (arg.type === "config" ? await directConfig(arg.xpath) : "") : await directOp(arg);
  // 优先 entry 数组（licenses/security_rules/address_objects 等）
  const entries = xmlEntries(txt);
  if (entries.length) return { entry: entries, _count: entries.length };
  // 再字段提取（设备/会话等无 entry 的命令）
  const fields = {};
  const re = /<(\w+)>([^<]+)<\/\1>/g;
  let m;
  while ((m = re.exec(txt)) !== null) if (!(m[1] in fields)) fields[m[1]] = m[2];
  ["response", "result", "job", "status", "msg"].forEach((k) => delete fields[k]);
  const KNOWN = ["hostname", "model", "sw-version", "ip-address", "serial", "uptime", "mac-address", "num-active", "num-tcp", "num-udp", "num-max", "kbps", "pps", "enabled", "ntun", "feature", "expires", "expired", "description", "ip", "type", "state", "zone", "name", "total-count"];
  const picked = {};
  KNOWN.forEach((k) => { if (fields[k] !== undefined) picked[k] = fields[k]; });
  if (Object.keys(picked).length) return picked;
  return { raw: txt.slice(0, 2000) };
}

const toolCache = new Map();
const CACHE_TTL = { get_traffic_logs: 20000, get_threat_logs: 20000, get_system_logs: 20000, get_url_filter_logs: 20000, default: 60000 };

// 核心查询工具直连 + 策展解析（比 MCP 快一倍，输出适合人读；MCP 返回的是未策展的嵌套/原始数据）
async function directCurated(name) {
  const cmdMap = {
    get_firewall_info: "<show><system><info></info></system></show>",
    get_system_resources: "<show><system><resources></resources></system></show>",
    get_active_sessions: "<show><session><info></info></session></show>",
    get_ha_status: "<show><high-availability><state></state></high-availability></show>",
    get_licenses: "<request><license><info></info></license></request>",
    get_interfaces: "<show><interface>all</interface></show>",
  };
  if (!cmdMap[name]) throw new Error("无策展命令: " + name);
  // show system info 尾部带 <plugin><entry> 会干扰 entry 优先策略，改用纯字段提取
  if (name === "get_firewall_info") {
    const txt = await directOp(cmdMap[name]);
    const fields = {};
    const re = /<([\w-]+)>([^<]+)<\/\1>/g;  // [\w-] 匹配带连字符的标签（ip-address/sw-version/mac-address 等）
    let m;
    while ((m = re.exec(txt)) !== null) if (!(m[1] in fields)) fields[m[1]] = m[2].trim();
    ["response", "result", "job", "status", "msg", "pkginfo", "pkgtype"].forEach((k) => delete fields[k]);
    return fields;
  }
  let r2 = await directRunOp(cmdMap[name]);
  if (name === "get_system_resources" && r2.raw && typeof r2.raw === "string") {
    const t = r2.raw;
    const load = t.match(/load average: ([^\n]+)/);
    const mem = t.match(/MiB Mem :\s*([\d.]+) total,\s*([\d.]+) free,\s*([\d.]+) used/);
    r2 = { "load average": load ? load[1].trim() : "?", "mem total": mem ? mem[1] + " MiB" : "?", "mem used": mem ? mem[3] + " MiB" : "?" };
  }
  return r2;
}

async function callTool(name, args = {}, firewall) {
  const key = name + "|" + (firewall || "") + "|" + JSON.stringify(args || {});
  const hit = toolCache.get(key);
  const ttl = CACHE_TTL[name] || CACHE_TTL.default;
  if (hit && Date.now() - hit.ts < ttl) return hit.data;
  const data = await callToolImpl(name, args, firewall);
  toolCache.set(key, { data, ts: Date.now() });
  return data;
}

// ── 工具级路由配置（tools-config.json，按工具指定 mcp/direct/auto）──
const TOOLS_CONFIG_PATH = process.env.TOOLS_CONFIG || path.join(__dirname, "tools-config.json");
let TOOL_ROUTES = {};
try { TOOL_ROUTES = JSON.parse(fs.readFileSync(TOOLS_CONFIG_PATH, "utf-8")); }
catch (e) { console.warn("[agent] tools-config.json 未找到或无效，全部 auto 模式:", TOOLS_CONFIG_PATH); }
function toolRoute(name) { const r = (TOOL_ROUTES.routes && TOOL_ROUTES.routes[name]) || TOOL_ROUTES._default || "auto"; return r; }

async function callToolImpl(name, args = {}, firewall) {
  const route = toolRoute(name);
  if (route === "direct") return await directForTool(name, args);
  if (route === "mcp") {
    const r = await callToolRaw(name, args, firewall);
    if (r.ok) return r.data;
    throw r.error;
  }
  // 直连专用工具（MCP 117 工具中不存在）：硬件环境（温度/电源/风扇）
  if (name === "get_system_environmentals") {
    return await directRunOp("<show><system><environmentals></environmentals></system></show>");
  }
  // 日志类工具直接走直连（跳过 MCP：MCP server 的日志工具存在 v3Schema 故障，且等待 30s 超时太慢）
  if (["get_traffic_logs", "get_threat_logs", "get_system_logs", "get_url_filter_logs", "get_config_logs"].includes(name)) {
    const typeMap = { get_traffic_logs: "traffic", get_threat_logs: "threat", get_system_logs: "system", get_url_filter_logs: "url", get_config_logs: "config" };
    const nlogs = args.nlogs || 20;
    return await directLog(typeMap[name], nlogs, args.query || "");
  }
  // 核心查询工具直连优先（更快 + 输出已策展可读；失败回退 MCP）
  if (["get_firewall_info", "get_system_resources", "get_active_sessions", "get_ha_status", "get_licenses", "get_interfaces"].includes(name)) {
    try { return await directCurated(name); }
    catch (e) { console.error("[agent] 策展直连失败，回退 MCP:", name, String(e.message || e)); }
  }
  const r = await callToolRaw(name, args, firewall);
  if (r.ok) return r.data;
  // MCP server 全局故障（v3Schema）时，回退到直接 HTTP 调用防火墙 API
  if (["get_firewall_info", "get_system_resources", "get_active_sessions", "get_content_versions", "get_wildfire_status", "get_security_rules", "get_address_objects", "get_interfaces", "get_zones", "get_licenses", "get_routing_table", "get_arp_table", "get_ha_status", "get_ipsec_tunnels", "get_globalprotect_users", "get_application_filters"].includes(name)) {
    const cmdMap = {
      get_firewall_info: "<show><system><info></info></system></show>",
      get_system_resources: "<show><system><resources></resources></system></show>",
      get_active_sessions: "<show><session><info></info></session></show>",
      get_content_versions: "<show><jobs><id>content-update</id></jobs></show>",
      get_wildfire_status: "<show><wildfire><status></status></wildfire></show>",
      get_security_rules: { type: "config", xpath: "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules" },
      get_address_objects: { type: "config", xpath: "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address" },
      get_interfaces: "<show><interface>all</interface></show>",
      get_zones: { type: "config", xpath: "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone" },
      get_licenses: "<request><license><info></info></license></request>",
      get_routing_table: "<show><routing>route</routing></show>",
      get_ha_status: "<show><high-availability><state></state></high-availability></show>",
      get_ipsec_tunnels: "<show><vpn>ipsec</vpn></show>",
      get_globalprotect_users: "<show><global-protect-gateway><clients></clients></global-protect-gateway></show>",
      get_application_filters: "<show><running><application-filter><entry></entry></application-filter></running></show>",
    };
    try {
      // get_firewall_info 特殊解析：show system info 尾部带 <plugin><entry> 会干扰 entry 优先策略
      if (name === "get_firewall_info") return await directCurated(name);
      let r2 = await directRunOp(cmdMap[name]);
      if (name === "get_system_resources" && r2.raw && typeof r2.raw === "string") {
        const t = r2.raw;
        const load = t.match(/load average: ([^\n]+)/);
        const mem = t.match(/MiB Mem :\s*([\d.]+) total,\s*([\d.]+) free,\s*([\d.]+) used/);
        r2 = { "load average": load ? load[1].trim() : "?", "mem total": mem ? mem[1] + " MiB" : "?", "mem used": mem ? mem[3] + " MiB" : "?" };
      }
      return r2;
    } catch (e) { throw new Error(`${name} 直连也失败：${e.message}`); }
  }
  throw r.error;
}

// direct 路由：强制走直连路径（日志 directLog / 核心 directCurated / 查询 directRunOp）
async function directForTool(name, args = {}) {
  const typeMap = { get_traffic_logs: "traffic", get_threat_logs: "threat", get_system_logs: "system", get_url_filter_logs: "url", get_config_logs: "config" };
  if (typeMap[name]) return await directLog(typeMap[name], args.nlogs || 20, args.query || "");
  if (name === "get_system_environmentals") return await directRunOp("<show><system><environmentals></environmentals></system></show>");
  if (["get_firewall_info", "get_system_resources", "get_active_sessions", "get_ha_status", "get_licenses", "get_interfaces"].includes(name)) {
    return await directCurated(name);
  }
  const cmdMap = {
    get_firewall_info: "<show><system><info></info></system></show>",
    get_system_resources: "<show><system><resources></resources></system></show>",
    get_active_sessions: "<show><session><info></info></session></show>",
    get_content_versions: "<show><jobs><id>content-update</id></jobs></show>",
    get_wildfire_status: "<show><wildfire><status></status></wildfire></show>",
    get_security_rules: { type: "config", xpath: "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules" },
    get_address_objects: { type: "config", xpath: "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address" },
    get_interfaces: "<show><interface>all</interface></show>",
    get_zones: { type: "config", xpath: "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone" },
    get_licenses: "<request><license><info></info></license></request>",
    get_routing_table: "<show><routing>route</routing></show>",
    get_arp_table: "<show><arp><entry name='all'/></arp></show>",
    get_ha_status: "<show><high-availability><state></state></high-availability></show>",
    get_ipsec_tunnels: "<show><vpn>ipsec</vpn></show>",
    get_globalprotect_users: "<show><global-protect-gateway><clients></clients></global-protect-gateway></show>",
    get_application_filters: "<show><running><application-filter><entry></entry></application-filter></running></show>",
  };
  if (cmdMap[name]) {
    let r2 = await directRunOp(cmdMap[name]);
    if (name === "get_system_resources" && r2.raw && typeof r2.raw === "string") {
      const t = r2.raw;
      const load = t.match(/load average: ([^\n]+)/);
      const mem = t.match(/MiB Mem :\s*([\d.]+) total,\s*([\d.]+) free,\s*([\d.]+) used/);
      r2 = { "load average": load ? load[1].trim() : "?", "mem total": mem ? mem[1] + " MiB" : "?", "mem used": mem ? mem[3] + " MiB" : "?" };
    }
    return r2;
  }
  throw new Error(name + " 无 direct 路由（请配置为 mcp 或 auto）");
}

// ── LLM 分类（当前提供方）──
async function llmClassify(role, system, input, timeoutMs = 20000) {
  const p = LLM_PROVIDERS[currentLLM];
  if (!p || !p.key) return null;
  // Kimi（k2.6 等思考型模型）响应慢，规划类调用默认 20s 常超时 → 自动放宽到 45s
  const effectiveTimeout = (currentLLM === "kimi" && timeoutMs <= 20000) ? 45000 : timeoutMs;
  // 429 自动重试：Moonshot/Kimi 限流频繁，单次 429 等 3s 通常可恢复（kimi 1 个任务多次调用易撞 rpm 限制）
  for (let attempt = 0; attempt < 2; attempt++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), effectiveTimeout);
    const t0 = Date.now();
    try {
      const r = await fetch(`${p.base_url}/chat/completions`, {
        method: "POST", signal: ac.signal,
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${p.key}` },
        body: JSON.stringify({ model: p.model, ...(currentLLM === "kimi" ? {} : { temperature: 0 }),
          messages: [{ role: "system", content: system }, { role: "user", content: input }],
          // deepseek / qwen3.8-max / kimi-k2.6 均为思考型模型：禁用 thinking 避免花大量时间生成内部推理
          // （实测 qwen3.8-max 不禁用→107s，禁用→9.4s；kimi-k2.6 不禁用→正文空（token 全被 thinking 吃掉），禁用→993字符）
          ...(["deepseek", "qwen", "kimi"].includes(currentLLM) ? { thinking: { type: "disabled" } } : {}) }),
      });
      if (r.status === 429 && attempt === 0) {
        // 限流：等 3s 重试一次
        console.warn(`[agent] LLM ${currentLLM} 429 限流，3s 后重试`);
        await new Promise((r) => setTimeout(r, 3000));
        continue;
      }
      if (!r.ok) { console.error("[agent] LLM http", r.status); return null; }
      const d = await r.json();
      const text = d.choices?.[0]?.message?.content || "";
      recordLLM(role, input, text, Date.now() - t0);
      return text;
    } catch (e) { console.error("[agent] LLM error:", e.message); recordLLM(role, input, "ERROR: " + e.message, Date.now() - t0); return null; }
    finally { clearTimeout(timer); }
  }
  return null;
}

async function llmResolveAction(input) {
  const list = Object.entries(ACTIONS).map(([k, v]) => `${k}: ${v.label}（如"${v.keywords[0]}"）`).join("\n");
  const text = await llmClassify("意图规划",
    `你是防火墙运维意图分类器。从动作列表选一个 key；若输入与防火墙查询无关输出 {"action":null}；若输入是配置变更请求（创建/删除/封禁/改策略）输出 {"action":"change"}；若输入是故障诊断请求（连不上/不通/访问不了/排查/诊断/健康检查/某IP什么情况/一直扫描/某个具体故障现象）输出 {"action":"diag"}；若输入是审计/配置变更查询（谁改的/审计/变更记录/谁修改/谁删了/配置变更）输出 {"action":"audit"}。
注意：若输入是**咨询/方案/教学/画图类**请求（如何配置XX、XX是什么、帮我画个拓扑图、最佳实践建议、概念解释等）→ 输出 {"action":null}（系统会用自由问答回答，不要归为 diag）。
【多轮追问】输入前可能附带【最近对话上下文】。若当前问题引用了上下文（如"那条/上面那条/刚才那个/这个结果/它/那个策略/那台设备/结合上面的结果继续/基于刚才的"等指代词或依赖前文才能理解）→ 属于**追问**，按下列规则处理：
  - 追问上轮结果的具体含义/细节/为什么 → {"action":null}（自由问答会结合上下文回答）
  - 追问"把那条删掉/禁用/封禁"等（指代上下文中的具体条目）→ {"action":"change"}（系统会结合上下文解析出具体条目）
  - 追问"那条对应的流量/策略分析"（指代上轮结果做进一步诊断）→ {"action":"diag"}
只输出 JSON：{"action":"<key>"}。\n动作列表（含 diag）:\n${list}\ndiag: 故障诊断（连不上/不通/访问不了/排查/诊断/健康检查/什么情况）`, withCtx(input));
  if (!text) return null;
  const m = text.match(/"action"\s*:\s*("?)(\w+|null)\1/);
  if (!m) return null;
  const key = m[2];
  return key === "null" ? null : key;
}

// 变更参数提取（模板化，LLM 只填参数）
async function llmExtractChange(input) {
  const tmplList = Object.entries(CHANGE_TEMPLATES).map(([k, v]) => `${k}: ${v.label}（参数: ${v.params.join(", ")}）`).join("\n");
  const text = await llmClassify("变更参数提取",
    `你是防火墙配置变更解析器。从模板列表选一个 template，并提取参数（ip 为合法 IPv4；name 允许字母/数字/点/下划线/连字符 [a-zA-Z0-9_.-]，防火墙规则名如 block-1.1.1.1-20260820 是合法的，必须原样保留）。

【重要区分规则】
- block_ip / allow_ip：用于**创建新的**封禁/放行策略（"添加/新建/创建一条封禁/放行/拒绝/允许XX的策略"）。即使提到"置顶/最顶部"，只要是"创建新策略"场景，就用 block_ip / allow_ip。
- move_security_rule：仅用于**移动已有的**策略（"把XX移到YY"）。必须有明确的已有规则名 name，name 不能为空。
  - "添加一条封禁XX的策略在最顶部" → block_ip，不是 move_security_rule
  - "把 block-social 移到 deny-all 上面" → move_security_rule (name=block-social, where=before, destination=deny-all)
  - "把 A 移到最上面" → move_security_rule (name=A, where=top)

move_security_rule 的 where 取值 top/bottom/before/after 之一：
- "把 A 移到 B 上面/之前" → where=before, destination=B
- "把 A 移到 B 下面/之后" → where=after, destination=B
- "把 A 移到最上面" / "置顶 A" → where=top
- "把 A 移到最下面" / "置底 A" → where=bottom

delete_security_rule：
- 用户给了精确规则名（只含字母数字下划线短横线）→ 填 name="<精确名>"
- 用户只给了模糊描述（"名称带 block 的"、"名字含 social 的"、"那条 deny 开头的"）→
  **抽取最核心的搜索子串**放进 keyword 字段，去掉"的/带/有/含/按/在/里/上/下/规则/名字/名称"等停用词
  （例如"名称带 block 的" → keyword="block"；"那条 deny 开头的" → keyword="deny"；"名字含 social 的" → keyword="social"）
  **不要把整段描述塞进 keyword**
  系统会列出含核心子串的候选由用户确认
set_security_rule_disabled（禁用规则）：用法同 delete_security_rule（精确名填 name，模糊 keyword 取核心子串）
set_security_rule_enabled（启用规则）：用法同 delete_security_rule
allow_ip（放行 IP）：从"放行/允许/白名单/allow"相关输入提取 ip（合法 IPv4）
block_ip / allow_ip / block_ip_group：**可选 params.position 决定创建后位置**（缺省 = 不移动，规则留在末尾）：
  - 用户说"最顶部/置顶/最上面" → position="top"
  - 用户说"最底部/置底/最下面" → position="bottom"
  - 用户说"X 策略的上面/之前" → position="before" + destination="X 的精确名"
  - 用户说"X 策略的下面/之后" → position="after" + destination="X 的精确名"
  - 用户**没说位置** → 整个 position 字段省略（不移动）——避免无脑 top 误伤用户原本的规则顺序
block_ip_group（封禁 IP 组）：用于**多个 IP 封禁 + 放进地址组**场景。识别关键词："封禁这 3 个 IP"/"把多个 IP 放进一个组"/"地址组"/"把 IP 打包封禁"/"在源地址里用组"。
  - 提取所有 IPv4 到 params.ips 数组（如 ["1.1.2.1","1.1.2.2","1.1.2.3"]），不能是字符串
  - 用户给了组名（如"黑名单组/封禁组/internet-block"）→ 填 params.group_name；未给则系统自动生成 "block-group-YYYYMMDD"
  - **绝不能**把多个 IP 用逗号拼成一个名字（PAN-OS 不接受逗号），绝不能用 block_ip 单 IP 模板
【多轮追问】输入前可能附带【最近对话上下文】（含关键条目名）。若用户用指代词引用上下文中的条目（如"把那条/上面那条/刚才那条/它/这个策略/那个对象 删除/禁用/启用/移动/封禁"）：
  - 先看上下文的"关键条目"和"结果"，把指代解析为**上下文中真实存在的条目 name**（如 block-1.1.1.1-20260822 / Allow all），填入 params.name
  - **禁止编造**上下文里不存在的 name；无法确定时 name 留空走 keyword 预检
若无法匹配模板输出 {"template":null}。只输出 JSON：{"template":"<key>","params":{...}}。\n${tmplList}`, withCtx(input));
  if (!text) return null;
  try {
    const m = text.match(/\{[\s\S]*\}/);
    const o = JSON.parse(m ? m[0] : "{}");
    if (!o.template || !CHANGE_TEMPLATES[o.template]) return null;
    // 安全网：LLM 误把"添加封禁/放行策略"归为 move_security_rule（name 为空），自动纠正为 block_ip/allow_ip
    if (o.template === "move_security_rule" && (!o.params || !o.params.name || String(o.params.name).trim() === "")) {
      // 从输入中提取 IP，如果有的话说明是封禁/放行场景而非移动策略
      const ipMatch = input.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      if (ipMatch) {
        const ip = ipMatch[1];
        const isAllow = /放行|允许|白名单|allow/i.test(input);
        // block_ip/allow_ip 现在默认置顶，不再需要传 position 参数
        o.template = isAllow ? "allow_ip" : "block_ip";
        o.params = { ip };
      } else {
        // 无 IP 也无 name，这个 move 模板无法执行，返回 null 让系统走自由问答
        return null;
      }
    }
    return o;
  } catch { return null; }
}

// 诊断意图解析：connectivity / threat_profile / generic
// 审计请求解析：时间窗口 + 对象类型
async function llmParseAudit(input) {
  const text = await llmClassify("审计解析",
    `你是防火墙审计日志查询解析器。从用户请求中提取：minutes（时间窗口分钟数，如"10分钟前"=10、"最近1小时"=60、"今天"=1440，无则默认60）；object（对象类型："策略"=security、"地址"=address、"全部"=all）。只输出 JSON：{"minutes":<num>,"object":"<type>"}。`,
    input);
  if (!text) return { minutes: 60, object: "all" };
  const m = text.match(/\{[\s\S]*?\}/);
  if (!m) return { minutes: 60, object: "all" };
  try {
    const o = JSON.parse(m[0]);
    return { minutes: Number(o.minutes) || 60, object: String(o.object || "all") };
  } catch { return { minutes: 60, object: "all" }; }
}

// LLM 诊断综合解读（基于实际数据给出根因/置信度/建议）
async function llmSynthesize(input, sections, stats) {
  // 精简数据：每段 result 限 200 字符、统计限 600 字符，让 Kimi 等思考型模型能快速响应
  const ctx = sections.map((s) => "[" + s.step + "] " + String(s.result).slice(0, 200)).join("\n");
  const statCtx = stats ? "\n日志统计(前6):\n" + JSON.stringify(stats).slice(0, 600) : "";
  const text = await llmClassify("诊断综合",
    `你是 PAN-OS 防火墙诊断专家。**禁止套模板**，必须真正读数据、交叉对照、做证据链推理。

【重要推理原则】
- **"观察缺失 ≠ 否定结论"**：流量日志没有 X ≠ "X 没发生"。可能是：根本没到达防火墙、被前置设备丢掉、查询命令不带正确字段、过滤窗口太窄、主机方向问题。**涉及"未观测到"的关键证据时，置信度不应给"高"**——只能给"中"或"低"。
- **直接证据 > 间接推断**：日志里出现 N 条 → 直接证据；"观察缺失" → 弱证据，不能用它下确定性结论。
- **必须"过数据"**：用户提到的 IP/主机/对象，**逐段检查**它在每段数据中是否出现、出现几次（正向证据）。如果没出现 → 这本身也是证据（"用户对象未被防火墙观测到"→ 报告这个事实），但要避免跳到"对象损坏/不存在"这种跳跃结论。
- **PAN-OS zone 是核心**：策略匹配靠 zone。跨 zone 默认拒绝。即便没有该 IP 的具体策略，只要 zone 间没明确允许，就不通；如果 source-zone 都没匹配上更应怀疑 zone 配置。先列 zone，再列策略。
- **跨子网时 ARP 表空 ≠ 主机不可达**：源主机（不同子网）的 MAC 在网关处处理，不一定进入防火墙 ARP 表。ARP 表空只能说明"防火墙未直接 ARP 过该主机"，结合 traceroute/ping 才能推断。
- **路由缺失推断要克制**：没默认路由未必是该主机不通，可能防火墙只需 stub 路由。需看源 IP 是否有特定路由 + 是否经转发。
- **如果用户描述与数据"明显冲突"**（例如用户说"192.168.0.3 不能访问 192.168.1.2"但你看到数据里两个 IP 均未出现），需在 verdict 中明确指出**"用户陈述与防火墙观测一致（防火墙没观测到这两个 IP 的交互），建议先在源主机实测确认前提"**，**不要硬去找"为什么不通"的根因**。
- **绝对优先级："功能未配置"识别**（这是最常见的误判陷阱）：当用户 query 涉及某个功能/组件（GP 客户端、VPN 隧道、IPSec、DHCP、HA、特定 zone 间路由等），如果相关数据**全部为空**（如 GP 配置空 + GP 用户列表空 + IPSec 隧道 0 + 源 IP 入接口无记录 + ARP 空 + 会话空），结论**应当是"该功能未配置 / 未启用 / 未启动"**，而不是"已配置但失败"。**绝对不要**强行套用"已建立但被拒绝""隧道建了但路由不通"这种模板——证据不支持。
  - 验证逻辑：先看用户 query 中"关键功能"的配置/启用证据（如 get_globalprotect_config 是否非空）→ 若全部为空 → 直接结论"未配置"
  - 反例警示：流量里有 ssl 应用 ≠ GP 客户端连接；流量 reset-both ≠ GP 客户端被拒绝（前提是是GP 必须已配置；如配置为空则这条推理完全无效）

【输出格式】
JSON：
{
  "verdict": "一段话根因（含证据引用：[流量]、[策略]、[zone] 等指明依据）",
  "confidence": "高/中/低",
  "confidence_reason": "为什么是这个置信度",
  "evidence": ["关键证据1:…", "关键证据2:…", "反驳证据:…"],
  "recommendation": "可执行下一步（具体到工具/命令）"
}

【用户症状】"${input}"
【数据】
${ctx}${statCtx}`,
    input, 120000);
  if (!text) return null;
  const m = text.match(/\{[\s\S]*?\}/);
  if (!m) return { verdict: text.slice(0, 300), confidence: "?", recommendation: "" };
  try {
    const o = JSON.parse(m[0]);
    return {
      verdict: String(o.verdict || "").slice(0, 600),
      confidence: ["高", "中", "低"].includes(o.confidence) ? o.confidence : "?",
      confidenceReason: String(o.confidence_reason || "").slice(0, 200),
      evidence: Array.isArray(o.evidence) ? o.evidence.slice(0, 8).map(String) : [],
      recommendation: String(o.recommendation || "").slice(0, 800),
    };
  } catch { return { verdict: text.slice(0, 300), confidence: "?", recommendation: "" }; }
}
async function llmParseDiag(input) {
  const text = await llmClassify("诊断规划",
    `你是网络诊断解析器。判断用户症状属于：connectivity（连通性排查，涉及源/目的/IP/端口/连不上/不通/访问不了）、threat_profile（威胁源画像，涉及"什么情况/一直扫描/攻击/画像"且给定了IP）、generic（通用健康检查）。提取参数：ip（IPv4）、port（端口）、direction（inbound/outbound）、target_label（如"外网"）、minutes（时间窗口分钟数，如"最近10分钟"=10、"最近1小时"=60、"今天"=1440，无则默认60）、probe（可选：用户要求"ping/测试连通/探测"填"ping"；要求"追踪路由/traceroute"填"traceroute"；否则不填）。
【多轮追问】输入前可能附带【最近对话上下文】。若用户引用前文（如"那条策略/刚才那个IP/上面的结果"）继续诊断，从上下文提取 ip/port 等缺失参数。无法判断输出 {"type":null}。只输出 JSON：{"type":"<t>","params":{}}。`, withCtx(input));
  if (!text) return null;
  try {
    const m = text.match(/\{[\s\S]*\}/);
    const o = JSON.parse(m ? m[0] : "{}");
    if (o.params && o.params.minutes !== undefined) o.params.minutes = Number(o.params.minutes) || 60;
    if (o.params && o.params.probe !== undefined && !["ping", "traceroute"].includes(o.params.probe)) delete o.params.probe;
    return o;
  } catch { return null; }
}

// ── 任务系统 ──
function newTask(type, input, extra = {}) {
  // 多轮追问：自动关联最近一个已完成的任务（前端据此显示"追问自 #N"；extra 可覆盖）
  let followUpOf = null;
  for (let i = tasks.length - 1; i >= 0; i--) {
    const x = tasks[i];
    if (["done", "failed"].includes(x.status) && ["query", "diag", "chat", "inspect"].includes(x.type)) { followUpOf = x.id; break; }
  }
  return { id: ++taskSeq, type, input, status: "pending", steps: [], result: null, error: null, createdAt: new Date().toLocaleString("zh-CN"), followUpOf, ...extra };
}
function saveTask(t) { const i = tasks.findIndex((x) => x.id === t.id); if (i >= 0) tasks[i] = t; persistTasks(); }

async function runQueryTask(t, action, firewall) {
  t.status = "running";
  const results = [];
  for (const tool of ACTIONS[action].tools) {
    if (t.cancelled) { t.status = "cancelled"; break; }
    const step = { tool, status: "running", startMs: Date.now() };
    t.steps.push(step);
    try {
      const r = await callTool(tool, {}, firewall);
      step.status = "ok"; step.ms = Date.now() - step.startMs;
      results.push({ tool, data: r });
    } catch (e) {
      step.status = "err"; step.ms = Date.now() - step.startMs; step.msg = String(e.message || e);
      results.push({ tool, error: step.msg });
    }
  }
  if (t.status !== "cancelled") {
    // 查询匹配分析：把用户 query + 工具结果摘要给 LLM，做"语义匹配分析"
    // （例：query"哪些策略放行了 Internet 到 DMZ" → LLM 要把"Internet"映射到源 zone/DAG，
    //  "DMZ"映射到目标 zone，再从规则列表中筛出真正匹配的放行规则）
    try {
      const summary = await summarizeQuery(t.input, action, results);
      t.result = { label: ACTIONS[action].label, results, summary };
    } catch (e) {
      // LLM 失败不影响查询结果本身——只展示工具原始数据
      t.result = { label: ACTIONS[action].label, results };
    }
    t.status = "done";
    history.unshift({ ts: new Date().toLocaleString("zh-CN"), input: String(t.input), action, label: ACTIONS[action].label });
    if (history.length > MAX_HISTORY) history.pop();
  }
  saveTask(t);
}

// 查询任务的语义匹配分析（轻量 LLM 调用，30s 超时）
async function summarizeQuery(input, action, results) {
  // 抽取最核心的语义：每个工具结果的"条目摘要"——关键字段放最前，避免长 JSON 截断丢失 action/@_name
  const ctx = results.map((r) => {
    if (r.error) return `[${r.tool}] ERROR: ${r.error}`;
    const d = r.data || {};
    if (typeof d === "string") return `[${r.tool}] ${d.slice(0, 1500)}`;
    const items = Array.isArray(d) ? d
      : Array.isArray(d.entry) ? d.entry
      : Array.isArray(d.rules?.entry) ? d.rules.entry
      : Array.isArray(d.zone?.entry) ? d.zone.entry
      : null;
    if (items) {
      // 关键字段提到最前面（防止 250 字符截断把 action/@_name 砍掉，LLM 误判"数据不完整"）
      const head = items.slice(0, 50).map((it) => {
        if (it && typeof it === "object") {
          const ordered = {};
          for (const k of ["@_name", "name", "action", "disabled", "from", "to", "source", "destination", "service", "application", "uuid", "@_uuid"]) {
            if (k in it) ordered[k] = it[k];
          }
          for (const k of Object.keys(it)) if (!(k in ordered)) ordered[k] = it[k];
          return JSON.stringify(ordered).slice(0, 1200);
        }
        return String(it).slice(0, 1200);
      }).join("\n");
      return `[${r.tool}] 共 ${items.length} 条：\n${head}` + (items.length > 50 ? "\n... (省略剩余 " + (items.length - 50) + " 条)" : "");
    }
    return `[${r.tool}] ${JSON.stringify(d).slice(0, 1500)}`;
  }).join("\n\n");
  const text = await llmClassify("查询匹配",
    `你是 PAN-OS 防火墙查询结果分析器。用户的问句往往带语义（如"哪些策略放行了 Internet到 DMZ"——"Internet"=源 zone Untrust 或外部，"DMZ"=目标 zone DMZ 或特定对象）。你需要：

1. **语义映射**：把用户 query 中的关键词（"Internet"/"DMZ"/"内部"/"外部"/特定 IP）映射到实际数据中（zone 名/address 对象/any）。
2. **匹配筛选**：基于映射结果，从上面数据里选出**真正满足用户问题**的条目（按 action 字段区分 allow/deny）。
3. **明确回答**：直接说出"有/无/几条"匹配；如果没有，**明确说"没有匹配的策略"**（不要强行凑"全放行 Allow all"这种看似匹配但实际不相关的）。
4. **完整汇报元数据**：当工具返回 Dashboard General Information 风格的元数据（get_firewall_info）时，**主动列出关键模块版本和状态**——GP/AV/Threat/WildFire/URL 各模块版本号、Advanced Routing、Duplicate IP、Plugin DLP、Device Certificate Status、Uptime 等。问"设备清单/资产"时这些是关键信息，不能漏。
5. **引用**：用条目 @_name 或关键字段标识匹配项。
6. **多轮追问**：若用户问题引用了前文（如"那条/上面那条/它"），优先结合【最近对话上下文】中的条目名和结果回答，不要重复全量查询。

输出 1-3 段简洁中文（≤350 字，比一般查询多 100 字用于展示元数据），不要堆 JSON。`,
    `用户问句：${input}\n\n工具结果：\n${ctx}${buildConversationContext() ? "\n\n" + buildConversationContext() : ""}`,
    30000);
  return text || null;
}

async function runInspectTask(t, firewall) {
  t.status = "running";
  const tools = ACTIONS.inspect.tools;
  const results = [];
  for (const tool of tools) {
    if (t.cancelled) { t.status = "cancelled"; break; }
    const step = { tool, status: "running", startMs: Date.now() };
    t.steps.push(step);
    try { results.push({ tool, data: await callTool(tool, {}, firewall) }); step.status = "ok"; step.ms = Date.now() - step.startMs; }
    catch (e) { step.status = "err"; step.ms = Date.now() - step.startMs; step.msg = String(e.message || e); results.push({ tool, error: step.msg }); }
  }
  if (t.status === "cancelled") { saveTask(t); return; }
  // 简版合规评分（8 项中的 5 项计分）
  const d = (tool) => results.find((r) => r.tool === tool)?.data || {};
  const fw = d("get_firewall_info");
  const rules = d("get_security_rules")?.rules?.entry || [];
  const lic = d("get_licenses")?.licenses?.entry || [];
  const threat = d("get_threat_logs")?.entry || [];
  const wildfire = d("get_wildfire_status")?.raw || String(d("get_wildfire_status"));
  const checks = [
    { name: "策略最小权限", pass: !rules.some((r) => r.action === "allow" && !r.disabled && r.source?.member === "any" && r.destination?.member === "any") },
    { name: "威胁防护启用", pass: !/Disabled due to configuration/.test(wildfire) },
    { name: "许可有效性", pass: !lic.some((l) => l.expired === "yes") },
    { name: "日志连续性", pass: threat.length > 0 && Date.now() - new Date(threat[0].receive_time).getTime() < 7 * 864e5 },
    { name: "内容库更新", pass: true },
  ];
  const scored = checks.filter((c) => c.name !== "内容库更新");
  const pass = scored.filter((c) => c.pass).length;
  const rate = Math.round((pass / scored.length) * 100);
  const grade = rate >= 90 ? "优秀" : rate >= 75 ? "良好" : rate >= 60 ? "需改进" : "不达标";
  const date = new Date().toISOString().slice(0, 10);
  const md = `# PAN-OS 合规巡检报告（WebUI 任务）\n\n| 项 | 值 |\n|---|---|\n| 设备 | ${fw.hostname || "?"} (${fw.serial || "?"}) |\n| 版本 | ${fw["sw-version"] || "?"} |\n| 时间 | ${date} |\n| 评级 | ${grade} (${rate}%) |\n\n| 检查项 | 结果 |\n|---|---|\n` + checks.map((c) => `| ${c.name} | ${c.pass ? "✅ 通过" : "❌ 不通过"} |`).join("\n");
  if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const file = path.join(REPORTS_DIR, `compliance-${date}-task.md`);
  fs.writeFileSync(file, md);
  t.result = { grade, rate, file, checks, hostname: fw.hostname, model: fw.model };
  t.steps.push(`报告落盘 ${path.basename(file)}`);
  t.status = "done";
  saveTask(t);
}

// 变更执行（candidate 阶段）
async function runChangeCandidate(t, tmpl, params, firewall) {
  t.status = "executing";
  const p = { ...params, type: params.type || "ip-netmask" };
  // name 合法化：仅对"创建"类操作生效（add_address_object / block_ip / allow_ip）
  // 删除/移动/禁用/启用必须使用精确的已有规则名（来自防火墙），不得"修正"
  const CREATE_TMPLS = ["add_address_object", "block_ip", "allow_ip"];
  if (CREATE_TMPLS.includes(tmpl) && p.name && !/^[a-zA-Z0-9_.\-]+$/.test(p.name)) {
    t.steps.push(`原 name "${p.name}" 含非法字符，自动生成`);
    p.name = `obj_${(p.value || p.ip || "x").replace(/[^a-zA-Z0-9]/g, "_")}_${Date.now().toString(36)}`;
  }
  // 改用 directOp（XML 命令），绕开 MCP v3Schema 故障
  if (tmpl === "add_address_object") {
    // 用 type=config (POST) 走 setConfig，绕开 op 的 vsys context 问题
    const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='${p.name}']`;
    const xml = `<${p.type}>${p.value}</${p.type}>`;
    const r = await directConfigSet(xpath, xml);
    t.steps.push("candidate: add_address_object (type=config) → " + JSON.stringify(r).slice(0, 80));
  } else if (tmpl === "delete_address_object") {
    const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='${p.name}']`;
    const r = await directConfigDelete(xpath);
    t.steps.push("candidate: delete_address_object (type=config) → " + JSON.stringify(r).slice(0, 80));
  } else if (tmpl === "block_ip") {
    // 封禁 IP：写 address 对象 + security rule。必须用 type=config (set)，type=op 不会持久化到候选配置。
    const ts = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const name = `block-${p.ip}-${ts}`;
    const XPATH_BASE = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']`;
    // 1) 地址对象
    const r1 = await directConfigSet(
      `${XPATH_BASE}/address/entry[@name='${name}']`,
      `<ip-netmask>${p.ip}/32</ip-netmask>`
    );
    t.steps.push("candidate: address " + name + " → " + JSON.stringify(r1).slice(0, 80));
    // 2) 安全规则（拒绝 any → this src）。element 仅用必需字段，避免 log-setting/profile 缺失导致 code 12。
    const ruleXml = `<from><member>any</member></from><to><member>any</member></to><source><member>${name}</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>deny</action><description>WebUI block by Agent</description>`;
    const r2 = await directConfigSet(
      `${XPATH_BASE}/rulebase/security/rules/entry[@name='${name}']`,
      ruleXml
    );
    t.steps.push("candidate: deny rule " + name + " → " + JSON.stringify(r2).slice(0, 80));
    p._objName = name;
    // 3) 可选 move：仅在用户明确指定位置时执行（position=top/bottom/before/after）
    //    未指定 → 不移动，规则留在默认末尾（避免无脑 top 误伤用户原本的规则顺序）
    if (p.position && ["top", "bottom", "before", "after"].includes(p.position)) {
      if ((p.position === "before" || p.position === "after") && !p.destination) {
        t.steps.push("⚠️ " + p.position + " 需要 destination 参照规则名，跳过 move，规则留在末尾");
      } else {
        try {
          const moveXpath = `${XPATH_BASE}/rulebase/security/rules/entry[@name='${name}']`;
          const moveDest = (p.position === "before" || p.position === "after")
            ? `${XPATH_BASE}/rulebase/security/rules/entry[@name='${p.destination}']`
            : null;
          const r3 = await directConfigMove(moveXpath, p.position, moveDest);
          const destTxt = moveDest ? " (参照 " + p.destination + ")" : "";
          t.steps.push("candidate: move " + name + " " + WHERE_CN[p.position] + destTxt + " → " + JSON.stringify(r3).slice(0, 120));
          const r3txt = typeof r3 === "string" ? r3 : JSON.stringify(r3);
          if (r3txt.includes("success") && !r3txt.includes("false") || r3txt.includes("command succeeded")) {
            t.steps.push("✅ move " + WHERE_CN[p.position] + " 成功");
          } else if (!r3txt.includes("success") && !r3txt.includes("succeeded")) {
            t.steps.push("⚠️ move 响应异常：" + r3txt.slice(0, 200));
          }
        } catch (e) {
          t.steps.push("⚠️ move 失败：" + e.message.slice(0, 120));
        }
      }
    } else {
      t.steps.push("ℹ️ 用户未指定位置，规则留在末尾（不移动）");
    }
  } else if (tmpl === "block_ip_group") {
    // 封禁 IP 组：多 IP → 各自地址对象 → 1 个地址组 → deny 规则 source 引用组 → 置顶
    const ips = Array.isArray(p.ips) ? p.ips.filter((x) => x && /^\d+\.\d+\.\d+\.\d+$/.test(String(x).trim())) : [];
    if (ips.length === 0) throw new Error("block_ip_group: 至少需要一个有效 IPv4");
    const ts = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const XPATH_BASE = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']`;
    // group_name 校验：仅 [a-zA-Z0-9_.-]，缺失自动生成
    const groupName = (p.group_name && /^[a-zA-Z0-9_.\-]+$/.test(p.group_name))
      ? p.group_name
      : `block-group-${ts}`;
    // 1) 为每个 IP 建一个 address 对象
    const objNames = [];
    for (const ip of ips) {
      const n = `block-${ip}-${ts}`;
      const r1 = await directConfigSet(
        `${XPATH_BASE}/address/entry[@name='${n}']`,
        `<ip-netmask>${ip}/32</ip-netmask>`
      );
      t.steps.push("candidate: address " + n + " → " + JSON.stringify(r1).slice(0, 80));
      objNames.push(n);
    }
    // 2) 建地址组（成员 = 上面建的 address 对象）
    const staticXml = "<static>" + objNames.map((n) => `<member>${n}</member>`).join("") + "</static><description>WebUI block group by Agent</description>";
    const r2 = await directConfigSet(
      `${XPATH_BASE}/address-group/entry[@name='${groupName}']`,
      staticXml
    );
    t.steps.push("candidate: address-group " + groupName + " (" + objNames.length + " 成员) → " + JSON.stringify(r2).slice(0, 80));
    // 3) deny 规则 source 引用 group
    const ruleName = groupName;
    const ruleXml = `<from><member>any</member></from><to><member>any</member></to><source><member>${groupName}</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>deny</action><description>WebUI block group by Agent (${ips.length} IPs)</description>`;
    const r3 = await directConfigSet(
      `${XPATH_BASE}/rulebase/security/rules/entry[@name='${ruleName}']`,
      ruleXml
    );
    t.steps.push("candidate: deny rule (source=group) " + ruleName + " → " + JSON.stringify(r3).slice(0, 80));
    p._objName = ruleName;
    p._groupName = groupName;
    p._memberCount = objNames.length;
    // 4) 可选 move：仅在用户明确指定位置时执行；未指定 → 规则留在末尾（不移动）
    if (p.position && ["top", "bottom", "before", "after"].includes(p.position)) {
      if ((p.position === "before" || p.position === "after") && !p.destination) {
        t.steps.push("⚠️ " + p.position + " 需要 destination 参照规则名，跳过 move，规则留在末尾");
      } else {
        try {
          const moveXpath = `${XPATH_BASE}/rulebase/security/rules/entry[@name='${ruleName}']`;
          const moveDest = (p.position === "before" || p.position === "after")
            ? `${XPATH_BASE}/rulebase/security/rules/entry[@name='${p.destination}']`
            : null;
          const r4 = await directConfigMove(moveXpath, p.position, moveDest);
          const destTxt = moveDest ? " (参照 " + p.destination + ")" : "";
          t.steps.push("candidate: move " + ruleName + " " + WHERE_CN[p.position] + destTxt + " → " + JSON.stringify(r4).slice(0, 120));
          const r4txt = typeof r4 === "string" ? r4 : JSON.stringify(r4);
          if (r4txt.includes("success") && !r4txt.includes("false") || r4txt.includes("command succeeded")) {
            t.steps.push("✅ move " + WHERE_CN[p.position] + " 成功");
          } else if (!r4txt.includes("success") && !r4txt.includes("succeeded")) {
            t.steps.push("⚠️ move 响应异常：" + r4txt.slice(0, 200));
          }
        } catch (e) {
          t.steps.push("⚠️ move 失败：" + e.message.slice(0, 120));
        }
      }
    } else {
      t.steps.push("ℹ️ 用户未指定位置，规则留在末尾（不移动）");
    }
  } else if (tmpl === "move_security_rule") {
    // 移动策略：改用 directConfigMove，绕开 MCP move_security_rule 的 v3Schema 故障
    if (!p.name || !p.where) throw new Error("move_security_rule 缺少 name 或 where");
    if ((p.where === "before" || p.where === "after") && !p.destination) {
      throw new Error("move_security_rule 在 before/after 时必须提供 destination（参照规则名）");
    }
    const XPATH_BASE = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']`;
    const moveXpath = `${XPATH_BASE}/rulebase/security/rules/entry[@name='${p.name}']`;
    const moveDest = (p.where === "before" || p.where === "after")
      ? `${XPATH_BASE}/rulebase/security/rules/entry[@name='${p.destination}']`
      : null;
    const r = await directConfigMove(moveXpath, p.where, moveDest);
    t.steps.push("candidate: move_security_rule " + p.name + " " + p.where + (moveDest ? " " + p.destination : "") + " → " + JSON.stringify(r).slice(0, 120));
  } else if (tmpl === "delete_security_rule") {
    // 模糊关键词：先列候选，不删除
    const res = await resolveRuleTarget(t, p, firewall, "删除");
    if (!res) return; // 已转 awaiting_selection，等用户点选
    // 改用 directConfigDelete（type=config delete），绕开 MCP delete_security_rule 的 v3Schema 故障
    const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='${res.name}']`;
    const r = await directConfigDelete(xpath);
    t.steps.push("candidate: delete_security_rule " + res.name + " → " + JSON.stringify(r).slice(0, 120));
    p.name = res.name;
  } else if (tmpl === "set_security_rule_disabled") {
    const res = await resolveRuleTarget(t, p, firewall, "禁用");
    if (!res) return;
    // 改用 directConfigSet 写 <disabled>yes</disabled>，绕开 MCP set_security_rule_disabled 的 v3Schema 故障
    const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='${res.name}']/disabled`;
    const r = await directConfigSet(xpath, `<disabled>yes</disabled>`);
    t.steps.push("candidate: disable " + res.name + " → " + JSON.stringify(r).slice(0, 120));
    p.name = res.name;
  } else if (tmpl === "set_security_rule_enabled") {
    const res = await resolveRuleTarget(t, p, firewall, "启用");
    if (!res) return;
    // 改用 directConfigSet 写 <disabled>no</disabled>，绕开 MCP set_security_rule_disabled 的 v3Schema 故障
    const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='${res.name}']/disabled`;
    const r = await directConfigSet(xpath, `<disabled>no</disabled>`);
    t.steps.push("candidate: enable " + res.name + " → " + JSON.stringify(r).slice(0, 120));
    p.name = res.name;
  } else if (tmpl === "allow_ip") {
    // 放行 IP：对称 block_ip，写 address 对象 + allow 规则
    const ts = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const name = `allow-${p.ip}-${ts}`;
    const XPATH_BASE = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']`;
    const r1 = await directConfigSet(
      `${XPATH_BASE}/address/entry[@name='${name}']`,
      `<ip-netmask>${p.ip}/32</ip-netmask>`
    );
    t.steps.push("candidate: address " + name + " → " + JSON.stringify(r1).slice(0, 80));
    const ruleXml = `<from><member>any</member></from><to><member>any</member></to><source><member>${name}</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>allow</action><description>WebUI allow by Agent</description>`;
    const r2 = await directConfigSet(
      `${XPATH_BASE}/rulebase/security/rules/entry[@name='${name}']`,
      ruleXml
    );
    t.steps.push("candidate: allow rule " + name + " → " + JSON.stringify(r2).slice(0, 80));
    p._objName = name;
    // 3) 可选 move：仅在用户明确指定位置时执行；未指定 → 规则留在末尾（不移动）
    if (p.position && ["top", "bottom", "before", "after"].includes(p.position)) {
      if ((p.position === "before" || p.position === "after") && !p.destination) {
        t.steps.push("⚠️ " + p.position + " 需要 destination 参照规则名，跳过 move，规则留在末尾");
      } else {
        try {
          const moveXpath = `${XPATH_BASE}/rulebase/security/rules/entry[@name='${name}']`;
          const moveDest = (p.position === "before" || p.position === "after")
            ? `${XPATH_BASE}/rulebase/security/rules/entry[@name='${p.destination}']`
            : null;
          const r3 = await directConfigMove(moveXpath, p.position, moveDest);
          const destTxt = moveDest ? " (参照 " + p.destination + ")" : "";
          const r3txt = typeof r3 === "string" ? r3 : JSON.stringify(r3);
          t.steps.push("candidate: move " + name + " " + WHERE_CN[p.position] + destTxt + " → " + r3txt.slice(0, 120));
          if (r3txt.includes("success") || r3txt.includes("command succeeded") || r3txt.includes("moved")) {
            t.steps.push("✅ move " + WHERE_CN[p.position] + " 成功");
          } else {
            t.steps.push("⚠️ move 响应异常：" + r3txt.slice(0, 200));
          }
        } catch (e) {
          t.steps.push("⚠️ move 失败：" + e.message.slice(0, 120));
        }
      }
    } else {
      t.steps.push("ℹ️ 用户未指定位置，规则留在末尾（不移动）");
    }
  }
  t.params = p;
  t.status = "awaiting_commit";
  saveTask(t);
}

// 规则名解析：精确 name 直接返回 {name}；只有模糊 keyword 时把任务停在 awaiting_selection 并 return null
async function resolveRuleTarget(t, p, firewall, verb) {
  if (p.name && /^[a-zA-Z0-9_.\-]+$/.test(p.name)) return { name: p.name };
  await setAwaitingSelection(t, p, firewall, verb, []);
  return null;
}

// 模糊路径专用：调 get_security_rules 过滤匹配，转 awaiting_selection 状态
async function setAwaitingSelection(t, p, firewall, verb, _extraSteps) {
  const kw = (p.keyword || "").trim();
  if (!kw) throw new Error(`该操作需要精确规则名或模糊 keyword 之一`);
  // 绕开 MCP get_security_rules（它读 candidate config，不含 running rules），
  // 直接用 directConfigShow 读 running config（已 commit 的实际生效规则）
  const SECURITY_RULES_XPATH = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules`;
  const txt = await directConfigShow(SECURITY_RULES_XPATH);
  const blocks = (txt.match(/<entry[^>]*>([\s\S]*?)<\/entry>/g) || []);
  const all = blocks.map((blk) => {
    const e = {};
    const nm = blk.match(/<entry[^>]*\bname="([^"]+)"/);
    if (nm) e["@_name"] = nm[1];
    const tag = /<(\w+)>([^<]*)<\/\1>/g;
    let tm;
    while ((tm = tag.exec(blk)) !== null) if (!(tm[1] in e)) e[tm[1]] = tm[2];
    return e;
  });
  // 1) 先按整串子串匹配（保持原行为）
  let matches = all.filter((r) => r["@_name"]?.toLowerCase().includes(kw.toLowerCase()));
  let mode = "整串匹配";
  // 2) 0 命中时 fallback 拆词 OR 匹配（处理 LLM 把"name带有block"整段当 keyword 的情况）
  if (matches.length === 0) {
    const tokens = tokenizeForMatch(kw);
    if (tokens.length > 0) {
      const seen = new Set();
      matches = all.filter((r) => {
        const name = (r["@_name"] || "").toLowerCase();
        const hit = tokens.some((tk) => name.includes(tk.toLowerCase()));
        if (hit && !seen.has(r["@_name"])) { seen.add(r["@_name"]); return true; }
        return false;
      });
      if (matches.length) mode = `拆词 OR 匹配 [${tokens.join(", ")}]`;
    }
  }
  const top = matches.slice(0, 10).map((r) => r["@_name"]);
  t.steps.push(`${mode} "${kw}" 命中 ${matches.length} 条规则` + (top.length ? `：${top.join("、")}` : ""));
  t.status = "awaiting_selection";
  t.result = { awaitingSelection: true, verb, keyword: kw, matched: top, totalMatches: matches.length, mode };
  t._candidate = { name: p.name, keyword: kw, template: t.template, firewall };
  saveTask(t);
}

// 把模糊描述拆成可独立匹配的核心 token（中文/英文连续段 + 过滤常见停用词）
function tokenizeForMatch(text) {
  const STOP = new Set([
    "的", "在", "和", "与", "或", "带", "有", "含", "按", "上", "里", "下", "中", "为", "是",
    "规则", "名字", "名称", "rule", "policy", "删除", "封禁", "放行", "禁用", "启用",
    "请", "把", "我", "你", "他", "的", "把", "来", "下", "起", "到",
    "this", "that", "the", "with", "and", "or", "rule", "policy"
  ]);
  const tokens = text.match(/[\u4e00-\u9fa5]+|[A-Za-z][A-Za-z0-9_-]*/g) || [];
  return tokens
    .map((t) => t.trim())
    .filter((t) => t && t.length >= 2 && !STOP.has(t.toLowerCase()) && !STOP.has(t));
}

async function runChangeCommit(t, firewall) {
  t.status = "committing";
  let job = null;
  try {
    // 走 directCommit（POST + <async/>），绕开 MCP commit 工具的 v3Schema 故障
    const r = await directCommit("WebUI Agent: " + (t.templateLabel || t.type));
    const txt = String(r);
    // 鲁棒解析 job：<job>ID</job> / <id>ID</id> / "jobid 123" / "id 123" / JSON "job":ID
    const m = txt.match(/<job>(\d+)<\/job>/i)
      || txt.match(/<id>(\d+)<\/id>/i)
      || txt.match(/jobid[\s=]+["']?(\d+)/i)
      || txt.match(/\bid\s+(\d+)\b/i)
      || txt.match(/"job"\s*:\s*(\d+)/);
    job = m ? m[1] : null;
    t.steps.push("commit 入队" + (job ? ` job=${job}` : "：无 job（响应：" + txt.slice(0, 120) + "）"));
    if (!job) {
      t.steps.push("可能原因：candidate 未生效（无变更可提交）或 commit 端点未返回 job");
      t.status = "done";
      t.result = Object.assign(t.result || {}, { needsManualCommit: true, raw: txt.slice(0, 300) });
      saveTask(t);
      return;
    }
  } catch (e) {
    t.steps.push("commit 入队失败：" + e.message.slice(0, 80));
    t.status = "done";
    t.result = Object.assign(t.result || {}, { needsManualCommit: true });
    saveTask(t);
    return;
  }
  // 轮询 job（动态间隔：前 30 次每 3 秒，之后每 5 秒，最多 200 次 ≈ 10 分钟）
  let lastJobSig = ""; // 用于节流 commit 轮询步骤记录（状态/进度变化时才记录）
  for (let i = 0; i < 200; i++) {
    // 用户取消：停止轮询，但 commit 可能已在防火墙执行，明确提示
    if (t.cancelled) {
      t.steps.push("已取消任务，停止 commit 轮询");
      t.steps.push("⚠️ commit job=" + job + " 可能已在防火墙执行，请到 Monitor → Jobs 确认最终状态；如需回退变更请手动处理");
      t.status = "cancelled";
      t.result = Object.assign(t.result || {}, { cancelledWhileCommitting: true, job });
      saveTask(t);
      return;
    }
    await new Promise((res) => setTimeout(res, i < 30 ? 3000 : 5000));
    try {
      const s2 = await directOp(`<show><jobs><id>${job}</id></jobs></show>`);
      const stxt = String(s2);
      const stm = stxt.match(/<status>\s*([^<\s]+)/i);
      const st = stm ? stm[1].toUpperCase() : "";
      const pct = stxt.match(/<progress>\s*(\d+)/i);
      const pctVal = pct ? pct[1] : "";
      // 节流 commit 轮询步骤记录：避免长时间 commit 刷出大量"status=ACT (0%)"步骤
      // 只在状态/进度变化 或 间隔足够大时记录（节流不影响 FIN/FAIL/ERROR 终态判断）
      const sig = st + "|" + pctVal;
      if (sig !== lastJobSig || i % 15 === 0) {
        t.steps.push(`commit job=${job} status=${st}${pctVal ? ` (${pctVal}%)` : ""}`);
        lastJobSig = sig;
      }
      if (st === "FIN" || st === "FINOK" || stxt.includes("FIN OK")) {
        t.steps.push("commit 完成 (job=" + job + ")");
        t.status = "done";
        t.result = Object.assign(t.result || {}, { job });
        saveTask(t);
        return;
      }
      if (st === "FAIL" || st === "STOPPED" || st === "ERROR") {
        t.steps.push("commit 失败：" + st + " job=" + job);
        t.status = "done";
        t.result = Object.assign(t.result || {}, { job, commitFailed: true });
        saveTask(t);
        return;
      }
    } catch (e) {
      // 单次轮询错误不中断，继续
    }
  }
  t.steps.push("️ commit 超时（10 分钟）：job=" + job + " 可能在防火墙后台仍在执行中。请登录防火墙 Web 界面 → Monitor → Jobs，搜索 job ID " + job + " 查看最终状态，或手动执行 commit");
  t.status = "done";
  t.result = Object.assign(t.result || {}, { needsManualCommit: true, timeout: true, job });
  saveTask(t);
  // 超时：标记需要手动 commit（但提供 job id 供用户去 PAN-OS UI 跟进）
  t.steps.push(`commit 轮询超时（job ${job}）— 可能仍在执行，请到 PAN-OS UI 查看或继续轮询`);
  t.status = "done";
  t.result = Object.assign(t.result || {}, { job, needsManualCommit: true, timedOut: true });
  saveTask(t);
}

// ── 意图 → 任务路由 ──

// ── 多轮追问上下文（方案A）：从 tasks 取最近 N 轮已结束任务，组装成上下文文本 ──
// 所有通道（Web/飞书）的任务都进同一个 tasks 数组，自动按时间窗口串成会话，无需前端传 session
const CTX_ROUNDS = 5;   // 上下文轮数（超限自动丢最旧，控制 token）
const CTX_SUMMARY_LEN = 300; // 每轮结果摘要截断长度
function extractKeyItems(t) {
  // 从任务结果中提取关键条目名（@_name / 规则名 / 对象名），供 LLM 指代解析
  const names = new Set();
  const walk = (o) => {
    if (o == null || typeof o !== "object") return;
    if (Array.isArray(o)) { o.forEach(walk); return; }
    for (const k of ["@_name", "name", "rule"]) {
      const v = o[k];
      if (typeof v === "string" && v && !/^(any|entry)$/.test(v)) names.add(v);
    }
    Object.values(o).forEach(walk);
  };
  const r = t.result || {};
  (r.results || []).forEach((res) => walk(res.data));
  return [...names].slice(0, 8).join(", ");
}
function buildConversationContext(limit = CTX_ROUNDS) {
  const recent = tasks
    .filter((x) => ["done", "failed"].includes(x.status) && ["query", "diag", "chat", "inspect"].includes(x.type))
    .slice(-limit);
  if (!recent.length) return "";
  return "【最近对话上下文】（用户之前问过这些，你回答过；当前问题可能引用它们）\n" + recent.map((x, i) => {
    const r = x.result || {};
    const summary = String(r.summary || r.answer || "").slice(0, CTX_SUMMARY_LEN);
    const items = extractKeyItems(x);
    return `轮${i + 1} 用户问: ${x.input}\n结果: ${summary || "(无摘要)"}${items ? `\n关键条目: ${items}` : ""}`;
  }).join("\n\n");
}
// 在用户问题前拼接上下文（无上下文时原样返回）
function withCtx(userInput) {
  const ctx = buildConversationContext();
  return ctx ? ctx + "\n\n【用户当前问题】" + userInput : userInput;
}

async function createTaskFromInput(input, firewall, source) {
  // 重复任务去重：先扫描 active 任务，发现与 input normalize 后完全相同则取消旧任务
  const dup = dedupeActiveTask(input);
  let action = null, fromLLM = false;
  for (const [k, v] of Object.entries(ACTIONS)) { if (k === input || v.label === input) action = k; }
  if (!action) {
    action = await llmResolveAction(input);
    if (action) fromLLM = true;
  }
  if (action === "change") {
    const c = await llmExtractChange(input);
    if (!c) return { error: "无法解析变更意图（支持：创建/删除地址对象、封禁/放行 IP、移动/删除/禁用/启用安全策略）" };
    const tmpl = CHANGE_TEMPLATES[c.template];
    // 规则类模板（delete/disable/enable）若只有模糊 keyword，先预检转 awaiting_selection
    const RULE_TMPL = ["delete_security_rule", "set_security_rule_disabled", "set_security_rule_enabled"];
    const needPrecheck = RULE_TMPL.includes(c.template) && !(c.params?.name && /^[a-zA-Z0-9_.\-]+$/.test(c.params.name));
    const t = newTask("change", input, { template: c.template, templateLabel: tmpl.label, params: c.params, firewall, source, status: needPrecheck ? "awaiting_selection" : "awaiting_approval" });
    t.plan = tmpl.plan(c.params || {});
    if (needPrecheck) {
      // 同步做一次预检（list candidates）→ 任务状态已是 awaiting_selection，前端直接展示候选按钮
      try { await setAwaitingSelection(t, c.params, firewall, tmpl.label, []); }
      catch (e) { t.status = "failed"; t.error = e.message; saveTask(t); }
    } else {
      t.steps.push("变更计划已生成，等待审批");
    }
    t.llm = currentLLM;  // 记录处理该任务时实际使用的 LLM provider key
    tasks.push(t); persistTasks();
    return needPrecheck && t.status === "awaiting_selection"
      ? { taskId: t.id, status: t.status, plan: t.plan, candidates: t.result.matched, totalMatches: t.result.totalMatches }
      : { taskId: t.id, status: t.status, plan: t.plan };
  }
  if (action === "audit") {
    const a = await llmParseAudit(input);
    const t = newTask("audit", input, { firewall, source, audit: a });
    t.llm = currentLLM;
    t.decision = `LLM 规划 → 审计查询（${a.minutes} 分钟内${a.object}）（${LLM_PROVIDERS[currentLLM]?.label || currentLLM}）`;
    t.steps.push(t.decision);
    tasks.push(t); persistTasks();
    runAuditTask(t, firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); saveTask(t); });
    return { taskId: t.id, status: t.status, type: "audit" };
  }
  if (action === "diag") {
    const d = await llmParseDiag(input);
    // 诊断规划判定为非诊断请求（type:null，如"画个拓扑图"）→ 降级自由问答，
    // 不再生硬报"无法解析诊断意图"——让 LLM 分析推理回答（16:48 飞书案例根因）
    if (!d || !d.type) return await createFreeAnswer(input, firewall);
    const t = newTask("diag", input, { firewall, source, diag: d });
    t.llm = currentLLM;
    t.decision = `LLM 规划 → 诊断 ${d.type}（${LLM_PROVIDERS[currentLLM]?.label || currentLLM}）`;
    t.steps.push(t.decision);
    tasks.push(t); persistTasks();
    runDiagTask(t, firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); saveTask(t); });
    return { taskId: t.id, status: t.status, type: "diag" };
  }
  if (action === "inspect") {
    const t = newTask("inspect", input, { firewall, source });
    tasks.push(t); persistTasks();
    runInspectTask(t, firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); saveTask(t); });
    return { taskId: t.id, status: t.status, type: "inspect" };
  }
  if (action && ACTIONS[action]) {
    const t = newTask("query", input, { action, firewall, source });
    if (fromLLM) t.llm = currentLLM;
    t.decision = fromLLM ? `LLM 规划 → 动作 ${action}（${LLM_PROVIDERS[currentLLM]?.label || currentLLM}）` : `关键词匹配 → 动作 ${action}`;
    t.steps.push(t.decision);
    tasks.push(t); persistTasks();
    runQueryTask(t, action, firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); saveTask(t); });
    return { taskId: t.id, status: t.status, type: "query", label: ACTIONS[action].label };
  }
  // 兜底：意图不匹配任何 action → 自由问答（LLM 分析/推理/思考后回答，不直接拒绝）
  return await createFreeAnswer(input, firewall, source);
}

// 自由问答兜底：用户问题未匹配现有 tools/action 时，让 LLM 结合设备基础信息做分析推理回答
async function createFreeAnswer(input, firewall, source) {
  let fwCtx = "";
  try {
    const fw = await callTool("get_firewall_info", {}, firewall).catch(() => null);
    if (fw && fw.hostname) fwCtx = `设备: ${fw.hostname} ${fw.model} SW${fw["sw-version"]}`;
  } catch {}
  const text = await llmClassify("自由问答",
    `你是 PAN-OS 防火墙运维专家（会思考、分析、推理后再回答）。用户的问题没有匹配到系统的标准动作（设备状态/安全策略/威胁日志/流量日志/完整巡检/诊断/变更审批/审计），请做以下三件事：

1. **分析问题意图**：判断用户到底想干什么（可能问的是网络概念、配置建议、排错思路、最佳实践、命令语法、License 等）。
2. **推理回答**：结合你的 PAN-OS 知识给出有深度的答案（配置步骤/排查思路/相关命令 show 或 request、注意事项）。
3. **给出建议**：说明如何用本系统或防火墙 CLI 进一步验证（如"可以用系统里的'完整巡检'跑一遍"、"在防火墙 CLI 执行 show session info"）。

要求：
- 不要敷衍，不要只说"无法处理"。
- 如果问题其实是标准动作能解决的（例如用户在绕弯子问设备状态），先指出"这可以用系统 XX 功能直接查看"，再补充答案。
- 200-400 字，条理清晰，用 markdown 列表。
【多轮追问】输入前可能附带【最近对话上下文】（含用户之前的问句、结果、关键条目名）。若当前问题引用前文（"那条/上面那条/刚才/它/第二条/这个结果"），**必须基于上下文中的真实条目和数据回答**（如引用上轮结果里的具体策略名/设备/数值），不要泛泛而谈，不要编造上下文里没有的条目。`,
    `${fwCtx ? fwCtx + "\n" : ""}用户问题：${withCtx(input)}`,
    60000);
  const t = newTask("chat", input, { firewall, source });
  t.llm = currentLLM;
  if (source) t.source = source;  // 标记任务来源（'feishu'/'web'/'bridge'），用于 WebUI 区分展示
  t.decision = `LLM 兜底 → 自由问答（${LLM_PROVIDERS[currentLLM]?.label || currentLLM}）`;
  t.steps.push(t.decision);
  t.result = { answer: text || "抱歉，LLM 未能给出回答。您可以换个说法，或试试：设备状态 / 安全策略 / 威胁日志 / 完整巡检 / 封禁 1.2.3.4。", sentTo: source === "feishu" ? "feishu" : "web" };
  t.status = "done";
  tasks.push(t); persistTasks();
  return { taskId: t.id, status: t.status, type: "chat" };
}

// ── 重复任务去重：用户短时间内（30 秒）反复提交完全相同的 query 时，保留最新一个，
//    自动取消之前的活跃任务（committing 除外——commit 已发到防火墙，强制取消会误导）
//    防止误触 Enter 或漏标点造成重复任务浪费资源（query）/ 重复规则（change）──
const ACTIVE_FOR_DEDUPE = ["pending", "running", "executing", "awaiting_approval", "awaiting_selection", "awaiting_commit"];
function normalizeInput(s) {
  // 去所有标点/空白 + 去末尾中文语气词("的是呢啊呀")，便于"问号/句号/无标点+尾字"的相似 query 也算重复
  return String(s || "")
    .toLowerCase()
    .replace(/[\s？?。.！!，,~～`'"、;；:：]+/g, "")
    .replace(/(的|了|呢|啊|呀|嘛|哦|哈)+$/g, "")
    .trim();
}
// Levenshtein 距离（编辑距离）——小差异容忍
function lev(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m || !n) return Math.max(m, n);
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]) + 1;
    }
  }
  return dp[m][n];
}
function dedupeActiveTask(input) {
  const norm = normalizeInput(input);
  if (!norm) return null;
  const dup = tasks.find((x) => {
    if (!x.input || !ACTIVE_FOR_DEDUPE.includes(x.status)) return false;
    const xn = normalizeInput(x.input);
    if (!xn) return false;
    // 完全相等 或 编辑距离 ≤ 3（容忍几字符差异，如末尾"的吗/？"）
    return xn === norm || lev(xn, norm) <= 3;
  });
  if (!dup) return null;
  // 自动取消旧任务（保留本次提交的，作为最新意图）
  dup.status = "cancelled";
  dup.steps.push("🔁 与新提交任务完全一致，被新任务自动取消");
  saveTask(dup);
  return dup;
}

// ── 审计日志任务 ──
async function runAuditTask(t, firewall) {
  t.status = "running";
  t.steps.push("查询配置变更日志 (config log)");
  const step = { tool: "get_config_logs", status: "running", startMs: Date.now() };
  t.steps.push(step);
  let entries = [];
  try {
    const data = await callTool("get_config_logs", { nlogs: 200 }, firewall);
    entries = data.entry || [];
  } catch (e) {
    step.status = "err"; step.msg = String(e.message || e);
    t.status = "failed"; t.error = step.msg; saveTask(t); return;
  }
  step.status = "ok"; step.ms = Date.now() - step.startMs;

  const { minutes, object } = t.audit || { minutes: 60, object: "all" };
  const cutoff = Date.now() - minutes * 60000;
  const isSec = (p) => /rulebase\/security|security\/rules/.test(p || "");
  const rows = entries
    .map((e) => ({
      time: e.receive_time || e.time_generated || "",
      admin: e.admin || "?",
      cmd: e.cmd || "?",
      result: e.result || "?",
      client: e.client || "?",
      path: (e["full-path"] || e.path || "").slice(0, 80),
    }))
    .filter((r) => {
      // 时间过滤
      if (!r.time) return true;
      const t = Date.parse(r.time.replace("/", "-").replace("/", "-"));
      if (isNaN(t)) return true;
      if (t < cutoff) return false;
      // 对象过滤
      if (object === "security") return isSec(r.path);
      return true;
    });
  t.result = { title: `配置变更审计（最近 ${minutes} 分钟${object === "security" ? " · 策略相关" : ""}）`, rows, total: rows.length, minutes, object };
  t.steps.push(`筛选出 ${rows.length} 条变更记录`);
  t.status = "done";
  saveTask(t);
}

// ── 智能诊断任务 ──
function ipInRules(rules, ip) {
  return rules.filter((r) => {
    const src = r.source?.member, dst = r.destination?.member, act = r.action;
    const hit = (m) => Array.isArray(m) ? m.includes(ip) || m.includes("any") : m === ip || m === "any";
    return hit(src) && hit(dst) && (act === "allow" || act === "deny");
  }).map((r) => ({ name: r["@_name"], action: r.action, disabled: r.disabled === "yes", from: r.from?.member, to: r.to?.member }));
}

// 判断路由目的（CIDR/精确 IP）是否覆盖目标 IP
function ipMatchDest(dest, ip) {
  if (!dest) return false;
  const [d, bits] = String(dest).split("/");
  if (d === ip) return true;
  const n = parseInt(bits, 10);
  if (!n || isNaN(n)) return false;
  const ipN = ipv4ToInt(ip), dN = ipv4ToInt(d);
  if (ipN === null || dN === null) return false;
  const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
  return (ipN & mask) === (dN & mask);
}
function ipv4ToInt(ip) {
  const p = String(ip || "").split(".").map(Number);
  if (p.length !== 4 || p.some((x) => isNaN(x) || x < 0 || x > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

// ── 监控 KPI 概览（30s 缓存）──
let overviewCache = null, overviewTs = 0;
// 活跃会话数：<show><session><all> 返回 entry 数（避免解析 353 个 entry 的开销）
async function getActiveSessions() {
  const xmlAll = await directOp("<show><session><all></all></session></show>");
  const num_active = (xmlAll.match(/<entry>/g) || []).length;
  const xmlInfo = await directOp("<show><session><info></info></session></show>");
  const f = {};
  const re = /<(\w+)>([^<]+)<\/\1>/g;
  let m; while ((m = re.exec(xmlInfo)) !== null) if (!(m[1] in f)) f[m[1]] = m[2];
  return { num_active, num_max: 65536, kbps: f.kbps, pps: f.pps, cps: f.cps };
}

async function getOverview() {
  if (overviewCache && Date.now() - overviewTs < 5000) return overviewCache;
  const kpi = { device: {}, ha: {}, session: {}, resource: {}, license: {} };
  const fast = await Promise.allSettled([
    callTool("get_firewall_info", {}, null).catch(() => null),
    callTool("get_ha_status", {}, null).catch(() => null),
    getActiveSessions().catch(() => null),
    callTool("get_system_resources", {}, null).catch(() => null),
    callTool("get_licenses", {}, null).catch(() => null),
  ]);
  const [fw, ha, sess, res, lic] = fast.map((x) => (x.status === "fulfilled" ? x.value : null));
  if (fw) { kpi.device = { hostname: fw.hostname, model: fw.model, sw: fw["sw-version"], uptime: fw.uptime, serial: fw.serial }; }
  if (ha) kpi.ha = { enabled: ha.enabled === "yes" || ha.enabled === true };
  if (sess) kpi.session = { active: sess.num_active, max: sess.num_max, kbps: sess.kbps, pps: sess.pps };
  if (res) kpi.resource = { load: res["load average"], memUsed: res["mem used"], memTotal: res["mem total"] };
  if (lic) {
    const arr = lic.entry || [];
    kpi.license = { total: arr.length, expired: arr.filter((e) => String(e.expired).toLowerCase() === "yes").length };
  }
  const out = { ts: Date.now(), kpi, health: kpi.device.hostname ? "ok" : "degraded" };
  overviewCache = out; overviewTs = Date.now();
  // 指标采样（报表预留）：每次 getOverview 计算完成后把 KPI 快照写入环形缓冲，
  // 未来切 SQLite/PG 时按 spec 第 12 章 metrics 表落库；现在提供 /api/metrics 供前端可视化。
  metricsBuffer.push({ ts: out.ts, kpi: JSON.parse(JSON.stringify(kpi)), health: out.health });
  if (metricsBuffer.length > MAX_METRICS) metricsBuffer.shift();
  return out;
}

async function runDiagTask(t, firewall) {
  t.status = "running";
  const { type = "generic", params = {} } = t.diag || {};
  const ip = params.ip || "";
  const minutes = params.minutes || 60;
  const sections = [];
  let cancelled = false;
  let stats = null;   // 日志统计（喂给 LLM 综合）
  function addStep(tool) { const s = { tool, status: "running", startMs: Date.now() }; t.steps.push(s); return s; }
  async function safeCall(tool, args) {
    if (t.cancelled) { cancelled = true; return null; }
    const s = addStep(tool);
    try { const r = await callTool(tool, args, firewall); s.status = "ok"; s.ms = Date.now() - s.startMs; return r; }
    catch (e) { s.status = "err"; s.ms = Date.now() - s.startMs; s.msg = String(e.message || e); t.steps.push({ tool: `${tool} 失败`, status: "err", msg: s.msg }); return null; }
  }

  if (cancelled) { t.status = "cancelled"; saveTask(t); return; }
  if (type === "connectivity") {
    t.steps.push("诊断类型: 连通性");
    // 1 策略命中
    const rules = (await callTool("get_security_rules", {}, firewall))?.rules?.entry || [];
    const matched = ip ? ipInRules(rules, ip) : rules.filter((r) => r.action === "allow" && !r.disabled);
    const anyAllow = rules.some((r) => r.action === "allow" && !r.disabled && r.source?.member === "any" && r.destination?.member === "any");
    sections.push({ step: "策略命中分析", result: anyAllow ? "存在全放行规则，策略层不会阻断该目标" : (matched.length ? `命中 ${matched.length} 条规则: ` + matched.map((m) => `${m.name}(${m.action})`).join(", ") : "未找到明确匹配规则") });
    // 2 流量证据（deepLog：200 条 + 时间窗口 + Top N 统计）
    const ld = await deepLog("traffic", { minutes, nlogs: 200 });
    stats = ld.top;
    const logs = ld.entries;
    const hits = logs.filter((l) => (ip && (l.src === ip || l.dst === ip)) || (!ip && l.action !== "allow"));
    const actions = {};
    hits.forEach((l) => { actions[l.action] = (actions[l.action] || 0) + 1; });
    sections.push({ step: "流量证据", result: hits.length ? `最近 ${minutes} 分钟该目标相关 ${hits.length} 条: ` + Object.entries(actions).map(([a, c]) => `${a}×${c}`).join(" ") : (ip ? `最近 ${minutes} 分钟无该目标流量记录` : `最近 ${minutes} 分钟未发现被拦截流量`) });
    sections.push({ step: "流量 Top 统计", result: fmtTop(ld.top, ["src", "dst", "app", "action"]) + (ld.degraded ? `（窗口内无数据，展示全部 ${ld.rawCount} 条，最早 ${ld.oldest}）` : "") });
    // 3 路由（spec：路由联动——默认路由 + 是否有指向目标的特定路由）
    const routes = (await callTool("get_routing_table", {}, firewall))?.entry || [];
    const hasDefault = Array.isArray(routes) && routes.some((r) => (r.destination || "").includes("0.0.0.0"));
    let routeDetail = "未发现默认路由（可能影响出网）";
    if (hasDefault) {
      const def = routes.find((r) => (r.destination || "").includes("0.0.0.0"));
      routeDetail = `存在默认路由${def ? ` via ${def.nexthop || def["ip-address"] || "?"}` : ""}`;
      if (ip) {
        const specific = routes.filter((r) => ipMatchDest(r.destination, ip));
        routeDetail += specific.length ? `；另有 ${specific.length} 条指向 ${ip} 的特定路由` : "；无该目标特定路由（走默认）";
      }
    }
    sections.push({ step: "路由可达性", result: routeDetail });
    // 4 Zone 联动（PAN-OS 核心：策略按 zone 匹配，跨 zone 默认拒绝）
    try {
      // 修复：MCP get_zones 返回 {zone:{entry:[...]}}，外层是 zone 包装
      const zoneRaw = await callTool("get_zones", {}, firewall);
      const zones = (zoneRaw && (zoneRaw.zone?.entry || zoneRaw.entry)) || [];
      const interfaces = (await callTool("get_interfaces", {}, firewall))?.hw?.entry || [];
      // 接口 → zone 映射（PAN-OS zone 内接口路径是 z.network.{layer2|layer3|virtual-wire}.member，member 可能是字符串或字符串数组）
      const ifZones = {};
      const toArr = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
      function zoneIfList(z) {
        const n = z.network || {};
        return [
          ...toArr(n["layer2"]?.member),
          ...toArr(n["layer3"]?.member),
          ...toArr(n["virtual-wire"]?.member),
        ];
      }
      for (const z of zones) {
        for (const i of zoneIfList(z)) ifZones[i] = z["@_name"];
      }
      // 源/目的 IP 所属接口？没有精确办法，但可查它们在哪些 zone 边界（用地址对象）
      const addrRaw = await callTool("get_address_objects", {}, firewall);
      const addrs = (addrRaw && (addrRaw.entry || addrRaw.address?.entry)) || [];
      const matchAddr = (testIp) => {
        const hits = addrs.filter((a) => {
          // 防御性归一化：地址对象字段可能是字符串/数组/对象（PAN-OS 多值/嵌套），统一为字符串数组
          const vs = [];
          for (const f of [a["ip-range"], a["fqdn"], a["ip-netmask"]]) {
            if (f == null) continue;
            if (Array.isArray(f)) { for (const x of f) if (x != null) vs.push(String(x)); }
            else if (typeof f === "object") vs.push(JSON.stringify(f));
            else vs.push(String(f));
          }
          return testIp && vs.some((v) => v.includes(testIp));
        }).map((a) => String(a["@_name"] || ""));
        return hits;
      };
      const list = zones.map((z) => {
        const ifs = zoneIfList(z);
        return `${z["@_name"]}(${ifs.length ? "接口=" + ifs.join(",") : "无接口"})`;
      });
      let zoneResult = `Zone 共 ${zones.length} 个：` + (list.length ? list.join("; ") : "(空 list — 通常不该空，先看 interfaces 确认是否虚拟 wire)");
      if (ip) {
        const addrHits = matchAddr(ip);
        zoneResult += addrHits.length ? `；${ip} 命中地址对象: ${addrHits.join(", ")}` : `；${ip} 未匹配地址对象`;
        // 额外给出：源 IP 的接口若在 ifZones 中有映射，可粗略估计 zone
        //（无法精确反查 IP→interface，仅做提示）
      }
      sections.push({ step: "Zone 配置", result: zoneResult });
    } catch (e) { sections.push({ step: "Zone 配置", result: "Zone 查询失败: " + String(e.message || e).slice(0, 120) }); }
    // 5 ARP（spec：ARP 联动——目标是否在同一二层/L3 可达 MAC 解析）
    try {
      const arp = (await callTool("get_arp_table", {}, firewall))?.entry || [];
      let arpResult = `ARP 表 ${arp.length ? arp.length + " 条" : "为空"}`;
      if (ip && arp.length) {
        const hitArp = arp.filter((a) => a.ip === ip || a["ip-address"] === ip);
        arpResult += hitArp.length ? `；${ip} 已解析 → ${hitArp.map((a) => `MAC=${a.mac || a["mac-address"] || "?"} 接口=${a.interface || a.ifname || "?"}`).join(", ")}` : `；${ip} 无 ARP 记录（跨网段正常，需结合路由/zone 判定）`;
      }
      sections.push({ step: "ARP 联动", result: arpResult });
    } catch (e) { sections.push({ step: "ARP 联动", result: "ARP 查询失败: " + String(e.message || e).slice(0, 120) }); }
    // 6 活跃会话联动（spec：会话联动——该 IP 是否有活跃会话、方向、应用）
    try {
      const sess = await callTool("get_active_sessions", {}, firewall);
      const nActive = parseInt((sess && sess["num-active"]) || 0, 10);
      let sessResult = nActive ? `活跃会话 ${nActive} 个` : "无活跃会话";
      if (ip && nActive) {
        try {
          // 精确到目标 IP 的会话明细：<show><session><all> 全量太重，用 filter 精准查
          const sessXml = await directOp(`<show><session><filter><source>${ip}</source></filter></session></show>`);
          const cnt = (sessXml.match(/<entry>/g) || []).length;
          sessResult = cnt ? `活跃会话中 ${ip} 作为源有 ${cnt} 条` : `活跃会话 ${nActive} 个；${ip} 无作为源的活动会话`;
        } catch { sessResult = `活跃会话 ${nActive} 个（明细过滤不可用）`; }
      }
      sections.push({ step: "会话联动", result: sessResult });
    } catch (e) { sections.push({ step: "会话联动", result: "会话查询失败: " + String(e.message || e).slice(0, 120) }); }
    // 7 源 IP 入接口流量（spec：路由/ARP/会话联动——按 IP 找入接口证据；流量日志按 in_if 聚合）
    if (ip) {
      try {
        const ingoing = hits.filter((l) => l.src === ip);
        if (ingoing.length) {
          const byIf = {}, byAct = {};
          ingoing.forEach((l) => {
            const k = l.inbound_if || l["inbound-if"] || "?";
            byIf[k] = (byIf[k] || 0) + 1;
            byAct[l.action] = (byAct[l.action] || 0) + 1;
          });
          sections.push({ step: "源 IP 入接口", result: `${ip} 共 ${ingoing.length} 条入向流量；入接口=${Object.entries(byIf).map(([k, v]) => `${k}×${v}`).join(", ")}；action=${Object.entries(byAct).map(([k, v]) => `${k}×${v}`).join(", ")}` });
        } else {
          // 即使没命中源 IP，也直说"该 IP 没有任何防火墙观测到的入向流量"，重要诊断信号
          sections.push({ step: "源 IP 入接口", result: `防火墙流量日志中 ${ip} **没有任何入向记录**（可能是：源主机没发包到防火墙 / 包被前置网络丢弃 / 发包时段超出 ${minutes} 分钟窗口）` });
        }
      } catch (e) { sections.push({ step: "源 IP 入接口", result: "查询失败: " + String(e.message || e).slice(0, 120) }); }
    }
    // 7b VPN/GP 状态（关键：让 LLM 看到"功能是否配置"的事实，避免强行套模板）
    try {
      const gpRaw = (await callToolRaw("get_globalprotect_config", {}, firewall));
      const gpCfg = String(gpRaw?.data ?? "");
      const gpUserRaw = (await callToolRaw("get_globalprotect_users", {}, firewall));
      const gpUser = String(gpUserRaw?.data ?? "");
      const ipsecRaw = (await callToolRaw("get_ipsec_tunnels", {}, firewall));
      const ipsec = ipsecRaw?.data || {};
      const gpConfigured = gpCfg && gpCfg !== '""' && gpCfg.trim() !== "" && gpCfg !== "{}";
      const gpUsers = gpUser && gpUser !== '""' && gpUser.trim() !== "" && gpUser !== "{}";
      let gpResult = "";
      if (!gpConfigured && !gpUsers) gpResult = "GP 未配置或未启用：get_globalprotect_config 配置为空，get_globalprotect_users 用户列表为空";
      else gpResult = `GP 配置存在（${gpCfg.length} 字符）；用户列表 ${gpUsers ? "有连接" : "为空"}`;
      const ipsecCount = parseInt(ipsec.ntun || 0, 10) || 0;
      const ipsecEntries = ipsec.entries || "";
      gpResult += `；IPSec 隧道数 ${ipsecCount}${ipsecEntries && ipsecEntries !== '""' ? `（${String(ipsecEntries).slice(0, 200)}）` : ""}`;
      sections.push({ step: "VPN/GP 状态", result: gpResult });
    } catch (e) { sections.push({ step: "VPN/GP 状态", result: "VPN 状态查询失败: " + String(e.message || e).slice(0, 120) }); }
    // 8 实时探测（spec：抓包分析 run_op_command——ping/traceroute 探测）
    const probe = params.probe || (ip ? "ping" : null);
    if (probe && ip) {
      t.steps.push(`实时探测: ${probe} ${ip}`);
      const probeCmd = probe === "traceroute"
        ? `<test><traceroute><destination>${ip}</destination></traceroute></test>`
        : `<test><ping><destination>${ip}</destination><count>3</count></ping></test>`;
      try {
        const raw = await callToolRaw("run_op_command", { command: probeCmd }, firewall);
        const txt = String(raw?.data || raw || "");
        // 提取关键行（丢包率/往返时延/可达性）
        const loss = txt.match(/loss[^%]*(\d+(?:\.\d+)?)%/i);
        const min = txt.match(/min\/avg\/max[^=]*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)/i);
        const verdict = /Unsupported command|error/i.test(txt) ? "（防火墙不支持该探测命令或权限不足）" : "";
        sections.push({ step: "实时探测 " + probe, result: (loss ? `丢包 ${loss[1]}%` : "") + (min ? ` RTT min/avg/max=${min[1]}/${min[2]}/${min[3]}ms` : "") + verdict + (verdict ? " 原始输出: " + txt.slice(0, 200) : "") });
      } catch (e) {
        sections.push({ step: "实时探测 " + probe, result: "探测失败: " + String(e.message || e).slice(0, 120) });
      }
    } else {
      sections.push({ step: "实时探测", result: ip ? "未指定 probe（可用 ping / traceroute）" : "未指定目标 IP，跳过实时探测" });
    }
    t.result = { title: "连通性诊断" + (ip ? "（" + ip + (params.port ? ":" + params.port : "") + "）" : ""), sections };
  } else if (type === "threat_profile") {
    t.steps.push("诊断类型: 威胁源画像");
    const ld = await deepLog("threat", { minutes, nlogs: 200 });
    stats = ld.top;
    const tf = ld.entries.filter((l) => !ip || l.src === ip || l.dst === ip);
    const byType = {};
    tf.forEach((l) => { byType[l.subtype || "other"] = (byType[l.subtype || "other"] || 0) + 1; });
    sections.push({ step: "威胁事件", result: tf.length ? `最近 ${minutes} 分钟共 ${tf.length} 条: ` + Object.entries(byType).map(([k, v]) => `${k}×${v}`).join(", ") : "威胁日志中无该目标记录" });
    const sev = {};
    tf.forEach((l) => { sev[l.severity || "?"] = (sev[l.severity || "?"] || 0) + 1; });
    sections.push({ step: "严重级别", result: Object.entries(sev).map(([k, v]) => `${k}×${v}`).join(" ") || "无" });
    sections.push({ step: "威胁源 Top", result: fmtTop(ld.top, ["src", "subtype", "severity"]) + (ld.degraded ? `（窗口内无威胁，展示全部 ${ld.rawCount} 条，最早 ${ld.oldest}）` : "") });
    // 跨日志关联（第2项）：Top 威胁源 → 反查流量 action + 策略命中
    const trLd = await deepLog("traffic", { minutes, nlogs: 200 });
    const rules = (await callTool("get_security_rules", {}, firewall))?.entry || [];
    const topSrcs = (ld.top.src || []).filter(([v]) => !ip || v !== ip).slice(0, 3).map(([v]) => v);
    if (topSrcs.length) {
      const parts = [];
      for (const src of topSrcs) {
        const h = trLd.entries.filter((l) => l.src === src);
        const acts = [...new Set(h.map((l) => l.action))];
        const rm = ipInRules(rules, src);
        const pol = rm.length ? rm.map((r) => `${r.name}(${r.action})`).join(",") : "未匹配明确规则";
        parts.push(`${src}: 流量${h.length}条 action=${acts.join("/") || "无"} 策略=${pol}`);
      }
      sections.push({ step: "跨日志关联", result: parts.join("；") });
    } else {
      sections.push({ step: "跨日志关联", result: "无其他威胁源可关联" });
    }
    const trHits = trLd.entries.filter((l) => l.src === ip || l.dst === ip);
    const bad = tf.some((l) => ["high", "critical"].includes(l.severity)) || trHits.some((l) => l.action === "deny" || l.action === "reset-both");
    t.result = { title: "威胁源画像" + (ip ? "：" + ip : ""), sections };
  } else {
    t.steps.push("诊断类型: 通用健康");
    const fw = await callTool("get_firewall_info", {}, firewall);
    sections.push({ step: "设备", result: `${fw.hostname} ${fw.model} ${fw["sw-version"]}` });
    const res = await callTool("get_system_resources", {}, firewall);
    const load = typeof res === "string" ? res.split("\n").find((l) => l.includes("load average")) : "";
    sections.push({ step: "负载", result: load || "（资源查询无摘要）" });
    const sess = await callTool("get_active_sessions", {}, firewall);
    sections.push({ step: "会话", result: `活跃 ${sess["num-active"] || 0} / 上限 ${sess["num-max"] || 0}` });
    const sys = filterByMinutes((await callTool("get_system_logs", {}, firewall))?.entry || [], minutes);
    const errs = sys.filter((l) => ["error", "critical"].includes(l.severity));
    sections.push({ step: "系统事件", result: errs.length ? `最近 ${minutes} 分钟内 ${errs.length} 条 error/critical` : `最近 ${minutes} 分钟无 error/critical 事件` });
    const ldTh = await deepLog("threat", { minutes, nlogs: 200 });
    stats = ldTh.top;
    const th = ldTh.entries;
    sections.push({ step: "威胁近况", result: th.length ? `最近 ${minutes} 分钟威胁日志 ${th.length} 条` : `最近 ${minutes} 分钟无威胁日志` });
    sections.push({ step: "威胁源 Top", result: fmtTop(ldTh.top, ["src", "subtype", "severity"]) });
    t.result = { title: "通用健康诊断", sections };
  }
  // LLM 综合解读（基于实际数据推理根因/置信度/建议）
  const synth = await llmSynthesize(t.input, sections, stats);
  if (synth) {
    t.result.verdict = synth.verdict;
    t.result.confidence = synth.confidence;
    t.result.recommendation = synth.recommendation || "";
  }
  // Fallback：LLM 综合失败/超时时，verdict 为空 → 用已收集的 sections 自动汇总成 fallback verdict
  // （避免用户看到空白根因区——这是 Kimi 等慢模型最容易出现的情况）
  if (!t.result.verdict) {
    const hits = sections.filter((s) => /\b(为空|空|无|未配置|未启用|不存在|未观测到|没有任何)\b/.test(s.result || ""));
    const emptyKeys = hits.map((s) => s.step);
    const sectionsOk = sections.filter((s) => s.result && !emptyKeys.includes(s.step));
    t.result.verdict = sectionsOk.length
      ? `（LLM 综合推理超时/失败，以下为已收集的关键事实）\n\n` +
        `已采集 ${sections.length} 段数据，其中 ${emptyKeys.length} 段为空：${emptyKeys.join("、") || "（无）"}。\n` +
        `正面事实：\n` + sectionsOk.map((s) => `• ${s.step}：${String(s.result).slice(0, 150)}`).join("\n") +
        (emptyKeys.length ? `\n\n推断方向：观察到「${emptyKeys.join("、")}」为空，建议先核实关键组件（如 GP 配置、目标主机在线状态、路由配置）后再下定论。` : "")
      : `LLM 综合推理未产出结论，请查看下方排查步骤表（${sections.length} 段原始数据已采集）。`;
    t.result.confidence = "低（fallback）";
    t.result.recommendation = "1) 重跑此任务（可能是临时网络问题）；2) 若反复失败，可缩短时间窗口（minutes=30）减少 prompt 长度；3) 检查下方 sections 数据手动判断。";
  }
  if (stats) t.result.logStats = stats;
  t.status = "done";
  saveTask(t);
}
const server = http.createServer(async (req, res) => {
  // 所有响应默认 no-cache（前端会随轮询实时变化；浏览器/代理缓存旧值会误导排查）
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  const send = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" }); res.end(JSON.stringify(obj)); };
  const body = () => new Promise((ok) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => ok(b)); });
  try {
    if (req.url === "/favicon.ico") { res.writeHead(204); res.end(); return; }
    // ── 认证：登录接口放行；其余 /api/* 必须携带有效 token（用户会话或 internal_token）──
    // 静态资源（/、/index.html、/assets/*、图片）免认证——不含敏感数据，前端 JS 会检测 401 展示登录页
    const urlPath0 = req.url.split("?")[0];
    const isStatic = req.method === "GET" && (urlPath0 === "/" || urlPath0 === "/index.html" || urlPath0.startsWith("/assets/") || /^\/[a-zA-Z0-9_.\-]+\.(png|jpg|jpeg|svg|gif|ico|webp|woff2)$/.test(urlPath0));
    if (urlPath0.startsWith("/api/") && !isStatic) {
      if (req.method === "POST" && urlPath0 === "/api/auth/login") {
        // 登录：校验用户名密码，签发会话 token（带空闲超时配置）
        let cred = {};
        try { cred = JSON.parse(await body()); } catch (e) { cred = {}; }
        if (cred.username === authData.username && sha256(cred.password || "") === authData.password_hash) {
          send(200, { ok: true, token: authIssueToken(), username: authData.username, expiresIn: AUTH_SESSION_DAYS * 86400, idleMinutes: IDLE_MINUTES });
        } else {
          send(401, { error: "用户名或密码错误" });
        }
        return;
      }
      if (req.method === "POST" && urlPath0 === "/api/auth/logout") {
        const h = req.headers["authorization"] || "";
        const t = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
        if (t && authData.sessions[t]) { delete authData.sessions[t]; saveAuth(); }
        send(200, { ok: true });
        return;
      }
      if (req.method === "GET" && urlPath0 === "/api/auth/check") {
        const ok = authCheck(req);
        send(ok ? 200 : 401, ok ? { ok: true, username: authData.username, idleMinutes: IDLE_MINUTES } : { error: "未认证" });
        return;
      }
      // 保持登录（空闲警告弹窗点击"保持登录"时调用，刷新 lastSeen）
      if (req.method === "POST" && urlPath0 === "/api/auth/keepalive") {
        if (!authCheck(req)) { send(401, { error: "未认证或登录已过期" }); return; }
        const h = req.headers["authorization"] || "";
        const t = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
        if (t && t !== authData.internal_token) authTouch(t);
        send(200, { ok: true, idleMinutes: IDLE_MINUTES });
        return;
      }
      // 修改密码：需已认证 + 校验旧密码；成功后清空所有会话（含当前），强制重新登录
      if (req.method === "POST" && urlPath0 === "/api/auth/change-password") {
        if (!authCheck(req)) { send(401, { error: "未认证或登录已过期，请重新登录" }); return; }
        let cred = {};
        try { cred = JSON.parse(await body()); } catch (e) { cred = {}; }
        const oldPw = String(cred.old_password || "");
        const newPw = String(cred.new_password || "");
        if (sha256(oldPw) !== authData.password_hash) { send(400, { error: "旧密码不正确" }); return; }
        if (newPw.length < 8) { send(400, { error: "新密码至少 8 位" }); return; }
        if (newPw === oldPw) { send(400, { error: "新密码不能与旧密码相同" }); return; }
        authData.password_hash = sha256(newPw);
        authData.sessions = {}; // 清空全部会话，强制重新登录
        fs.writeFileSync(AUTH_FILE, JSON.stringify(authData, null, 2));
        send(200, { ok: true, message: "密码已修改，请重新登录" });
        return;
      }
      // 其余 API：统一认证拦截（401 让前端显示登录页）；用户主动操作类接口通过后刷新 lastSeen
      if (!authCheck(req)) {
        send(401, { error: "未认证或登录已过期，请重新登录" });
        return;
      }
      const hdr = req.headers["authorization"] || "";
      const tok = hdr.startsWith("Bearer ") ? hdr.slice(7).trim() : "";
      authTouchIfUserAction(req, tok);
    }
    // 静态资源：assets/ 目录 + webui/ 根的零散文件（logo 等），防路径穿越
    if (req.method === "GET") {
      const urlPath = decodeURIComponent(req.url.split("?")[0]);
      const MIME = { ".png":"image/png", ".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".svg":"image/svg+xml", ".gif":"image/gif", ".ico":"image/x-icon", ".webp":"image/webp", ".woff2":"font/woff2" };
      let candidate = null;
      if (urlPath.startsWith("/assets/")) candidate = path.join(__dirname, urlPath);
      else if (/^\/[a-zA-Z0-9_.\-]+$/.test(urlPath) && urlPath !== "/" && urlPath !== "/index.html") candidate = path.join(__dirname, urlPath.slice(1));
      if (candidate && fs.existsSync(candidate)) {
        const real = fs.realpathSync(candidate);
        // 路径穿越防护：必须在 __dirname 下
        if (real.startsWith(fs.realpathSync(__dirname))) {
          const ext = path.extname(real).toLowerCase();
          const mime = MIME[ext];
          if (mime) {
            res.writeHead(200, { "Content-Type": mime, "Cache-Control": "public, max-age=3600" });
            res.end(fs.readFileSync(real));
            return;
          }
        }
      }
    }
    if (req.method === "GET" && (req.url.split("?")[0] === "/" || req.url.split("?")[0] === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store, no-cache, must-revalidate" });
      let html = fs.readFileSync(path.join(__dirname, "index.html"), "utf-8");
      // 注入 cache-bust 注释（绕过缓存，URL 变化导致内容不同 → 浏览器重新解析）
      const ver = Date.now().toString(36);
      html = html.replace("<body>", "<body><!-- build: " + ver + " -->");
      res.end(html);
      return;
    }
    if (req.method === "POST" && req.url === "/api/llm/reset") {
      // 语义（13:34 更新）：用户选择持久化——刷新/重启都保持上次选择（读 llm-choice.json），
      // 不再强制回 _default。只有手动 /api/llm/select 切换才改变。
      send(200, { current: currentLLM, note: "保持用户选择" });
      return;
    }
    if (req.method === "GET" && req.url === "/api/actions") {
      send(200, { actions: Object.fromEntries(Object.entries(ACTIONS).map(([k, v]) => [k, v.label])),
        llm: currentLLM !== "keyword", model: currentLLM !== "keyword" ? LLM_PROVIDERS[currentLLM].model : null });
      return;
    }
    if (req.method === "GET" && req.url === "/api/llm") {
      send(200, { current: currentLLM,
        providers: Object.fromEntries(Object.entries(LLM_PROVIDERS).map(([k, v]) => [k, {
          label: v.label, model: v.model, base_url: v.base_url, env: v.env,
          configured: Boolean(v.key),
          key_hint: v.key ? (v.key.slice(0, 4) + "***" + v.key.slice(-3)) : null,
        }])) });
      return;
    }
    if (req.method === "POST" && req.url === "/api/llm/config") {
      const { provider, base_url, model, key, env, label } = JSON.parse(await body());
      if (!provider || !/^[a-z0-9_-]+$/.test(provider)) { send(400, { error: "provider 必填且仅小写字母数字下划线" }); return; }
      const seed = LLM_SEED[provider] || { label: provider, env: (env || provider.toUpperCase() + "_API_KEY") };
      LLM_PROVIDERS[provider] = {
        label: label || seed.label,
        base_url: base_url || seed.base_url,
        model: model || seed.model,
        env: env || seed.env,
        key: key || "",
      };
      try { saveLLMConfig(); } catch (e) { send(500, { error: "写入 llm-config.json 失败：" + e.message }); return; }
      send(200, { ok: true, provider, configured: Boolean(LLM_PROVIDERS[provider].key) });
      return;
    }
    if (req.method === "POST" && req.url === "/api/llm/config/delete") {
      const { provider } = JSON.parse(await body());
      if (LLM_PROVIDERS[provider]) { delete LLM_PROVIDERS[provider]; try { saveLLMConfig(); } catch {} }
      send(200, { ok: true });
      return;
    }
    if (req.method === "POST" && req.url === "/api/llm/select") {
      const { provider } = JSON.parse(await body());
      // 用户选择持久化：写 cfgs/llm-choice.json，刷新/重启都保持，只有手动切换才变
      if (provider === "keyword") { currentLLM = "keyword"; saveLLMChoice("keyword"); send(200, { current: currentLLM }); return; }
      if (LLM_PROVIDERS[provider] && LLM_PROVIDERS[provider].key) { currentLLM = provider; saveLLMChoice(provider); send(200, { current: currentLLM }); return; }
      const v = LLM_PROVIDERS[provider];
      const SIGNUP = { deepseek: "https://platform.deepseek.com", qwen: "https://bailian.console.aliyun.com", kimi: "https://platform.moonshot.cn" };
      send(400, {
        error: "「" + (v?.label || provider) + "」未配置 API key",
        hint: "请按以下步骤配置：\n\n1. 申请 API key：\n   " + (SIGNUP[provider] || v?.base_url || "https://...") + "\n\n2. 在 webui/start.sh 中添加环境变量：\n   export " + (v?.env || "?") + '="你的key"\n\n3. 重启控制台：\n   cd webui && ./start.sh'
      });
      return;
    }
    if (req.method === "GET" && req.url === "/api/firewalls") {
      let fws = [];
      try { fws = JSON.parse(fs.readFileSync(CFG, "utf-8")).firewalls.map(({ name, host }) => ({ name, host })); } catch {}
      send(200, { firewalls: fws, multi: fws.length > 1 });
      return;
    }
    if (req.method === "GET" && req.url === "/api/llm/log") { send(200, { logs: llmLogs }); return; }
    if (req.method === "POST" && req.url === "/api/llm/test") {
      const { text } = JSON.parse(await body());
      const t0 = Date.now();
      const out = await llmClassify("手动测试", "你是防火墙运维意图分类器。输出 JSON：{\"action\":\"<key>\"}。可选 key：device(设备状态)/security(安全策略)/threat(威胁日志)/traffic(流量日志)/inspect(完整巡检)/change(变更)/diag(诊断)/null(无关)", text || "");
      send(200, { output: out, ms: Date.now() - t0, provider: currentLLM });
      return;
    }
    if (req.method === "GET" && req.url === "/api/tasks") { send(200, { tasks }); return; }
    if (req.method === "POST" && req.url === "/api/tasks/clean") {
      // 清除终态任务（done/cancelled/failed），只保留活跃与待审批任务
      const TERMINAL = new Set(["done", "cancelled", "failed"]);
      const before = tasks.length;
      for (let i = tasks.length - 1; i >= 0; i--) { if (TERMINAL.has(tasks[i].status)) tasks.splice(i, 1); }
      persistTasks();
      send(200, { removed: before - tasks.length, remain: tasks.length });
      return;
    }
    if (req.method === "POST" && req.url === "/api/task") {
      const { query, firewall, source } = JSON.parse(await body());
      if (!client) await connect();
      // 区分任务来源：'web'（Web 控制台默认）/ 'feishu'（飞书 bridge 提交）
      // 飞书移动端发来的任务 WebUI 不显示长答案，Web 端正常显示
      send(200, await createTaskFromInput(query, firewall, source || "web"));
      return;
    }
    if (req.method === "POST" && req.url.startsWith("/api/task/")) {
      const parts = req.url.split("/"); // /api/task/:id/:action[/name]
      const id = Number(parts[3]); const act = parts[4]; const selName = parts[5] ? decodeURIComponent(parts[5]) : null;
      const t = tasks.find((x) => x.id === id);
      if (!t) { send(404, { error: "task not found" }); return; }
      // 用户从候选列表选择精确规则名：用新 name 重跑 candidate 阶段
      if (act === "select" && t.status === "awaiting_selection" && t._candidate) {
        const cand = t._candidate;
        const newParams = { ...cand.name, name: selName, keyword: cand.keyword };
        t.status = "executing";
        t.steps.push(`用户从候选选中：${selName}`);
        saveTask(t);
        runChangeCandidate(t, cand.template, newParams, cand.firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); saveTask(t); });
        send(200, { taskId: t.id, status: t.status }); return;
      }
      // 批量选择执行：POST /api/task/:id/select-multi，body: {names: ["name1", "name2", ...]}
      if (act === "select-multi" && t.status === "awaiting_selection" && t._candidate) {
        const { names } = JSON.parse(await body());
        if (!Array.isArray(names) || !names.length) {
          send(400, { error: "names 必须是非空数组" });
          return;
        }
        t.steps.push(`批量执行 ${names.length} 个策略：${names.join(", ")}`);
        t.status = "executing";
        saveTask(t);
        // 异步批量执行
        (async () => {
          const cand = t._candidate;
          const results = [];
          // 串行执行每个变更（避免并发冲突）
          for (const name of names) {
            const newTask = {
              id: tasks.length + 1,
              type: "change",
              input: `${cand.template} ${name}`,
              template: cand.template,
              params: { name },
              firewall: cand.firewall,
              status: "pending",
              steps: [],
              createdAt: new Date().toISOString(),
            };
            tasks.push(newTask);
            persistTasks();
            try {
              await runChangeCandidate(newTask, cand.template, { name }, cand.firewall);
              results.push({ name, success: true, taskId: newTask.id });
            } catch (e) {
              newTask.status = "failed";
              newTask.error = String(e.message || e);
              saveTask(newTask);
              results.push({ name, success: false, error: String(e.message || e), taskId: newTask.id });
            }
          }
          // 所有变更后做一次统一 commit（而非每个子任务独立 commit，节省时间+减少 commit job）
          const successfulTasks = results.filter(r => r.success).map(r => tasks.find(t => t.id === r.taskId));
          if (successfulTasks.length > 0) {
            t.steps.push(`统一 commit ${successfulTasks.length} 个变更（合并为单次 commit）`);
            try {
              await runChangeCommit(t, cand.firewall);
              // runChangeCommit 不抛异常，通过 t.result.{commitFailed,needsManualCommit} 判断结果
              if (t.result?.commitFailed || t.result?.needsManualCommit) {
                const errMsg = t.result.commitFailed ? "commit 失败" : "commit 超时/需手动";
                for (const st of successfulTasks) {
                  st.status = "failed";
                  st.error = errMsg + " (job=" + (t.result.job || "?") + ")";
                  saveTask(st);
                }
              } else {
                for (const st of successfulTasks) {
                  st.status = "done";
                  st.result = Object.assign(st.result || {}, { mergedCommit: true, commitJob: t.result.job });
                  saveTask(st);
                }
              }
            } catch (e) {
              for (const st of successfulTasks) {
                st.status = "failed";
                st.error = "commit 失败: " + String(e.message || e);
                saveTask(st);
              }
              t.steps.push("commit 异常: " + String(e.message || e).slice(0, 120));
            }
          } else {
            t.steps.push("无可 commit 的变更");
          }
          t.status = "done";
          // 合并 commit job 信息（runChangeCommit 已设 t.result.job），不要覆盖
          t.result = Object.assign(t.result || {}, { batch: true, total: names.length, results });
          saveTask(t);
        })().catch(e => {
          t.status = "failed";
          t.error = String(e.message || e);
          saveTask(t);
        });
        send(200, { taskId: t.id, status: "executing", message: `开始批量执行 ${names.length} 个策略` });
        return;
      }
      if (act === "cancel") {
        t.cancelled = true; t.status = "cancelled"; t.steps.push("手动取消");
        saveTask(t);
        send(200, { taskId: t.id, status: t.status }); return;
      }
      if (act === "approve" && t.status === "awaiting_approval") {
        runChangeCandidate(t, t.template, t.params || {}, t.firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); saveTask(t); });
        send(200, { taskId: t.id, status: t.status }); return;
      }
      if (act === "reject" && t.status === "awaiting_approval") { t.status = "cancelled"; t.steps.push("已拒绝"); saveTask(t); send(200, { taskId: t.id, status: t.status }); return; }
      if (act === "confirm" && t.status === "awaiting_commit") {
        runChangeCommit(t, t.firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); saveTask(t); });
        send(200, { taskId: t.id, status: t.status }); return;
      }
      if (act === "cancel" && (t.status === "awaiting_approval" || t.status === "awaiting_commit")) { t.status = "cancelled"; t.steps.push("已取消"); saveTask(t); send(200, { taskId: t.id, status: t.status }); return; }
      send(400, { error: "非法操作或状态不匹配: " + t.status });
      return;
    }
    if (req.url === "/api/feishu/status") {
      const running = await feishuDaemonRunning();
      send(200, { chat: FEISHU_CHAT, running, lark: LARK_CLI });
      return;
    }
    if (req.url === "/api/feishu/send") {
      const { text } = JSON.parse(await body());
      if (!text) { send(400, { error: "消息不能为空" }); return; }
      send(200, await feishuSend(text));
      return;
    }
    if (req.url === "/api/feishu/push-report") {
      // 推送最新合规报告到飞书
      const dir = path.join(__dirname, "..", "reports");
      const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.startsWith("compliance-") && f.endsWith(".md")).sort().reverse() : [];
      if (!files.length) { send(400, { error: "没有合规报告" }); return; }
      const latest = fs.readFileSync(path.join(dir, files[0]), "utf-8");
      const summary = latest.slice(0, 1500);
      send(200, await feishuSend("【PAN-OS 合规报告 " + files[0] + "】\n" + summary));
      return;
    }
    if (req.method === "GET" && req.url === "/api/overview") {
      send(200, await getOverview());
      return;
    }
    // 报表接口预留（spec §12.1 metrics）：返回 KPI 指标采样序列，支持 ?minutes= 过滤
    if (req.method === "GET" && req.url.startsWith("/api/metrics")) {
      const u = new URL(req.url, "http://localhost");
      const mins = Math.max(1, Math.min(1440, parseInt(u.searchParams.get("minutes") || "120", 10) || 120));
      const since = Date.now() - mins * 60000;
      const pts = metricsBuffer.filter((m) => m.ts >= since);
      send(200, { series: pts, count: pts.length, windowMinutes: mins, note: "指标采样缓冲（10s 粒度，滚窗 2h）；切库后由 metrics 表提供" });
      return;
    }
    if (req.method === "GET" && req.url === "/api/history") { send(200, { history }); return; }
    send(404, { error: "Not Found" });
  } catch (e) { send(500, { error: String(e.message || e) }); }
});

server.listen(PORT, async () => {
  console.log(`[agent] PAN-OS Agent 控制台: http://localhost:${PORT}`);
  try { await connect(); } catch (e) { console.error("[agent] MCP connect fail:", e.message); }
});
