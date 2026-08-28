#!/usr/bin/env node
// PAN-OS 防火墙 Agent 控制台 - 后端 v4（任务系统 + LLM 多提供方）
// 纯 Node http + MCP SDK。任务类型：query(查询) / inspect(巡检) / change(变更审批闭环)
const http = require("http");
const fs = require("fs");
const path = require("path");
const { createPanosAdapter } = require("./adapters/panos-adapter");
const { createTaskService, normalizeChangeParams } = require("./services/task-service");
const { buildSecurityHeaders, isSameOriginApiPath } = require("./lib/security");
const { planFingerprint, transitionTask } = require("./lib/task-governance");
const { buildHealthSummary } = require("./lib/health");

// ── 路径（默认项目内相对路径，可用环境变量覆盖；脱离 WorkBuddy 独立部署无需改代码）──
const NODE = process.env.NODE_BIN || "node";
const PANOS_MCP_DIR = process.env.PANOS_MCP_DIR || path.join(__dirname, "..", "mcp", "panos-mcp");
const SRC = path.join(PANOS_MCP_DIR, "src", "index.ts");
const CWD = PANOS_MCP_DIR;
const CFG = process.env.PANOS_FIREWALLS_CONFIG || path.join(__dirname, "..", "cfgs", "firewalls.json");
const PORT = process.env.PORT || 8080;
const REPORTS_DIR = path.join(__dirname, "..", "reports");
const TASKS_FILE = process.env.TASKS_FILE || path.join(__dirname, "..", "cfgs", "tasks.json");
const AUDIT_FILE = process.env.AUDIT_FILE || path.join(__dirname, "..", "cfgs", "audit-events.json");
const AUTH_FILE = path.join(__dirname, "..", "cfgs", "auth.json");
const TOOLS_CONFIG_PATH = process.env.TOOLS_CONFIG || path.join(__dirname, "tools-config.json");
const panosAdapter = createPanosAdapter({
  cfgPath: CFG,
  toolsConfigPath: TOOLS_CONFIG_PATH,
  nodeBin: NODE,
  panosMcpDir: PANOS_MCP_DIR,
  sourcePath: SRC,
  workingDirectory: CWD,
});
const {
  connect,
  callTool,
  callToolRaw,
  directCommit,
  directConfigDelete,
  directConfigMove,
  directConfigSet,
  directConfigShow,
  directOp,
  deepLog,
  filterByMinutes,
  fmtTop,
  xmlEntries,
} = panosAdapter;

// ── WebUI 认证（发布公网前必须启用；所有 /api/* 需 token，飞书 bridge 用 internal_token）──
const crypto = require("crypto");
const sha256 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const AUTH_SESSION_DAYS = 7;               // 登录会话绝对有效期
// 空闲超时（分钟）：已停用（用户要求"先去掉，搞好以后再说"）。
// 恢复方法：把 IDLE_MINUTES 改为正数即可重新启用，并同步打开前端 _checkIdle 轮询。
const IDLE_MINUTES = 0;                    // 0 = 空闲超时停用（不再因空闲自动登出）
const IDLE_MS = IDLE_MINUTES > 0 ? IDLE_MINUTES * 60 * 1000 : Infinity;
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

const tasks = [];        // 任务列表
const history = [];      // 查询历史
const llmLogs = [];      // LLM 决策日志（证明 LLM 规划起作用）
const metricsBuffer = []; // KPI 指标采样环形缓冲（报表预留，见 spec §12.1 metrics 表）
const auditEvents = [];   // 任务审计独立持久化；清除任务视图不影响历史事件
const MAX_HISTORY = 20;
const MAX_LLM_LOGS = 50;
const MAX_TASKS = 200;   // 任务持久化上限（超出丢弃最旧）
const MAX_METRICS = 720; // 指标采样上限（10s 一次 ≈ 2 小时滚动窗口）

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

function loadAuditEvents() {
  try {
    const saved = JSON.parse(fs.readFileSync(AUDIT_FILE, "utf-8"));
    if (Array.isArray(saved)) auditEvents.push(...saved);
  } catch {}
}
function persistAuditEvents() {
  try {
    const tmp = AUDIT_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(auditEvents, null, 2));
    fs.renameSync(tmp, AUDIT_FILE);
  } catch (e) { console.error("[agent] persist audit failed:", e.message); }
}
function recordTaskAudit(t, event) {
  if (!event) return;
  const entry = { ...event, type: t.type, firewall: t.firewall || null, planFingerprint: t.planFingerprint || null };
  auditEvents.push(entry);
  persistAuditEvents();
}
loadAuditEvents();

// 任务状态与审批动作统一从服务入口处理；具体 PAN-OS 执行器暂以窄回调注入，保持现有异步响应行为。
const taskService = createTaskService({
  panosAdapter,
  taskStore: { load: () => tasks, save: persistTasks },
  auditStore: { load: () => auditEvents, save: persistAuditEvents },
  auditLogReader: (firewall) => callTool("get_config_logs", { nlogs: 200 }, firewall),
  actionDefinitions: () => ACTIONS,
  toolCaller: callTool,
  querySummarizer: summarizeQuery,
  queryHistoryRecorder: (entry) => {
    history.unshift({ ts: new Date().toLocaleString("zh-CN"), ...entry });
    if (history.length > MAX_HISTORY) history.pop();
  },
  inspectReportWriter: ({ date, markdown }) => {
    if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });
    const file = path.join(REPORTS_DIR, "compliance-" + date + "-task.md");
    fs.writeFileSync(file, markdown);
    return file;
  },
  diagnosticDependencies: {
    deepLog,
    filterByMinutes,
    formatTop: fmtTop,
    rawToolCaller: callToolRaw,
    directOp,
    synthesize: llmSynthesize,
  },
  deferExecution: true,
});

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

// ── 飞书桥（可选）──
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

async function llmResolveAction(input, conversationId) {
  const list = Object.entries(ACTIONS).map(([k, v]) => `${k}: ${v.label}（如"${v.keywords[0]}"）`).join("\n");
  const text = await llmClassify("意图规划",
    `你是防火墙运维意图分类器。从动作列表选一个 key；若输入与防火墙查询无关输出 {"action":null}；若输入是配置变更请求（创建/删除/封禁/改策略）输出 {"action":"change"}；若输入是故障诊断请求（连不上/不通/访问不了/排查/诊断/健康检查/某IP什么情况/一直扫描/某个具体故障现象）输出 {"action":"diag"}；若输入是审计/配置变更查询（谁改的/审计/变更记录/谁修改/谁删了/配置变更）输出 {"action":"audit"}。
注意：若输入是**咨询/方案/教学/画图类**请求（如何配置XX、XX是什么、帮我画个拓扑图、最佳实践建议、概念解释等）→ 输出 {"action":null}（系统会用自由问答回答，不要归为 diag）。
【多轮追问】输入前可能附带【最近对话上下文】。若当前问题引用了上下文（如"那条/上面那条/刚才那个/这个结果/它/那个策略/那台设备/结合上面的结果继续/基于刚才的"等指代词或依赖前文才能理解）→ 属于**追问**，按下列规则处理：
  - 追问上轮结果的具体含义/细节/为什么 → {"action":null}（自由问答会结合上下文回答）
  - 追问"把那条删掉/禁用/封禁"等（指代上下文中的具体条目）→ {"action":"change"}（系统会结合上下文解析出具体条目）
  - 追问"那条对应的流量/策略分析"（指代上轮结果做进一步诊断）→ {"action":"diag"}
【时间窗口 minutes】当动作是日志类查询（traffic 流量日志 / threat 威胁日志 / url 过滤日志等）且用户指定了时间范围时，提取为分钟数：如"过去4小时/4个小时/最近4小时"=240、"过去1小时/最近一小时"=60、"最近30分钟/半小时"=30、"最近10分钟"=10、"今天/最近1天"=1440、"过去2小时"=120、"过去6小时"=360。用户没提时间 → minutes=null。**如果用户提到时间但动作不是日志查询，minutes 仍为 null**。
只输出 JSON：{"action":"<key>","minutes":<数字或null>}。\n动作列表（含 diag）:\n${list}\ndiag: 故障诊断（连不上/不通/访问不了/排查/诊断/健康检查/什么情况）`, withCtx(input, conversationId));
  if (!text) return null;
  const m = text.match(/"action"\s*:\s*("?)(\w+|null)\1/);
  if (!m) return null;
  const key = m[2];
  if (key === "null") return { action: null, minutes: null };
  const mM = text.match(/"minutes"\s*:\s*(\d+)/);
  const minutes = mM ? Math.max(1, Math.min(1440, parseInt(mM[1], 10))) : null;
  return { action: key, minutes };
}

// 变更参数提取（模板化，LLM 只填参数）
async function llmExtractChange(input, conversationId) {
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
若无法匹配模板输出 {"template":null}。只输出 JSON：{"template":"<key>","params":{...}}。\n${tmplList}`, withCtx(input, conversationId));
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
  // 改进1/2：额外注入时间线趋势 + 数据时间范围（sections 里已有"流量时间线"段，这里再确保 LLM 看到）
  const tl = sections.find((s) => s.step === "流量时间线");
  const tlCtx = tl && tl.result && tl.result !== "（无时间线数据）" ? "\n【流量时间线】(10分钟桶 action 分布，越靠右越新):\n" + tl.result.slice(0, 600) : "";
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
- **必须标注数据时间范围**：verdict 开头必须说明"本结论基于【时间范围】的数据（最早 → 最晚）"——若用户报告的现象时间（如"16:59 看到 reset-both"）落在时间范围之外，要明确指出"该现象在本次数据窗口外，无法用本次数据证实/证伪，建议指定该时间点重查"。
- **必须看时间线趋势**：数据里的【时间线】字段按 10 分钟桶展示各 action 数量。如果时间线显示"某时刻起 reset-both/deny 集中出现，之后又恢复 allow"，说明是**阶段性/瞬时现象**，根因应解释"何时发生、为何恢复"，而不是给"当前状态"的单一快照结论。

【输出格式】
JSON：
{
  "verdict": "一段话根因（开头标注数据时间范围；含证据引用：[流量]、[策略]、[zone] 等指明依据）",
  "confidence": "高/中/低",
  "confidence_reason": "为什么是这个置信度",
  "evidence": ["关键证据1:…", "关键证据2:…", "反驳证据:…"],
  "recommendation": "可执行下一步（具体到工具/命令）"
}

【用户症状】"${input}"
【数据】
${ctx}${statCtx}${tlCtx}`,
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
async function llmParseDiag(input, conversationId) {
  const text = await llmClassify("诊断规划",
    `你是网络诊断解析器。判断用户症状属于：connectivity（连通性排查，涉及源/目的/IP/端口/连不上/不通/访问不了）、threat_profile（威胁源画像，涉及"什么情况/一直扫描/攻击/画像"且给定了IP）、generic（通用健康检查）。提取参数：ip（IPv4）、port（端口）、direction（inbound/outbound）、target_label（如"外网"）、minutes（时间窗口分钟数，如"最近10分钟"=10、"最近1小时"=60、"今天"=1440，无则默认60）、probe（可选：用户要求"ping/测试连通/探测"填"ping"；要求"追踪路由/traceroute"填"traceroute"；否则不填）、around_time（可选：用户指定了**现象发生的具体时间点**，如"16:59那次/昨天下午3点/刚才(默认不填)/2026/08/23 16:59"，填 "YYYY/MM/DD HH:MM" 或 "HH:MM"；用户没指定时间点则**不填**）。
【多轮追问】输入前可能附带【最近对话上下文】。若用户引用前文（如"那条策略/刚才那个IP/上面的结果"）继续诊断，从上下文提取 ip/port 等缺失参数。无法判断输出 {"type":null}。只输出 JSON：{"type":"<t>","params":{}}。`, withCtx(input, conversationId));
  if (!text) return null;
  try {
    const m = text.match(/\{[\s\S]*\}/);
    const o = JSON.parse(m ? m[0] : "{}");
    if (o.params && o.params.minutes !== undefined) o.params.minutes = Number(o.params.minutes) || 60;
    if (o.params && o.params.probe !== undefined && !["ping", "traceroute"].includes(o.params.probe)) delete o.params.probe;
    return o;
  } catch { return null; }
}

// ── 会话归组（方案C）：显式 replyTo → 沿链并入目标会话；否则按时间窗自动归组 ──
const SESSION_GAP_MS = 5 * 60 * 1000; // 连续任务间隔 <5 分钟 → 同一会话
let _convSeq = 0;
function nextConvId() {
  // 从现有任务恢复会话计数（重启后不重复编号）
  if (!_convSeq) {
    for (const x of tasks) {
      const m = x.conversationId && String(x.conversationId).match(/^conv-(\d+)$/);
      if (m) _convSeq = Math.max(_convSeq, Number(m[1]));
    }
  }
  _convSeq += 1;
  return "conv-" + _convSeq;
}
// 解析新任务会话归属：显式 replyTo（追问某条）→ 归入目标任务所在会话；
// 无 replyTo 时看最近一个任务的时间差，<SESSION_GAP_MS 归同会话，否则开新会话。
// 老任务（无 conversationId）惰性补号；返回 {conversationId, replyTo}
function resolveConversation(replyTo) {
  if (replyTo) {
    const target = tasks.find((x) => x.id === Number(replyTo));
    if (target) {
      if (!target.conversationId) { target.conversationId = nextConvId(); persistTasks(); } // 惰性迁移老任务（落盘防重启计数重复）
      return { conversationId: target.conversationId, replyTo: target.id };
    }
  }
  const last = tasks[tasks.length - 1];
  if (last) {
    const t0 = Date.parse(String(last.createdAt || "").replace(/\//g, "-"));
    if (!isNaN(t0) && Date.now() - t0 < SESSION_GAP_MS) {
      if (!last.conversationId) { last.conversationId = nextConvId(); persistTasks(); }
      return { conversationId: last.conversationId, replyTo: null };
    }
  }
  return { conversationId: nextConvId(), replyTo: null };
}

// ── 任务系统 ──
function newTask(type, input, extra = {}) {
  return taskService.createTask(type, input, extra);
}
function saveTask(t) { return taskService.saveTask(t); }

// 查询任务的语义匹配分析（轻量 LLM 调用，30s 超时）
async function summarizeQuery(input, action, results, conversationId) {
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
      // 时间范围标注：日志类结果（entry 带 receive_time）→ 告知 LLM 真实数据时间，防止"过去N小时"幻觉
      const times = items.map((it) => (it && it.receive_time) || "").filter(Boolean).sort();
      const timeNote = times.length ? `（数据时间范围：${times[0]} → ${times[times.length - 1]}，共 ${items.length} 条）` : "";
      return `[${r.tool}] 共 ${items.length} 条${timeNote}：\n${head}` + (items.length > 50 ? "\n... (省略剩余 " + (items.length - 50) + " 条)" : "");
    }
    return `[${r.tool}] ${JSON.stringify(d).slice(0, 1500)}`;
  }).join("\n\n");
  // 改进：若用户 query 提到时间窗口而数据时间与之不符，提示 LLM 明确说明
  const timeHint = /过去|最近|小时内|分钟|今天|昨天|小时前/.test(input)
    ? "\n【注意】用户要求了时间窗口。请在回答中**明确说明返回数据的实际时间范围**（最早→最晚），若实际数据时间与用户要求不符，要明确指出（如\"实际返回最近 5 分钟数据，未覆盖您要求的 4 小时\"），不要假装\"我筛选了 N 小时\"。"
    : "";
  const text = await llmClassify("查询匹配",
    `你是 PAN-OS 防火墙查询结果分析器。用户的问句往往带语义（如"哪些策略放行了 Internet到 DMZ"——"Internet"=源 zone Untrust 或外部，"DMZ"=目标 zone DMZ 或特定对象）。你需要：

1. **语义映射**：把用户 query 中的关键词（"Internet"/"DMZ"/"内部"/"外部"/特定 IP）映射到实际数据中（zone 名/address 对象/any）。
2. **匹配筛选**：基于映射结果，从上面数据里选出**真正满足用户问题**的条目（按 action 字段区分 allow/deny）。
3. **明确回答**：直接说出"有/无/几条"匹配；如果没有，**明确说"没有匹配的策略"**（不要强行凑"全放行 Allow all"这种看似匹配但实际不相关的）。
4. **完整汇报元数据**：当工具返回 Dashboard General Information 风格的元数据（get_firewall_info）时，**主动列出关键模块版本和状态**——GP/AV/Threat/WildFire/URL 各模块版本号、Advanced Routing、Duplicate IP、Plugin DLP、Device Certificate Status、Uptime 等。问"设备清单/资产"时这些是关键信息，不能漏。
5. **引用**：用条目 @_name 或关键字段标识匹配项。
6. **多轮追问**：若用户问题引用了前文（如"那条/上面那条/它"），优先结合【最近对话上下文】中的条目名和结果回答，不要重复全量查询。

输出 1-3 段简洁中文（≤350 字，比一般查询多 100 字用于展示元数据），不要堆 JSON。`,
    `用户问句：${input}${timeHint}\n\n工具结果：\n${ctx}${buildConversationContext(CTX_ROUNDS, conversationId) ? "\n\n" + buildConversationContext(CTX_ROUNDS, conversationId) : ""}`,
    30000);
  return text || null;
}

// ── 意图 → 任务路由 ──

// ── 多轮追问上下文（方案C）：优先注入同一 conversationId 会话内的已完成任务 ──
// 显式 replyTo/会话归组后，只取同会话历史，避免无关任务的上下文污染 LLM 判断
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
function buildConversationContext(limit = CTX_ROUNDS, conversationId) {
  // 指定会话 → 只取同会话内的任务；未指定（老调用/无会话）→ 退化为全局最近 N 个（兼容）
  const pool = conversationId ? tasks.filter((x) => x.conversationId === conversationId) : tasks;
  const recent = pool
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
function withCtx(userInput, conversationId) {
  const ctx = buildConversationContext(CTX_ROUNDS, conversationId);
  return ctx ? ctx + "\n\n【用户当前问题】" + userInput : userInput;
}

async function createTaskFromInput(input, firewall, source, opts = {}) {
  // 重复任务去重：先扫描 active 任务，发现与 input normalize 后完全相同则取消旧任务
  const dup = dedupeActiveTask(input);
  // 会话归组（方案C）：显式 replyTo（前端"↩ 追问这条"）→ 并入目标会话；否则按时间窗归组
  const conv = resolveConversation(opts.replyTo);
  let action = null, fromLLM = false, minutes = null;
  for (const [k, v] of Object.entries(ACTIONS)) { if (k === input || v.label === input) action = k; }
  if (!action) {
    const resolved = await llmResolveAction(input, conv.conversationId);
    if (resolved) { action = resolved.action; minutes = resolved.minutes; if (action) fromLLM = true; }
  }
  if (action === "change") {
    const c = await llmExtractChange(input, conv.conversationId);
    if (!c) return { error: "无法解析变更意图（支持：创建/删除地址对象、封禁/放行 IP、移动/删除/禁用/启用安全策略）" };
    const tmpl = CHANGE_TEMPLATES[c.template];
    const params = normalizeChangeParams(c.template, c.params);
    // 规则类模板（delete/disable/enable）若只有模糊 keyword，先预检转 awaiting_selection
    const RULE_TMPL = ["delete_security_rule", "set_security_rule_disabled", "set_security_rule_enabled"];
    const needPrecheck = RULE_TMPL.includes(c.template) && !(params.name && /^[a-zA-Z0-9_.\-]+$/.test(params.name));
    const t = newTask("change", input, { template: c.template, templateLabel: tmpl.label, params, firewall, source, conversationId: conv.conversationId, replyTo: conv.replyTo, status: needPrecheck ? "awaiting_selection" : "awaiting_approval" });
    t.plan = tmpl.plan(params);
    t.planFingerprint = planFingerprint({ template: c.template, params, firewall });
    if (needPrecheck) {
      // 同步做一次预检（list candidates）→ 任务状态已是 awaiting_selection，前端直接展示候选按钮
      try { await taskService.prepareRuleSelection(t, tmpl.label); }
      catch (e) { t.status = "failed"; t.error = e.message; saveTask(t); }
    } else {
      t.steps.push("变更计划已生成，等待审批");
    }
    t.llm = currentLLM;  // 记录处理该任务时实际使用的 LLM provider key
    taskService.addTask(t);
    recordTaskAudit(t, { taskId: t.id, action: "created", from: null, to: t.status, at: new Date().toISOString() });
    return needPrecheck && t.status === "awaiting_selection"
      ? { taskId: t.id, status: t.status, plan: t.plan, candidates: t.result.matched, totalMatches: t.result.totalMatches }
      : { taskId: t.id, status: t.status, plan: t.plan };
  }
  if (action === "audit") {
    const a = await llmParseAudit(input);
    const t = taskService.dispatchTask("audit", input, { firewall, source, audit: a, conversationId: conv.conversationId, replyTo: conv.replyTo }, (task) => {
      task.llm = currentLLM;
      task.decision = `LLM 规划 → 审计查询（${a.minutes} 分钟内${a.object}）（${LLM_PROVIDERS[currentLLM]?.label || currentLLM}）`;
      task.steps.push(task.decision);
    }, (task) => taskService.runAudit(task));
    return { taskId: t.id, status: t.status, type: "audit" };
  }
  if (action === "diag") {
    const d = await llmParseDiag(input, conv.conversationId);
    // 诊断规划判定为非诊断请求（type:null，如"画个拓扑图"）→ 降级自由问答，
    // 不再生硬报"无法解析诊断意图"——让 LLM 分析推理回答（16:48 飞书案例根因）
    if (!d || !d.type) return await createFreeAnswer(input, firewall, source, conv);
    const t = taskService.dispatchTask("diag", input, { firewall, source, diag: d, conversationId: conv.conversationId, replyTo: conv.replyTo }, (task) => {
      task.llm = currentLLM;
      task.decision = `LLM 规划 → 诊断 ${d.type}（${LLM_PROVIDERS[currentLLM]?.label || currentLLM}）`;
      task.steps.push(task.decision);
    }, (task) => taskService.runDiagnostic(task));
    return { taskId: t.id, status: t.status, type: "diag" };
  }
  if (action === "inspect") {
    const t = taskService.dispatchTask("inspect", input, { firewall, source, conversationId: conv.conversationId, replyTo: conv.replyTo }, null, (task) => taskService.runInspect(task));
    return { taskId: t.id, status: t.status, type: "inspect" };
  }
  if (action && ACTIONS[action]) {
    const t = taskService.dispatchTask("query", input, { action, firewall, source, minutes, conversationId: conv.conversationId, replyTo: conv.replyTo }, (task) => {
      if (fromLLM) task.llm = currentLLM;
      task.decision = fromLLM ? `LLM 规划 → 动作 ${action}（${LLM_PROVIDERS[currentLLM]?.label || currentLLM}）${minutes ? "，时间窗口 " + minutes + " 分钟" : ""}` : `关键词匹配 → 动作 ${action}`;
      task.steps.push(task.decision);
    }, (task) => taskService.runQuery(task, action));
    return { taskId: t.id, status: t.status, type: "query", label: ACTIONS[action].label };
  }
  // 兜底：意图不匹配任何 action → 自由问答（LLM 分析/推理/思考后回答，不直接拒绝）
  return await createFreeAnswer(input, firewall, source, conv);
}

// 自由问答兜底：用户问题未匹配现有 tools/action 时，让 LLM 结合设备基础信息做分析推理回答
async function createFreeAnswer(input, firewall, source, opts = {}) {
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
    `${fwCtx ? fwCtx + "\n" : ""}用户问题：${withCtx(input, opts.conversationId)}`,
    60000);
  const t = newTask("chat", input, { firewall, source, conversationId: opts.conversationId, replyTo: opts.replyTo });
  t.llm = currentLLM;
  if (source) t.source = source;  // 标记任务来源（'feishu'/'web'/'bridge'），用于 WebUI 区分展示
  t.decision = `LLM 兜底 → 自由问答（${LLM_PROVIDERS[currentLLM]?.label || currentLLM}）`;
  t.steps.push(t.decision);
  t.result = { answer: text || "抱歉，LLM 未能给出回答。您可以换个说法，或试试：设备状态 / 安全策略 / 威胁日志 / 完整巡检 / 封禁 1.2.3.4。", sentTo: source === "feishu" ? "feishu" : "web" };
  t.status = "done";
  taskService.addTask(t);
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
    callTool("get_interfaces", {}, null).catch(() => null),
    getPlatformLoading().catch(() => null),
  ]);
  const [fw, ha, sess, res, lic, ifc, plat] = fast.map((x) => (x.status === "fulfilled" ? x.value : null));
  if (fw) { kpi.device = { hostname: fw.hostname, model: fw.model, sw: fw["sw-version"], uptime: fw.uptime, serial: fw.serial }; }
  if (ha) kpi.ha = { enabled: ha.enabled === "yes" || ha.enabled === true };
  if (sess) kpi.session = { active: sess.num_active, max: sess.num_max, kbps: sess.kbps, pps: sess.pps };
  if (res) kpi.resource = { load: res["load average"], memUsed: res["mem used"], memTotal: res["mem total"] };
  if (lic) {
    const arr = lic.entry || [];
    kpi.license = { total: arr.length, expired: arr.filter((e) => String(e.expired).toLowerCase() === "yes").length };
  }
  // 接口信息（PA-440 物理/逻辑接口：名称/状态/速率/IP/MAC/角色）
  const interfaces = ifc ? parseInterfaces(ifc) : [];
  const health = buildHealthSummary({ kpi, interfaces, platform: plat || null });
  const out = { ts: Date.now(), kpi, interfaces, platform: plat || null, health };
  overviewCache = out; overviewTs = Date.now();
  // 指标采样（报表预留）：每次 getOverview 计算完成后把 KPI 快照写入环形缓冲，
  // 未来切 SQLite/PG 时按 spec 第 12 章 metrics 表落库；现在提供 /api/metrics 供前端可视化。
  metricsBuffer.push({ ts: out.ts, kpi: JSON.parse(JSON.stringify(kpi)), health: health.level });
  if (metricsBuffer.length > MAX_METRICS) metricsBuffer.shift();
  return out;
}

// ── 网络拓扑（用户要求：根据设备/IP/路由画带 IP 的拓扑图）──
// 数据：防火墙自身 + 接口(IP/zone) + 路由表(网段/网关) + ARP 表(二层邻居 IP+MAC) + 命名表(cfgs/topology.json)
let topologyCache = null, topologyTs = 0;
const TOPOLOGY_TTL = 20000; // 20s 缓存（ARP/路由不至于变化太快）
function loadTopologyNames() {
  try { return JSON.parse(fs.readFileSync(path.join(__dirname, "../cfgs/topology.json"), "utf-8")) || { devices: {} }; }
  catch (e) { return { devices: {} }; }
}
async function getTopology() {
  if (topologyCache && Date.now() - topologyTs < TOPOLOGY_TTL) return topologyCache;
  const names = loadTopologyNames();
  const [fwR, ifcR, zoneR] = await Promise.allSettled([
    callTool("get_firewall_info", {}, null).catch(() => null),
    callTool("get_interfaces", {}, null).catch(() => null),
    callTool("get_zones", {}, null).catch(() => null),
  ]);
  const fw = fwR.status === "fulfilled" && fwR.value ? fwR.value : null;
  const ifc = ifcR.status === "fulfilled" && ifcR.value ? ifcR.value : null;
  const zonesRaw = zoneR.status === "fulfilled" && zoneR.value ? zoneR.value : null;
  // 路由表：直接 op 命令 + xmlEntries（PAN-OS 11.2.4 Advanced Routing 模式下 show routing 系列已弃用 →
  // 拿不到就空数组，不影响拓扑主体：接口 + ARP 设备仍然完整展示）
  let routes = [];
  try {
    routes = xmlEntries(await directOp("<show><routing><route></route></routing></show>"));
  } catch (e) { routes = []; }
  // ARP 表：直接 op 命令 + xmlEntries（返回 <entries><entry> 结构，MCP 路径解析不稳定，直连最稳）
  let arp = [];
  try {
    arp = xmlEntries(await directOp("<show><arp><entry name='all'/></arp></show>"));
  } catch (e) { arp = []; }
  const zones = (zonesRaw && (zonesRaw.zone?.entry || zonesRaw.entry)) || [];
  // 防火墙中心节点
  const fwNode = {
    type: "firewall",
    ip: DIRECT_FW.host || fw?.["ip-address"] || "",
    name: "PA-440 防火墙",
    hostname: fw?.hostname || "",
    model: fw?.model || "",
    swVersion: fw?.["sw-version"] || "",
    serial: fw?.serial || "",
  };
  // 接口节点 + zone 映射
  const ifs = ifc ? parseInterfaces(ifc) : [];
  const ifZones = {};
  for (const z of zones) {
    const n = z.network || {};
    const toArr = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
    for (const i of [...toArr(n.layer2?.member), ...toArr(n.layer3?.member), ...toArr(n["virtual-wire"]?.member)]) ifZones[i] = z["@_name"];
  }
  const ifNodes = ifs.map((i) => ({ type: "interface", name: i.name, ip: i.ip, state: i.state, speed: i.speed, mac: i.mac, zone: ifZones[i.name] || i.role || "" }));
  // 网关节点：路由表 nexthop 去重（0.0.0.0 是默认路由 → Internet 网关）
  const gwMap = new Map();
  for (const r of routes) {
    const dest = r.destination || "";
    const nh = r.nexthop || r["ip-address"] || "";
    if (!nh || nh === "0.0.0.0") continue;
    if (!gwMap.has(nh)) gwMap.set(nh, { ip: nh, isInternet: dest.includes("0.0.0.0"), viaIf: r.interface || "", dest });
  }
  const gwNodes = [...gwMap.values()];
  // ARP 设备：按 IP 去重，挂接口 + 命名表
  const devMap = new Map();
  for (const a of arp) {
    const ip = a.ip || a["ip-address"] || "";
    if (!ip) continue;
    const mac = a.mac || a["mac-address"] || "";
    const iface = a.interface || a.ifname || "";
    if (devMap.has(ip)) { if (!devMap.get(ip).mac) devMap.get(ip).mac = mac; continue; }
    const cfg = names.devices[ip] || {};
    devMap.set(ip, { ip, mac, iface, name: cfg.name || ip, icon: cfg.icon || "pc" });
  }
  // 命名表 extra_nodes：ARP 未抓到但必须显示的节点（如 TPLINK 交换机 MAC 不响应 ARP）
  const extras = names.extra_nodes || {};
  for (const [ip, cfg] of Object.entries(extras)) {
    if (!devMap.has(ip)) devMap.set(ip, { ip, mac: cfg.mac || "", iface: cfg.iface || "", name: cfg.name || ip, icon: cfg.icon || "pc" });
  }
  devMap.delete(fwNode.ip); // 防火墙自身不算邻居
  // 汇聚节点标记：icon 为 switch/router/ap 的设备提升为汇聚层（前端画中间层，其他设备挂其下）
  for (const d of devMap.values()) d.agg = ["switch", "router", "ap"].includes(d.icon) ? 1 : 0;
  const out = { ts: Date.now(), fw: fwNode, interfaces: ifNodes, gateways: gwNodes, devices: [...devMap.values()], hasDefault: gwNodes.some((g) => g.isInternet), ok: !!(fwNode.hostname || fwNode.ip) };
  topologyCache = out; topologyTs = Date.now();
  return out;
}

// 解析 get_interfaces 输出（directRunOp 返回 {entry:[...]}，MCP 路径返回 {hw:{entry:[...]}}，两种都兼容）
function parseInterfaces(raw) {
  const arr = raw && raw.hw && Array.isArray(raw.hw.entry) ? raw.hw.entry
           : raw && Array.isArray(raw.entry) ? raw.entry
           : Array.isArray(raw) ? raw
           : [];
  return arr.map((it) => {
    const name = it.name || it["@_name"] || "";
    const state = String(it.state || it["admin-status"] || it.link || "").toLowerCase();
    const speed = it.speed || it["link-speed"] || "";
    const mac = it.mac || it["mac-address"] || "";
    const ip = it.ip || it["ip-address"] || "";
    const role = (it["logical-interface"] && it["logical-interface"].name) || it.type || it.zone || "";
    return { name, state, speed, mac, ip, role };
  }).filter((x) => x.name);
}

// ── 防火墙平台 CPU Loading（用户要求：展示防火墙自身的 Management Plane 与 Data Plane CPU）──
// Management Plane：show system resources → load average(1/5/15min) + 内存
//   ⚠️ PAN-OS 管理面的 `top` 输出在容器里 `id`（空闲率）永远为 0%（us 可超 100% 是多核累计），
//      用 `100-id` 算使用率会永远 100%——必须改用 load average 换算。
// Data Plane：show running resource-monitor → dp0 各 core 的 cpu-load-average 采样（0-100%）
const MP_CORES = 4;   // PA-440 管理面 4 核（官方规格：Cortex-A72 x4）
const PLATFORM_WINDOW = 5; // 采样平滑窗口：保留最近 5 次（30s×5 = 2.5 分钟平均），防单帧抖动
const PLATFORM_TTL = 30000; // 独立 30s 缓存：防止 overview 每 5s 触发一次 op 查询自激推高 MP CPU
const platformBuf = { mp: [], dp: [] };
let platformCache = null, platformCacheTs = 0;
async function getPlatformLoading() {
  if (platformCache && Date.now() - platformCacheTs < PLATFORM_TTL) return platformCache;
  const [mpR, dpR] = await Promise.allSettled([
    directOp("<show><system><resources></resources></system></show>"),
    directOp("<show><running><resource-monitor></resource-monitor></running></show>"),
  ]);
  const mpRaw = mpR.status === "fulfilled" ? String(mpR.value || "") : "";
  const dpRaw = dpR.status === "fulfilled" ? String(dpR.value || "") : "";
  // 解析原始样本
  const mpNew = parseMgmtPlane(mpRaw);
  const dpNew = parseDataPlane(dpRaw);
  // 推入采样缓冲：仅在线样本入栈；离线时清空缓冲（避免下次恢复时混入老数据 + 不让旧 online 冒充"现在"）
  if (mpNew.status === "online") {
    platformBuf.mp.push(mpNew);
    if (platformBuf.mp.length > PLATFORM_WINDOW) platformBuf.mp.shift();
  } else {
    platformBuf.mp.length = 0;
  }
  if (dpNew.status === "online") {
    platformBuf.dp.push(dpNew);
    if (platformBuf.dp.length > PLATFORM_WINDOW) platformBuf.dp.shift();
  } else {
    platformBuf.dp.length = 0;
  }
  const out = {
    managementPlane: smoothMgmt(platformBuf.mp, mpNew),
    dataPlane: smoothData(platformBuf.dp, dpNew),
  };
  platformCache = out; platformCacheTs = Date.now();
  return out;
}

// MP 平滑：last 离线 → 立即返回 offline（不让历史 online 样本冒充当前状态）；online 才取缓冲平均
function smoothMgmt(samples, last) {
  if (!last || last.status !== "online") {
    return { name: "Management Plane", status: "offline", sampleN: 0 };
  }
  if (!samples.length) {
    return { name: "Management Plane", status: "online", sampleN: 0, usagePct: null, load1: null, load5: null, load15: null };
  }
  const avg = (key) => {
    const v = samples.filter((s) => s[key] != null).map((s) => s[key]);
    if (!v.length) return null;
    return Math.round(v.reduce((a, b) => a + b, 0) / v.length * 100) / 100;
  };
  const load1 = avg("load1"), load5 = avg("load5"), load15 = avg("load15");
  const cpuUserPct = avg("cpuUserPct"), cpuSysPct = avg("cpuSysPct");
  // usagePct：优先用 sample 内 parse 的 us+sy+ni（精确反映 CPU 占用），没有则用 load5/cores 兜底
  let usagePct = avg("usagePct");
  let usageMethod = "us+sy+ni";
  if (usagePct == null && load5 != null) {
    usagePct = Math.max(0, Math.min(100, Math.round(load5 / MP_CORES * 1000) / 10));
    usageMethod = "load5/cores";
  }
  return {
    name: last.name || "Management Plane",
    status: "online",
    load1, load5, load15,
    cpuUserPct, cpuSysPct,
    usagePct,
    usageMethod,
    memUsedMB: last.memUsedMB,
    memTotalMB: last.memTotalMB,
    sampleN: samples.length,    // 参与平均的样本数（前端展示"基于 N 次采样"）
  };
}

// DP 平滑：同 MP 策略——last 离线立即返回 offline，不让历史 online 样本冒充当前
function smoothData(samples, last) {
  if (!last || last.status !== "online") {
    return { name: "Data Plane", status: "offline", sampleN: 0 };
  }
  if (!samples.length) {
    return { name: "Data Plane", status: "online", sampleN: 0, cpuPct: null, cores: null };
  }
  const avg = (key) => {
    const v = samples.filter((s) => s[key] != null).map((s) => s[key]);
    if (!v.length) return null;
    return Math.round(v.reduce((a, b) => a + b, 0) / v.length * 10) / 10;
  };
  return {
    name: last.name || "Data Plane",
    status: "online",
    processors: last.processors,
    cores: last.cores,
    cpuPct: avg("cpuPct"),
    cpuPeakPct: avg("cpuPeakPct"),
    cpu5sPct: avg("cpu5sPct"),
    pktBufPct: avg("pktBufPct"),
    sessionUtilPct: avg("sessionUtilPct"),
    pktDescPct: avg("pktDescPct"),
    sampleN: samples.length,
  };
}

// 解析管理面：show system resources（top 文本）
//   ⚠️ PAN-OS 管理面的 `top` 输出在容器里 `id`（空闲率）永远为 0%（us 可超 100% 是多核累计），
//      用 `100-id` 算使用率会永远 100%——必须改用 `us+sy+ni`（全核标准化工作时间）。
function parseMgmtPlane(txt) {
  const out = { name: "Management Plane", status: "offline" };
  if (!txt || !txt.includes("<result>")) return out;
  out.status = "online";
  // load average: 4.93, 5.08, 5.27（1/5/15 分钟）—— 包含运行队列+I/O 等待（I/O 高时 load 高但 CPU% 不一定高）
  const lm = txt.match(/load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)/);
  if (lm) { out.load1 = parseFloat(lm[1]); out.load5 = parseFloat(lm[2]); out.load15 = parseFloat(lm[3]); }
  // %Cpu(s): 12.4 us, 1.5 sy, 0.0 ni, 17.9 id → 使用率 = us + sy + ni（多核平均标准化，全核 0-100%）
  const cpuLine = txt.match(/%Cpu\(s\):([\s\S]*?)(?=MiB Mem|$)/);
  if (cpuLine) {
    const body = cpuLine[1];
    const um = body.match(/([\d.]+)\s+us/);
    const sm = body.match(/([\d.]+)\s+sy\b/);
    const nim = body.match(/([\d.]+)\s+ni\b/);
    if (um) {
      const u = parseFloat(um[1]), s = sm ? parseFloat(sm[1]) : 0, n = nim ? parseFloat(nim[1]) : 0;
      out.cpuUserPct = Math.round(u * 10) / 10;
      out.cpuSysPct = Math.round(s * 10) / 10;
      out.usagePct = Math.max(0, Math.min(100, Math.round((u + s + n) * 10) / 10));
    }
  }
  // MiB Mem : 15875.5 total, 704.1 free, 7348.8 used
  const mm = txt.match(/MiB Mem\s*:\s*([\d.]+) total,\s*([\d.]+) free,\s*([\d.]+) used/);
  if (mm) { out.memTotalMB = Math.round(parseFloat(mm[1])); out.memUsedMB = Math.round(parseFloat(mm[3])); }
  return out;
}

// 解析数据面：show running resource-monitor
// <dp0><second><cpu-load-average><entry><coreid>N</coreid><value>a,b,c,...(60 采样)</value></entry>...
function parseDataPlane(txt) {
  const out = { name: "Data Plane", status: "offline" };
  if (!txt || !txt.includes("<resource-monitor>")) return out;
  out.status = "online";
  // 数据处理器数（dp0/dp1/...）
  const dps = txt.match(/<dp\d+>/g) || [];
  out.processors = dps.length;
  // 取所有 dp 的 second.cpu-load-average 采样
  const avgBlocks = [...txt.matchAll(/<second>([\s\S]*?)<\/second>/g)].map((m) => m[1]);
  const secondBlock = avgBlocks[0] || "";
  const cpuAvgEntries = secondBlock.match(/<cpu-load-average>([\s\S]*?)<\/cpu-load-average>/)?.[1] || "";
  const entries = [...cpuAvgEntries.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map((m) => m[1]);
  const coreVals = [];
  for (const e of entries) {
    const coreId = e.match(/<coreid>(\d+)<\/coreid>/)?.[1];
    const valStr = e.match(/<value>([\s\S]*?)<\/value>/)?.[1];
    if (coreId != null && valStr) {
      const samples = valStr.split(",").map((s) => parseFloat(s)).filter((n) => !isNaN(n));
      if (samples.length) coreVals.push({ core: parseInt(coreId, 10), samples, avg: samples.reduce((a, b) => a + b, 0) / samples.length, last: samples[samples.length - 1] });
    }
  }
  if (coreVals.length) {
    out.cores = coreVals.length;
    // 各核平均使用率（60 个采样取均值），整体 = 各核再平均
    out.cpuPct = Math.round(coreVals.reduce((a, c) => a + c.avg, 0) / coreVals.length * 10) / 10;
    // 峰值：任一核任一秒的最大值（直观反映突发）
    out.cpuPeakPct = Math.round(Math.max(...coreVals.map((c) => Math.max(...c.samples))) * 10) / 10;
    // 最近 5 秒使用率（更贴近"当前"）
    const recent5 = coreVals.map((c) => {
      const s = c.samples.slice(-5);
      return s.reduce((a, b) => a + b, 0) / s.length;
    });
    out.cpu5sPct = Math.round(recent5.reduce((a, b) => a + b, 0) / recent5.length * 10) / 10;
  }
  // resource-utilization：packet buffer / session 等资源利用率（可选展示）
  const utilEntries = secondBlock.match(/<resource-utilization>([\s\S]*?)<\/resource-utilization>/)?.[1] || "";
  for (const u of [...utilEntries.matchAll(/<entry>([\s\S]*?)<\/entry>/g)]) {
    const name = u[1].match(/<name>([^<]+)<\/name>/)?.[1];
    const valStr = u[1].match(/<value>([\s\S]*?)<\/value>/)?.[1];
    if (!name || !valStr) continue;
    const samples = valStr.split(",").map((s) => parseFloat(s)).filter((n) => !isNaN(n));
    if (!samples.length) continue;
    const avg = Math.round(samples.reduce((a, b) => a + b, 0) / samples.length * 10) / 10;
    if (/packet buffer/.test(name)) out.pktBufPct = avg;
    else if (/^session$/.test(name)) out.sessionUtilPct = avg;
    else if (/packet descriptor/.test(name)) out.pktDescPct = avg;
  }
  return out;
}

function formatUptimeSec(sec) {
  sec = Math.max(0, parseInt(sec, 10) || 0);
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + m + "m";
  return m + "m " + (sec % 60) + "s";
}

const server = http.createServer(async (req, res) => {
  // 所有响应默认 no-cache（前端会随轮询实时变化；浏览器/代理缓存旧值会误导排查）
  for (const [name, value] of Object.entries(buildSecurityHeaders())) res.setHeader(name, value);
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
    if (isSameOriginApiPath(urlPath0) && !isStatic) {
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
    if (req.method === "GET" && req.url === "/api/tasks") { send(200, { tasks: taskService.listTasks() }); return; }
    if (req.method === "POST" && req.url === "/api/tasks/clean") {
      send(200, taskService.cleanTasks());
      return;
    }
    if (req.method === "POST" && req.url === "/api/task") {
      const { query, firewall, source, replyTo } = JSON.parse(await body());
      if (!panosAdapter.isConnected()) await connect();
      // 区分任务来源：'web'（Web 控制台默认）/ 'feishu'（飞书 bridge 提交）
      // 飞书移动端发来的任务 WebUI 不显示长答案，Web 端正常显示
      // replyTo：前端"↩ 追问这条"时携带被追问的任务 id，后端并入该任务所在会话
      send(200, await createTaskFromInput(query, firewall, source || "web", { replyTo }));
      return;
    }
    if (req.method === "POST" && req.url.startsWith("/api/task/")) {
      const parts = req.url.split("/"); // /api/task/:id/:action[/name]
      const id = Number(parts[3]); const act = parts[4]; const selName = parts[5] ? decodeURIComponent(parts[5]) : null;
      const t = taskService.getTask(id);
      if (!t) { send(404, { error: "task not found" }); return; }
      // 用户从候选列表选择精确规则名：用新 name 重跑 candidate 阶段
      if (act === "select" && t.status === "awaiting_selection" && t._candidate) {
        const cand = t._candidate;
        try {
          send(200, await taskService.actOnTask(id, "select", {
            params: { name: selName, keyword: cand.keyword },
            firewall: cand.firewall,
            step: `用户从候选选中：${selName}`,
          }));
        } catch (e) {
          send(400, { error: String(e.message || e) });
        }
        return;
      }
      // 批量选择执行：POST /api/task/:id/select-multi，body: {names: ["name1", "name2", ...]}
      if (act === "select-multi") {
        const { names } = JSON.parse(await body());
        try {
          send(200, await taskService.startBatchSelection(id, names));
        } catch (e) {
          send(400, { error: String(e.message || e) });
        }
        return;
      }
      if (["approve", "reject", "confirm", "cancel"].includes(act)) {
        try {
          send(200, await taskService.actOnTask(id, act));
        } catch (e) {
          const message = String(e.message || e);
          send(message === "变更计划已变化，请重新生成候选计划" ? 409 : 400, { error: message });
        }
        return;
      }
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
    // 网络拓扑（概览侧栏「网络拓扑」视图数据源）
    if (req.method === "GET" && req.url === "/api/topology") {
      send(200, await getTopology());
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
