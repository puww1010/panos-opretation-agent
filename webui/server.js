#!/usr/bin/env node
// PAN-OS 防火墙 Agent 控制台 - 后端 v4（任务系统 + LLM 多提供方）
// 纯 Node http + MCP SDK。任务类型：query(查询) / inspect(巡检) / change(变更审批闭环)
const http = require("http");
const fs = require("fs");
const path = require("path");
const { createPanosAdapter } = require("./adapters/panos-adapter");
const { createLlmService } = require("./services/llm-service");
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

const LLM_CONFIG_PATH = process.env.LLM_CONFIG || path.join(__dirname, "llm-config.json");
const LLM_CHOICE_FILE = process.env.LLM_CHOICE_FILE || path.join(__dirname, "..", "cfgs", "llm-choice.json");

const history = [];      // 查询历史
const metricsBuffer = []; // KPI 指标采样环形缓冲（报表预留，见 spec §12.1 metrics 表）
const MAX_HISTORY = 20;
const MAX_METRICS = 720; // 指标采样上限（10s 一次 ≈ 2 小时滚动窗口）

let taskService;
const llmService = createLlmService({
  configFile: LLM_CONFIG_PATH,
  choiceFile: LLM_CHOICE_FILE,
  taskLister: () => taskService ? taskService.listTasks() : [],
});

// Task Service owns task/audit in-memory state and JSON persistence. The server only composes dependencies.
taskService = createTaskService({
  panosAdapter,
  taskFile: TASKS_FILE,
  auditFile: AUDIT_FILE,
  auditLogReader: (firewall) => callTool("get_config_logs", { nlogs: 200 }, firewall),
  actionDefinitions: () => ACTIONS,
  toolCaller: callTool,
  querySummarizer: (...args) => llmService.summarizeQuery(...args),
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
    synthesize: (...args) => llmService.synthesizeDiagnostic(...args),
  },
  deferExecution: true,
});

function llmProviderLabel() {
  const current = llmService.getCurrent();
  return llmService.getProvider(current)?.label || current;
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
// ── 会话归组（方案C）：显式 replyTo → 沿链并入目标会话；否则按时间窗自动归组 ──
const SESSION_GAP_MS = 5 * 60 * 1000; // 连续任务间隔 <5 分钟 → 同一会话
let _convSeq = 0;
function nextConvId() {
  // 从现有任务恢复会话计数（重启后不重复编号）
  if (!_convSeq) {
    for (const x of taskService.listTasks()) {
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
  const tasks = taskService.listTasks();
  if (replyTo) {
    const target = tasks.find((x) => x.id === Number(replyTo));
    if (target) {
      if (!target.conversationId) { target.conversationId = nextConvId(); taskService.saveTask(target); } // 惰性迁移老任务（落盘防重启计数重复）
      return { conversationId: target.conversationId, replyTo: target.id };
    }
  }
  const last = tasks[tasks.length - 1];
  if (last) {
    const t0 = Date.parse(String(last.createdAt || "").replace(/\//g, "-"));
    if (!isNaN(t0) && Date.now() - t0 < SESSION_GAP_MS) {
      if (!last.conversationId) { last.conversationId = nextConvId(); taskService.saveTask(last); }
      return { conversationId: last.conversationId, replyTo: null };
    }
  }
  return { conversationId: nextConvId(), replyTo: null };
}

async function createTaskFromInput(input, firewall, source, opts = {}) {
  // 重复任务去重：先扫描 active 任务，发现与 input normalize 后完全相同则取消旧任务
  const dup = dedupeActiveTask(input);
  // 会话归组（方案C）：显式 replyTo（前端"↩ 追问这条"）→ 并入目标会话；否则按时间窗归组
  const conv = resolveConversation(opts.replyTo);
  let action = null, fromLLM = false, minutes = null;
  for (const [k, v] of Object.entries(ACTIONS)) { if (k === input || v.label === input) action = k; }
  if (!action) {
    const resolved = await llmService.resolveAction(input, { conversationId: conv.conversationId, actions: ACTIONS });
    if (resolved) { action = resolved.action; minutes = resolved.minutes; if (action) fromLLM = true; }
  }
  if (action === "change") {
    const c = await llmService.extractChange(input, { conversationId: conv.conversationId, changeTemplates: CHANGE_TEMPLATES });
    if (!c) return { error: "无法解析变更意图（支持：创建/删除地址对象、封禁/放行 IP、移动/删除/禁用/启用安全策略）" };
    const tmpl = CHANGE_TEMPLATES[c.template];
    const params = normalizeChangeParams(c.template, c.params);
    // 规则类模板（delete/disable/enable）若只有模糊 keyword，先预检转 awaiting_selection
    const RULE_TMPL = ["delete_security_rule", "set_security_rule_disabled", "set_security_rule_enabled"];
    const needPrecheck = RULE_TMPL.includes(c.template) && !(params.name && /^[a-zA-Z0-9_.\-]+$/.test(params.name));
    const t = taskService.createTask("change", input, { template: c.template, templateLabel: tmpl.label, params, firewall, source, conversationId: conv.conversationId, replyTo: conv.replyTo, status: needPrecheck ? "awaiting_selection" : "awaiting_approval" });
    t.plan = tmpl.plan(params);
    t.planFingerprint = planFingerprint({ template: c.template, params, firewall });
    if (needPrecheck) {
      // 同步做一次预检（list candidates）→ 任务状态已是 awaiting_selection，前端直接展示候选按钮
      try { await taskService.prepareRuleSelection(t, tmpl.label); }
      catch (e) { t.status = "failed"; t.error = e.message; taskService.saveTask(t); }
    } else {
      t.steps.push("变更计划已生成，等待审批");
    }
    t.llm = llmService.getCurrent();  // 记录处理该任务时实际使用的 LLM provider key
    taskService.addTask(t);
    taskService.recordAudit(t, { taskId: t.id, action: "created", from: null, to: t.status, at: new Date().toISOString() });
    return needPrecheck && t.status === "awaiting_selection"
      ? { taskId: t.id, status: t.status, plan: t.plan, candidates: t.result.matched, totalMatches: t.result.totalMatches }
      : { taskId: t.id, status: t.status, plan: t.plan };
  }
  if (action === "audit") {
    const a = await llmService.parseAudit(input);
    const t = taskService.dispatchTask("audit", input, { firewall, source, audit: a, conversationId: conv.conversationId, replyTo: conv.replyTo }, (task) => {
      task.llm = llmService.getCurrent();
      task.decision = `LLM 规划 → 审计查询（${a.minutes} 分钟内${a.object}）（${llmProviderLabel()}）`;
      task.steps.push(task.decision);
    }, (task) => taskService.runAudit(task));
    return { taskId: t.id, status: t.status, type: "audit" };
  }
  if (action === "diag") {
    const d = await llmService.parseDiagnostic(input, conv.conversationId);
    // 诊断规划判定为非诊断请求（type:null，如"画个拓扑图"）→ 降级自由问答，
    // 不再生硬报"无法解析诊断意图"——让 LLM 分析推理回答（16:48 飞书案例根因）
    if (!d || !d.type) return await createFreeAnswer(input, firewall, source, conv);
    const t = taskService.dispatchTask("diag", input, { firewall, source, diag: d, conversationId: conv.conversationId, replyTo: conv.replyTo }, (task) => {
      task.llm = llmService.getCurrent();
      task.decision = `LLM 规划 → 诊断 ${d.type}（${llmProviderLabel()}）`;
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
      if (fromLLM) task.llm = llmService.getCurrent();
      task.decision = fromLLM ? `LLM 规划 → 动作 ${action}（${llmProviderLabel()}）${minutes ? "，时间窗口 " + minutes + " 分钟" : ""}` : `关键词匹配 → 动作 ${action}`;
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
  const text = await llmService.answerFree(input, { conversationId: opts.conversationId, firewallContext: fwCtx });
  const t = taskService.createTask("chat", input, { firewall, source, conversationId: opts.conversationId, replyTo: opts.replyTo });
  t.llm = llmService.getCurrent();
  if (source) t.source = source;  // 标记任务来源（'feishu'/'web'/'bridge'），用于 WebUI 区分展示
  t.decision = `LLM 兜底 → 自由问答（${llmProviderLabel()}）`;
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
  const dup = taskService.listTasks().find((x) => {
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
  taskService.saveTask(dup);
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
      send(200, { current: llmService.getCurrent(), note: "保持用户选择" });
      return;
    }
    if (req.method === "GET" && req.url === "/api/actions") {
      send(200, { actions: Object.fromEntries(Object.entries(ACTIONS).map(([k, v]) => [k, v.label])),
        llm: llmService.getCurrent() !== "keyword", model: llmService.getCurrent() !== "keyword" ? llmService.getModel() : null });
      return;
    }
    if (req.method === "GET" && req.url === "/api/llm") {
      send(200, llmService.getPublicConfig());
      return;
    }
    if (req.method === "POST" && req.url === "/api/llm/config") {
      const { provider, base_url, model, key, env, label } = JSON.parse(await body());
      try { send(200, llmService.saveProvider({ provider, base_url, model, key, env, label })); }
      catch (e) { send(e.message === "provider 必填且仅小写字母数字下划线" ? 400 : 500, { error: e.message === "provider 必填且仅小写字母数字下划线" ? e.message : "写入 llm-config.json 失败：" + e.message }); }
      return;
    }
    if (req.method === "POST" && req.url === "/api/llm/config/delete") {
      const { provider } = JSON.parse(await body());
      try { send(200, llmService.deleteProvider(provider)); } catch { send(200, { ok: true }); }
      return;
    }
    if (req.method === "POST" && req.url === "/api/llm/select") {
      const { provider } = JSON.parse(await body());
      // 用户选择持久化：写 cfgs/llm-choice.json，刷新/重启都保持，只有手动切换才变
      const selected = llmService.selectProvider(provider);
      if (selected.ok) { send(200, { current: selected.current }); return; }
      const v = selected.provider;
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
    if (req.method === "GET" && req.url === "/api/llm/log") { send(200, { logs: llmService.getLogs() }); return; }
    if (req.method === "POST" && req.url === "/api/llm/test") {
      const { text } = JSON.parse(await body());
      const t0 = Date.now();
      const out = await llmService.classify("手动测试", "你是防火墙运维意图分类器。输出 JSON：{\"action\":\"<key>\"}。可选 key：device(设备状态)/security(安全策略)/threat(威胁日志)/traffic(流量日志)/inspect(完整巡检)/change(变更)/diag(诊断)/null(无关)", text || "");
      send(200, { output: out, ms: Date.now() - t0, provider: llmService.getCurrent() });
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
