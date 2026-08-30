#!/usr/bin/env node
// PAN-OS 防火墙 Agent 控制台 - 后端 v4（任务系统 + LLM 多提供方）
// 纯 Node http + MCP SDK。任务类型：query(查询) / inspect(巡检) / change(变更审批闭环)
const fs = require("fs");
const path = require("path");
const { createApp } = require("./app");
const { createPanosAdapter } = require("./adapters/panos-adapter");
const { createAuthService } = require("./services/auth-service");
const { createDashboardService } = require("./services/dashboard-service");
const { createLlmService } = require("./services/llm-service");
const { createTaskPlanner } = require("./services/task-planner");
const { createApiRouter } = require("./routes/api-routes");
const { createStaticRouter } = require("./routes/static-routes");
const { createTaskService, normalizeChangeParams } = require("./services/task-service");
const { buildSecurityHeaders, isSameOriginApiPath } = require("./lib/security");
const { planFingerprint } = require("./lib/task-governance");
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
  directOp,
  deepLog,
  filterByMinutes,
  fmtTop,
  getDefaultFirewall,
  xmlEntries,
} = panosAdapter;

// ── WebUI 认证（发布公网前必须启用；所有 /api/* 需 token，飞书 bridge 用 internal_token）──
// 用户主动操作类接口：通过认证后刷新 lastSeen（轮询类 GET 不在此列——挂机不续命）
function authTouchIfUserAction(req, token) {
  if (!token || authService.isInternalToken(token)) return;
  const p = req.url.split("?")[0];
  if (/^\/api\/task\//.test(p) || p === "/api/llm/select" || p === "/api/llm/save" || p === "/api/llm/del"
    || p === "/api/auth/change-password" || p === "/api/feishu/send" || p === "/api/feishu/push-report"
    || p === "/api/tasks/clean" || p === "/api/auth/keepalive") {
    authService.touch(token);
  }
}

const LLM_CONFIG_PATH = process.env.LLM_CONFIG || path.join(__dirname, "llm-config.json");
const LLM_CHOICE_FILE = process.env.LLM_CHOICE_FILE || path.join(__dirname, "..", "cfgs", "llm-choice.json");
const authService = createAuthService({ authFile: AUTH_FILE });
const staticRouter = createStaticRouter({ rootDirectory: __dirname });

const dashboardService = createDashboardService({
  callTool,
  directOp,
  xmlEntries,
  healthSummary: buildHealthSummary,
  firewallHost: getDefaultFirewall().host,
  topologyNames: () => {
    try { return JSON.parse(fs.readFileSync(path.join(__dirname, "../cfgs/topology.json"), "utf-8")) || { devices: {} }; }
    catch { return { devices: {} }; }
  },
});
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
  queryHistoryRecorder: (entry) => dashboardService.recordHistory(entry),
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
const taskPlanner = createTaskPlanner({
  taskService,
  llmService,
  actions: ACTIONS,
  changeTemplates: CHANGE_TEMPLATES,
  normalizeChangeParams,
  planFingerprint,
  callTool,
});
const apiRouter = createApiRouter({
  dashboardService,
  llmService,
  taskService,
  authService,
  actions: () => ACTIONS,
  isApiPath: isSameOriginApiPath,
  firewalls: () => { try { return JSON.parse(fs.readFileSync(CFG, "utf-8")).firewalls.map(({ name, host }) => ({ name, host })); } catch { return []; } },
  feishu: {
    status: async () => ({ chat: FEISHU_CHAT, running: await feishuDaemonRunning(), lark: LARK_CLI }),
    send: feishuSend,
    latestReport: () => { const files = fs.existsSync(REPORTS_DIR) ? fs.readdirSync(REPORTS_DIR).filter((file) => file.startsWith("compliance-") && file.endsWith(".md")).sort().reverse() : []; return files.length ? "【PAN-OS 合规报告 " + files[0] + "】\n" + fs.readFileSync(path.join(REPORTS_DIR, files[0]), "utf-8").slice(0, 1500) : null; },
  },
});

const server = createApp({
  apiRouter,
  staticRouter,
  buildSecurityHeaders,
  createTask: taskPlanner.createTaskFromInput,
  ensureConnected: async () => { if (!panosAdapter.isConnected()) await connect(); },
  touchIfUserAction: authTouchIfUserAction,
});

server.listen(PORT, async () => {
  console.log(`[agent] PAN-OS Agent 控制台: http://localhost:${PORT}`);
  try { await connect(); } catch (e) { console.error("[agent] MCP connect fail:", e.message); }
});
