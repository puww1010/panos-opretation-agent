#!/usr/bin/env node
// PAN-OS 防火墙 Agent 控制台 - 后端 v4（任务系统 + LLM 多提供方）
// 纯 Node http + MCP SDK。任务类型：query(查询) / inspect(巡检) / change(变更审批闭环)
const http = require("http");
const fs = require("fs");
const path = require("path");
// MCP SDK 可选加载（未安装则纯 direct 模式，不影响核心功能）
let Client = null, StdioClientTransport = null;
try {
  ({ Client } = require("@modelcontextprotocol/sdk/client/index.js"));
  ({ StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js"));
} catch (e) { console.warn("[agent] MCP SDK 未安装 → 纯 direct 模式（可选：npm install 启用 MCP 增强层）"); }

// ── 环境配置（零 WorkBuddy 依赖）──
// MCP server（可选增强层）：配置 MCP_SRC/MCP_CWD 才启用；未配置或连接失败 → 纯 direct 模式
const NODE = process.env.MCP_NODE || process.env.NODE || "node";
const SRC = process.env.MCP_SRC || "";
const CWD = process.env.MCP_CWD || "";
const MCP_NODE_PATH = process.env.MCP_NODE_PATH || (CWD ? require("path").join(CWD, "node_modules") : "");
const MCP_ENABLED = process.env.MCP_ENABLED !== "0" && !!SRC && !!Client;
const CFG = process.env.PANOS_FIREWALLS_CONFIG || "/Users/vpeng/.config/panos-mcp/firewalls.json";
const PORT = process.env.PORT || 8080;
const REPORTS_DIR = path.join(__dirname, "..", "reports");

// ── LLM 提供方（配置了 key 才可用）──
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
      data[k] = { ...LLM_SEED[k], key: process.env[LLM_SEED[k].env] };
    }
  }
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
let currentLLM = process.env.LLM_PROVIDER || Object.keys(LLM_PROVIDERS).find((k) => LLM_PROVIDERS[k].key) || "keyword";

let client = null;
const tasks = [];        // 任务列表
const history = [];      // 查询历史
const llmLogs = [];      // LLM 决策日志（证明 LLM 规划起作用）
const MAX_HISTORY = 20;
const MAX_LLM_LOGS = 50;
let taskSeq = 0;

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
const CHANGE_TEMPLATES = {
  add_address_object: { label: "创建地址对象", plan: (p) => `新增地址对象 ${p.name} = ${p.value}（${p.type}），零流量影响（未引用）`, params: ["name", "value"] },
  delete_address_object: { label: "删除地址对象", plan: (p) => `删除地址对象 ${p.name}`, params: ["name"] },
  block_ip: { label: "封禁 IP", plan: (p) => `封禁 ${p.ip}：建地址对象 + deny 策略置顶${p.expiry ? "，临时至 " + p.expiry : "，永久"}`, params: ["ip"] },
};

async function connect() {
  if (!MCP_ENABLED) { console.log("[agent] MCP 未启用（纯 direct 模式）"); client = null; return; }
  try {
    const transport = new StdioClientTransport({
      command: NODE, args: ["--experimental-strip-types", SRC], cwd: CWD,
      env: { ...process.env,
        NODE_PATH: MCP_NODE_PATH,
        PANOS_FIREWALLS_CONFIG: CFG,
        PANOS_PROXY: "", HTTPS_PROXY: "", https_proxy: "", HTTP_PROXY: "", http_proxy: "", ALL_PROXY: "", all_proxy: "", NO_PROXY: "*", no_proxy: "*" },
    });
    client = new Client({ name: "panos-agent", version: "4.0.0" });
    await client.connect(transport);
    console.log("[agent] MCP connected");
  } catch (e) {
    console.error("[agent] MCP 连接失败，降级纯 direct 模式:", e.message);
    client = null;
  }
}

// ── 直接调防火墙 API（绕开 MCP server 故障 + Node fetch 代理干扰）──
const https = require("https");
const { execFile } = require("child_process");
const FEISHU_CHAT = process.env.FEISHU_CHAT_ID || "oc_0238b0ea1d6d7a74180cfce85b18cf67";
// 飞书发送：优先群机器人 Webhook（零依赖），可配 app_id/app_secret 走 API
const FEISHU_WEBHOOK = process.env.FEISHU_WEBHOOK_URL || "";
const FEISHU_APP_ID = process.env.FEISHU_APP_ID || "";
const FEISHU_APP_SECRET = process.env.FEISHU_APP_SECRET || "";
let feishuToken = null, feishuTokenTs = 0;
async function feishuGetToken() {
  if (feishuToken && Date.now() - feishuTokenTs < 5400000) return feishuToken;
  const b = await new Promise((resolve, reject) => {
    const d = JSON.stringify({ app_id: FEISHU_APP_ID, app_secret: FEISHU_APP_SECRET });
    const req = https.request({ host: "open.feishu.cn", path: "/open-apis/auth/v3/tenant_access_token/internal", method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(d) }, rejectUnauthorized: false }, (res) => {
      let x = ""; res.on("data", (c) => (x += c)); res.on("end", () => resolve(x));
    });
    req.on("error", reject); req.end(d);
  });
  try { const o = JSON.parse(b); if (o.code === 0) { feishuToken = o.tenant_access_token; feishuTokenTs = Date.now(); return feishuToken; } throw new Error(o.msg); } catch (e) { throw new Error("飞书 token 失败: " + e.message); }
}
async function feishuSend(text) {
  try {
    if (FEISHU_WEBHOOK) {  // 群机器人 webhook
      const b = await new Promise((resolve, reject) => {
        const d = JSON.stringify({ msg_type: "text", content: { text } });
        const req = https.request(FEISHU_WEBHOOK, { method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(d) }, rejectUnauthorized: false }, (res) => {
          let x = ""; res.on("data", (c) => (x += c)); res.on("end", () => resolve(x));
        });
        req.on("error", reject); req.end(d);
      });
      const o = JSON.parse(b);
      return o.code === 0 ? { ok: true, data: o.data ? o.data.message_id : null } : { ok: false, error: o.msg || JSON.stringify(o) };
    }
    if (FEISHU_APP_ID && FEISHU_APP_SECRET) {  // 自建应用 API
      const token = await feishuGetToken();
      const b = await new Promise((resolve, reject) => {
        const d = JSON.stringify({ receive_id: FEISHU_CHAT, msg_type: "text", content: JSON.stringify({ text }) });
        const req = https.request({ host: "open.feishu.cn", path: "/open-apis/im/v1/messages?receive_id_type=chat_id", method: "POST", headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token, "Content-Length": Buffer.byteLength(d) }, rejectUnauthorized: false }, (res) => {
          let x = ""; res.on("data", (c) => (x += c)); res.on("end", () => resolve(x));
        });
        req.on("error", reject); req.end(d);
      });
      const o = JSON.parse(b);
      return o.code === 0 ? { ok: true, data: o.data ? o.data.message_id : null } : { ok: false, error: o.msg || JSON.stringify(o) };
    }
    return { ok: false, error: "未配置 FEISHU_WEBHOOK_URL 或 FEISHU_APP_ID/SECRET" };
  } catch (e) { return { ok: false, error: String(e.message || e).slice(0, 200) }; }
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

function httpsGet(path, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
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
  return await httpsGet(`/api/?type=commit&cmd=${encodeURIComponent(`<commit><description>${desc}</description></commit>`)}&key=${DIRECT_KEY}`);
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
  let url = `https://${DIRECT_HOST}:${DIRECT_PORT}/api/?type=config&action=move&xpath=${encodeURIComponent(xpath)}&where=${encodeURIComponent(where)}&key=${DIRECT_KEY}`;
  if (destination) url += `&destination=${encodeURIComponent(destination)}`;
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

async function callToolImpl(name, args = {}, firewall) {
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
  if (["get_firewall_info", "get_system_resources", "get_active_sessions", "get_content_versions", "get_wildfire_status", "get_security_rules", "get_address_objects", "get_interfaces", "get_zones", "get_licenses", "get_routing_table", "get_ha_status", "get_ipsec_tunnels", "get_globalprotect_users", "get_application_filters"].includes(name)) {
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

// ── LLM 分类（当前提供方）──
async function llmClassify(role, system, input, timeoutMs = 20000) {
  const p = LLM_PROVIDERS[currentLLM];
  if (!p || !p.key) return null;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 20000);
  const t0 = Date.now();
  try {
    const r = await fetch(`${p.base_url}/chat/completions`, {
      method: "POST", signal: ac.signal,
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${p.key}` },
      body: JSON.stringify({ model: p.model, temperature: 0,
        messages: [{ role: "system", content: system }, { role: "user", content: input }],
        // deepseek / qwen3.8-max / kimi-k2.6 均为思考型模型：禁用 thinking 避免超时/正文空
        ...(["deepseek", "qwen", "kimi"].includes(currentLLM) ? { thinking: { type: "disabled" } } : {}) }),
    });
    if (!r.ok) { console.error("[agent] LLM http", r.status); return null; }
    const d = await r.json();
    const text = d.choices?.[0]?.message?.content || "";
    recordLLM(role, input, text, Date.now() - t0);
    return text;
  } catch (e) { console.error("[agent] LLM error:", e.message); recordLLM(role, input, "ERROR: " + e.message, Date.now() - t0); return null; }
  finally { clearTimeout(timer); }
}

async function llmResolveAction(input) {
  const list = Object.entries(ACTIONS).map(([k, v]) => `${k}: ${v.label}（如"${v.keywords[0]}"）`).join("\n");
  const text = await llmClassify("意图规划",
    `你是防火墙运维意图分类器。从动作列表选一个 key；若输入与防火墙查询无关输出 {"action":null}；若输入是配置变更请求（创建/删除/封禁/改策略）输出 {"action":"change"}；若输入是故障诊断请求（连不上/不通/访问不了/排查/诊断/健康检查/某IP什么情况/一直扫描）输出 {"action":"diag"}；若输入是审计/配置变更查询（谁改的/审计/变更记录/谁修改/谁删了/配置变更）输出 {"action":"audit"}。只输出 JSON：{"action":"<key>"}。\n动作列表（含 diag）:\n${list}\ndiag: 故障诊断（连不上/不通/访问不了/排查/诊断/健康检查/什么情况）`, input);
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
    `你是防火墙配置变更解析器。从模板列表选一个 template，并提取参数（ip 为合法 IPv4）。

【重要区分规则】
- block_ip / allow_ip：用于**创建新的**封禁/放行策略（"添加/新建/创建一条封禁/放行/拒绝/允许XX的策略"）。即使提到"置顶/最顶部"，只要是"创建新策略"场景，就用 block_ip / allow_ip。
- move_security_rule：仅用于**移动已有的**策略（"把XX移到YY"）。必须有明确的已有规则名 name，name 不能为空。
  - "添加一条封禁XX的策略在最顶部" → block_ip，不是 move_security_rule
  - "把 block-social 移到 deny-all 上面" → move_security_rule (name=block-social, where=before, destination=deny-all)

若无法匹配模板输出 {"template":null}。只输出 JSON：{"template":"<key>","params":{...}}。\n${tmplList}`, input);
  if (!text) return null;
  try {
    const m = text.match(/\{[\s\S]*\}/);
    const o = JSON.parse(m ? m[0] : "{}");
    if (!o.template || !CHANGE_TEMPLATES[o.template]) return null;
    // 安全网：LLM 误把"添加封禁/放行策略"归为 move_security_rule（name 为空），自动纠正
    if (o.template === "move_security_rule" && (!o.params || !o.params.name || String(o.params.name).trim() === "")) {
      const ipMatch = input.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      if (ipMatch) {
        const ip = ipMatch[1];
        const isAllow = /放行|允许|白名单|allow/i.test(input);
        o.template = isAllow ? "allow_ip" : "block_ip";
        o.params = { ip };
      } else {
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
  const ctx = sections.map((s) => "[" + s.step + "] " + s.result).join("\n");
  const statCtx = stats ? "\n日志统计(前10):\n" + JSON.stringify(stats).slice(0, 1200) : "";
  const text = await llmClassify("诊断综合",
    `你是网络/PAN-OS 防火墙诊断专家。基于以下诊断数据,分析用户症状"${input}"的根因,并给出可执行建议。\n数据:\n${ctx}${statCtx}\n严格输出 JSON:{"verdict":"<一句话根因结论>","confidence":"高/中/低","recommendation":"<具体行动>"}`,
    input, 45000);
  if (!text) return null;
  const m = text.match(/\{[\s\S]*?\}/);
  if (!m) return { verdict: text.slice(0, 300), confidence: "?", recommendation: "" };
  try { return JSON.parse(m[0]); } catch { return { verdict: text.slice(0, 300), confidence: "?", recommendation: "" }; }
}
async function llmParseDiag(input) {
  const text = await llmClassify("诊断规划",
    `你是网络诊断解析器。判断用户症状属于：connectivity（连通性排查，涉及源/目的/IP/端口/连不上/不通/访问不了）、threat_profile（威胁源画像，涉及"什么情况/一直扫描/攻击/画像"且给定了IP）、generic（通用健康检查）。提取参数：ip（IPv4）、port（端口）、direction（inbound/outbound）、target_label（如"外网"）、minutes（时间窗口分钟数，如"最近10分钟"=10、"最近1小时"=60、"今天"=1440，无则默认60）。无法判断输出 {"type":null}。只输出 JSON：{"type":"<t>","params":{}}。`, input);
  if (!text) return null;
  try {
    const m = text.match(/\{[\s\S]*\}/);
    const o = JSON.parse(m ? m[0] : "{}");
    if (o.params && o.params.minutes !== undefined) o.params.minutes = Number(o.params.minutes) || 60;
    return o;
  } catch { return null; }
}

// ── 任务系统 ──
function newTask(type, input, extra = {}) {
  return { id: ++taskSeq, type, input, status: "pending", steps: [], result: null, error: null, createdAt: new Date().toLocaleString("zh-CN"), ...extra };
}
function saveTask(t) { const i = tasks.findIndex((x) => x.id === t.id); if (i >= 0) tasks[i] = t; }

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
    t.result = { label: ACTIONS[action].label, results };
    t.status = "done";
    history.unshift({ ts: new Date().toLocaleString("zh-CN"), input: String(t.input), action, label: ACTIONS[action].label });
    if (history.length > MAX_HISTORY) history.pop();
  }
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
}

// 变更执行（candidate 阶段）
async function runChangeCandidate(t, tmpl, params, firewall) {
  t.status = "executing";
  const p = { ...params, type: params.type || "ip-netmask" };
  // name 合法化：仅对"创建"类操作生效（add_address_object / block_ip / allow_ip）
  // 删除/移动/禁用/启用必须使用精确的已有规则名，不得"修正"
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
    const ts = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const name = `block-${p.ip}-${ts}`;
    await directOp(`<request><address><entry name="${name}"><ip-netmask>${p.ip}</ip-netmask></entry></address></request>`);
    await directOp(`<request><security><rules><entry name="${name}"><from><member>any</member></from><to><member>any</member></to><source><member>${name}</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>deny</action></entry></rules></security></request>`);
    t.steps.push("candidate: address+deny rule (directOp)");
    p._objName = name;
    // 3) 默认置顶（block_ip 语义就是"封禁+置顶"，与 plan 描述一致）
    // 注意：directOp 追加规则在末尾，必须 move 才能置顶
    try {
      // 改用 directConfigMove，绕开 MCP move_security_rule 的 v3Schema 故障
      const moveXpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='${name}']`;
      const r = await directConfigMove(moveXpath, "top");
      const rtxt = typeof r === "string" ? r : JSON.stringify(r);
      t.steps.push("candidate: move " + name + " to top → " + rtxt.slice(0, 120));
      if (rtxt.includes("success") || rtxt.includes("command succeeded") || rtxt.includes("moved")) {
        t.steps.push("✅ move to top 成功，规则已置顶");
      } else {
        t.steps.push("️ move to top 响应异常，请检查规则位置：" + rtxt.slice(0, 200));
      }
    } catch (e) {
      t.steps.push("⚠️ move to top 失败：" + e.message.slice(0, 120) + "（规则已创建但可能在末尾，请手动置顶）");
    }
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
  } else if (tmpl === "allow_ip") {
    // 放行 IP：对称 block_ip，写 address 对象 + allow 规则（默认置顶）
    const ts = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const name = `allow-${p.ip}-${ts}`;
    const XPATH_BASE = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']`;
    // 1) 地址对象
    const r1 = await directConfigSet(
      `${XPATH_BASE}/address/entry[@name='${name}']`,
      `<ip-netmask>${p.ip}/32</ip-netmask>`
    );
    t.steps.push("candidate: address " + name + " → " + JSON.stringify(r1).slice(0, 80));
    // 2) 安全规则（允许 any → this src）
    const ruleXml = `<from><member>any</member></from><to><member>any</member></to><source><member>${name}</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>allow</action><description>WebUI allow by Agent</description>`;
    const r2 = await directConfigSet(
      `${XPATH_BASE}/rulebase/security/rules/entry[@name='${name}']`,
      ruleXml
    );
    t.steps.push("candidate: allow rule " + name + " → " + JSON.stringify(r2).slice(0, 80));
    p._objName = name;
    // 3) 默认置顶（allow_ip 语义也是"放行+置顶"）
    try {
      const moveXpath = `${XPATH_BASE}/rulebase/security/rules/entry[@name='${name}']`;
      const r3 = await directConfigMove(moveXpath, "top");
      const r3txt = typeof r3 === "string" ? r3 : JSON.stringify(r3);
      t.steps.push("candidate: move " + name + " to top → " + r3txt.slice(0, 120));
      if (r3txt.includes("success") || r3txt.includes("command succeeded") || r3txt.includes("moved")) {
        t.steps.push("✅ move to top 成功，规则已置顶");
      } else {
        t.steps.push("️ move to top 响应异常，请检查规则位置：" + r3txt.slice(0, 200));
      }
    } catch (e) {
      t.steps.push("⚠️ move to top 失败：" + e.message.slice(0, 120) + "（规则已创建但可能在末尾，请手动置顶）");
    }
  }
  t.params = p;
  t.status = "awaiting_commit";
}

// 规则名解析：精确 name 直接返回 {name}；只有模糊 keyword 时把任务停在 awaiting_selection 并 return null
async function resolveRuleTarget(t, p, firewall, verb) {
  if (p.name && /^[a-zA-Z0-9_.\-]+$/.test(p.name)) return { name: p.name };
  await setAwaitingSelection(t, p, firewall, verb, []);
  return null;
}

// 模糊路径专用：读 running config 过滤匹配，转 awaiting_selection 状态
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
    // 走 directOp（<commit>），绕开 MCP commit 工具的 v3Schema 故障
    const r = await directCommit("WebUI Agent: " + (t.templateLabel || t.type));
    const m = String(r).match(/<job>(\d+)<\/job>/) || String(r).match(/jobid[= ]+(\d+)/i) || String(r).match(/<id>(\d+)<\/id>/);
    job = m ? m[1] : null;
    t.steps.push("commit 入队 job=" + (job || "?"));
  } catch (e) {
    t.steps.push("commit 入队失败：" + e.message.slice(0, 80));
    t.status = "done";
    t.result = Object.assign(t.result || {}, { needsManualCommit: true });
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
      const sig = st + "|" + pctVal;
      if (sig !== lastJobSig || i % 15 === 0) {
        t.steps.push(`commit job=${job} status=${st}${pctVal ? ` (${pctVal}%)` : ""}`);
        lastJobSig = sig;
      }
      if (st === "FIN" || st === "FINOK" || stxt.includes("FIN OK")) {
        t.steps.push("commit 完成 (job=" + job + ")");
        t.status = "done";
        t.result = Object.assign(t.result || {}, { job });
        return;
      }
      if (st === "FAIL" || st === "STOPPED" || st === "ERROR") {
        t.steps.push("commit 失败：" + st + " job=" + job);
        t.status = "done";
        t.result = Object.assign(t.result || {}, { job, commitFailed: true });
        return;
      }
    } catch (e) {
      // 单次轮询错误不中断，继续
    }
  }
  t.steps.push("️ commit 超时（10 分钟）：job=" + job + " 可能在防火墙后台仍在执行中。请登录防火墙 Web 界面 → Monitor → Jobs，搜索 job ID " + job + " 查看最终状态，或手动执行 commit");
  t.status = "done";
  t.result = Object.assign(t.result || {}, { needsManualCommit: true, timeout: true, job });
}

// ── 意图 → 任务路由 ──
async function createTaskFromInput(input, firewall, source) {
  let action = null, fromLLM = false;
  for (const [k, v] of Object.entries(ACTIONS)) { if (k === input || v.label === input) action = k; }
  if (!action) {
    action = await llmResolveAction(input);
    if (action) fromLLM = true;
  }
  if (action === "change") {
    const c = await llmExtractChange(input);
    if (!c) return { error: "无法解析变更意图（支持：创建/删除地址对象、封禁 IP）" };
    const tmpl = CHANGE_TEMPLATES[c.template];
    const t = newTask("change", input, { template: c.template, templateLabel: tmpl.label, params: c.params, firewall, source, status: "awaiting_approval" });
    t.plan = tmpl.plan(c.params || {});
    t.steps.push("变更计划已生成，等待审批");
    tasks.push(t);
    return { taskId: t.id, status: t.status, plan: t.plan };
  }
  if (action === "audit") {
    const a = await llmParseAudit(input);
    const t = newTask("audit", input, { firewall, source, audit: a });
    t.decision = `LLM 规划 → 审计查询（${a.minutes} 分钟内${a.object}）`;
    t.steps.push(t.decision);
    tasks.push(t);
    runAuditTask(t, firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); });
    return { taskId: t.id, status: t.status, type: "audit" };
  }
  if (action === "diag") {
    const d = await llmParseDiag(input);
    if (!d || !d.type) return { error: "无法解析诊断意图（示例：内部连不上外网 / 查一下 1.2.3.4 什么情况 / 全面健康检查）" };
    const t = newTask("diag", input, { firewall, source, diag: d });
    t.decision = `LLM 规划 → 诊断 ${d.type}（${LLM_PROVIDERS[currentLLM]?.label}）`;
    t.steps.push(t.decision);
    tasks.push(t);
    runDiagTask(t, firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); });
    return { taskId: t.id, status: t.status, type: "diag" };
  }
  if (action === "inspect") {
    const t = newTask("inspect", input, { firewall, source });
    tasks.push(t);
    runInspectTask(t, firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); });
    return { taskId: t.id, status: t.status, type: "inspect" };
  }
  if (action && ACTIONS[action]) {
    const t = newTask("query", input, { action, firewall, source });
    t.decision = fromLLM ? `LLM 规划 → 动作 ${action}（${LLM_PROVIDERS[currentLLM]?.label}）` : `关键词匹配 → 动作 ${action}`;
    t.steps.push(t.decision);
    tasks.push(t);
    runQueryTask(t, action, firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); });
    return { taskId: t.id, status: t.status, type: "query", label: ACTIONS[action].label };
  }
  return { error: "无法识别意图，试试：设备清单 / 设备状态 / 安全策略 / 威胁日志 / 完整巡检 / 封禁 1.2.3.4" };
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
    t.status = "failed"; t.error = step.msg; return;
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
}

// ── 智能诊断任务 ──
function ipInRules(rules, ip) {
  return rules.filter((r) => {
    const src = r.source?.member, dst = r.destination?.member, act = r.action;
    const hit = (m) => Array.isArray(m) ? m.includes(ip) || m.includes("any") : m === ip || m === "any";
    return hit(src) && hit(dst) && (act === "allow" || act === "deny");
  }).map((r) => ({ name: r["@_name"], action: r.action, disabled: r.disabled === "yes", from: r.from?.member, to: r.to?.member }));
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
  if (overviewCache && Date.now() - overviewTs < 10000) return overviewCache;
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

  if (cancelled) { t.status = "cancelled"; return; }
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
    // 3 路由
    const routes = (await callTool("get_routing_table", {}, firewall))?.entry || [];
    const hasDefault = Array.isArray(routes) && routes.some((r) => (r.destination || "").includes("0.0.0.0"));
    sections.push({ step: "路由可达性", result: hasDefault ? "存在默认路由" : "未发现默认路由（可能影响出网）" });
    // 4 接口
    const ifs = (await callTool("get_interfaces", {}, firewall))?.hw?.entry || [];
    const down = Array.isArray(ifs) ? ifs.filter((i) => i.state === "down").map((i) => i.name) : [];
    sections.push({ step: "接口状态", result: down.length ? "以下接口 down: " + down.join(", ") : "物理接口均 up" });
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
    sections.push({ step: "会话", result: `活跃 ${sess.num_active || 0} / 上限 ${sess.num_max || 0}` });
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
  if (stats) t.result.logStats = stats;
  t.status = "done";
}
const server = http.createServer(async (req, res) => {
  const send = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" }); res.end(JSON.stringify(obj)); };
  const body = () => new Promise((ok) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => ok(b)); });
  try {
    if (req.url === "/favicon.ico") { res.writeHead(204); res.end(); return; }
    // 静态资源：assets/ + 根零散（logo 等），防路径穿越
    if (req.method === "GET") {
      const urlPath = decodeURIComponent(req.url.split("?")[0]);
      const MIME = { ".png":"image/png", ".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".svg":"image/svg+xml", ".gif":"image/gif", ".ico":"image/x-icon", ".webp":"image/webp", ".woff2":"font/woff2" };
      let candidate = null;
      if (urlPath.startsWith("/assets/")) candidate = path.join(__dirname, urlPath);
      else if (/^\/[a-zA-Z0-9_.\-]+$/.test(urlPath) && urlPath !== "/" && urlPath !== "/index.html") candidate = path.join(__dirname, urlPath.slice(1));
      if (candidate && fs.existsSync(candidate)) {
        const real = fs.realpathSync(candidate);
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
      if (provider === "keyword") { currentLLM = "keyword"; send(200, { current: currentLLM }); return; }
      if (LLM_PROVIDERS[provider] && LLM_PROVIDERS[provider].key) { currentLLM = provider; send(200, { current: currentLLM }); return; }
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
    if (req.method === "POST" && req.url === "/api/task") {
      const { query, firewall, source } = JSON.parse(await body());
      if (!client && MCP_ENABLED) { try { await connect(); } catch {} }
      // 区分任务来源：'web'（Web 控制台默认）/ 'feishu'（飞书 bridge 提交）
      send(200, await createTaskFromInput(query, firewall, source || "web"));
      return;
    }
    if (req.method === "POST" && req.url.startsWith("/api/task/")) {
      const parts = req.url.split("/"); // /api/task/:id/:action
      const id = Number(parts[3]); const act = parts[4];
      const t = tasks.find((x) => x.id === id);
      if (!t) { send(404, { error: "task not found" }); return; }
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
        send(200, { taskId: t.id, status: t.status }); return;
      }
      if (act === "approve" && t.status === "awaiting_approval") {
        runChangeCandidate(t, t.template, t.params || {}, t.firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); });
        send(200, { taskId: t.id, status: t.status }); return;
      }
      if (act === "reject" && t.status === "awaiting_approval") { t.status = "cancelled"; t.steps.push("已拒绝"); send(200, { taskId: t.id, status: t.status }); return; }
      if (act === "confirm" && t.status === "awaiting_commit") {
        runChangeCommit(t, t.firewall).catch((e) => { t.status = "failed"; t.error = String(e.message || e); });
        send(200, { taskId: t.id, status: t.status }); return;
      }
      if (act === "cancel" && (t.status === "awaiting_approval" || t.status === "awaiting_commit")) { t.status = "cancelled"; t.steps.push("已取消"); send(200, { taskId: t.id, status: t.status }); return; }
      send(400, { error: "非法操作或状态不匹配: " + t.status });
      return;
    }
    if (req.url === "/api/feishu/status") {
      const running = await feishuDaemonRunning();
      send(200, { chat: FEISHU_CHAT, running, mode: FEISHU_WEBHOOK ? "webhook" : (FEISHU_APP_ID ? "api" : "未配置") });
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
    if (req.method === "GET" && req.url === "/api/history") { send(200, { history }); return; }
    send(404, { error: "Not Found" });
  } catch (e) { send(500, { error: String(e.message || e) }); }
});

server.listen(PORT, async () => {
  console.log(`[agent] PAN-OS Agent 控制台: http://localhost:${PORT}`);
  try { await connect(); } catch (e) { console.error("[agent] MCP connect fail:", e.message); }
});
