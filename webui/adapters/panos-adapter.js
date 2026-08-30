const fs = require("fs");
const https = require("https");
const path = require("path");
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");

function createPanosAdapter({
  cfgPath,
  toolsConfigPath,
  nodeBin = "node",
  panosMcpDir,
  sourcePath,
  workingDirectory,
  directFirewall,
  toolRoutes,
  callMcpTool,
  callDirectTool,
} = {}) {
  const NODE = nodeBin;
  const PANOS_MCP_DIR = panosMcpDir || "";
  const SRC = sourcePath || "";
  const CWD = workingDirectory || PANOS_MCP_DIR;
  const CFG = cfgPath || "";
  let client = null;
  const mcpInfo = { pid: null, startedAt: null, status: "unknown" };

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
  // 记录 MCP 子进程 PID/启动时间（避开 pgrep EPERM；不同 SDK 版本 process 字段名不同）
  mcpInfo.startedAt = Date.now();
  mcpInfo.status = "online";
  try {
    const proc = transport && (transport.process || transport._process || null);
    if (proc && proc.pid) mcpInfo.pid = proc.pid;
  } catch {}
  console.log("[agent] MCP connected, child pid:", mcpInfo.pid);
}


const DIRECT_FW = directFirewall || (cfgPath && fs.existsSync(cfgPath) ? (JSON.parse(fs.readFileSync(cfgPath, "utf-8")).firewalls[0] || {}) : {});
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
// 改进1：按时间桶统计 action 分布（让 LLM/用户看到"何时 reset-both 多、何时全 allow"的时间线趋势）
// 返回如 ["16:50 allow×2 reset-both×5", "17:00 allow×10", ...]，按时间升序
function fmtLogTime(d) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:00`;
}
function actionTimeline(entries, bucketMinutes = 10) {
  const buckets = new Map();
  for (const e of entries) {
    const t = Date.parse(String(e.receive_time || "").replace(/\//g, "-"));
    if (isNaN(t)) continue;
    const b = Math.floor(t / (bucketMinutes * 60000)) * (bucketMinutes * 60000);
    const a = e.action || "?";
    if (!buckets.has(b)) buckets.set(b, {});
    buckets.get(b)[a] = (buckets.get(b)[a] || 0) + 1;
  }
  return [...buckets.entries()]
    .sort((x, y) => x[0] - y[0])
    .map(([ts, cnt]) => {
      const d = new Date(ts);
      const hh = String(d.getHours()).padStart(2, "0");
      const mm = String(d.getMinutes()).padStart(2, "0");
      return `${hh}:${mm} ${Object.entries(cnt).sort((a, b) => b[1] - a[1]).map(([a, c]) => `${a}×${c}`).join(" ")}`;
    });
}
async function deepLog(type, opts = {}) {
  const { minutes = 60, nlogs = 200, query = "" } = opts;
  const data = await directLog(type, nlogs, query);
  const entries = (data.entry || []).filter((e) => !e._raw || Object.keys(e).length > 1);
  const windowed = filterByMinutes(entries, minutes);
  // 窗口内无数据时降级用全部样本（避免"无统计"误导），并标注时间范围
  const effective = windowed.length ? windowed : entries;
  const top = logStats(effective, ["src", "dst", "app", "action", "subtype", "severity"]);
  // 改进2：数据时间范围（让 verdict 明确"基于什么时间段的数据"）
  const times = effective.map((e) => e.receive_time).filter(Boolean).sort();
  return {
    entries: effective, minutes, nlogs, top,
    // 改进1：时间线趋势
    timeline: actionTimeline(effective, 10),
    timeRange: times.length ? (times[0] + " → " + times[times.length - 1]) : "",
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
  if (callMcpTool || callDirectTool) {
    const route = toolRoute(name);
    if (route === "direct") {
      if (!callDirectTool) throw new Error("direct transport unavailable");
      return callDirectTool(name, args, firewall);
    }
    if (!callMcpTool) throw new Error("MCP transport unavailable");
    return callMcpTool(name, args, firewall);
  }
  const key = name + "|" + (firewall || "") + "|" + JSON.stringify(args || {});
  const hit = toolCache.get(key);
  const ttl = CACHE_TTL[name] || CACHE_TTL.default;
  if (hit && Date.now() - hit.ts < ttl) return hit.data;
  const data = await callToolImpl(name, args, firewall);
  toolCache.set(key, { data, ts: Date.now() });
  return data;
}

// ── 工具级路由配置（tools-config.json，按工具指定 mcp/direct/auto）──
const TOOLS_CONFIG_PATH = toolsConfigPath;
let TOOL_ROUTES = toolRoutes || {};
if (!toolRoutes && TOOLS_CONFIG_PATH) {
  try { TOOL_ROUTES = JSON.parse(fs.readFileSync(TOOLS_CONFIG_PATH, "utf-8")); }
  catch (e) { console.warn("[agent] tools-config.json 未找到或无效，全部 auto 模式:", TOOLS_CONFIG_PATH); }
}
function toolRoute(name) { const r = (TOOL_ROUTES.routes && TOOL_ROUTES.routes[name]) || TOOL_ROUTES._default || "auto"; return r; }

// 日志条数估算：指定时间窗口时按"每分钟约 4 条"估算条数，让返回数据覆盖用户要求的时间跨度
// （默认 20 条只覆盖最近几秒；过去 4 小时→约 960 条，上限 1000；保证窗口内数据充分采样）
function logNlogs(args, baseDefault = 20) {
  if (args.nlogs) return args.nlogs;
  if (args.minutes) {
    const est = Math.round(args.minutes * 4);
    return Math.max(200, Math.min(1000, est));
  }
  return baseDefault;
}
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
    const nlogs = logNlogs(args);
    // minutes 支持（改进）：用户说"过去N小时/分钟" → 生成 receive_time 窗口过滤，避免只拉最新 N 条
    let query = args.query || "";
    if (args.minutes) {
      const from = fmtLogTime(new Date(Date.now() - args.minutes * 60000));
      const to = fmtLogTime(new Date());
      const win = `(receive_time geq '${from}' and receive_time leq '${to}')`;
      query = query ? `(${query}) and ${win}` : win;
      console.log(`[agent] ${name} minutes=${args.minutes} → 日志窗口 ${from} ~ ${to}`);
    }
    return await directLog(typeMap[name], nlogs, query);
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
  if (typeMap[name]) {
    // minutes 支持：用户说"过去N小时/分钟" → 生成 receive_time 窗口过滤（与 callToolImpl 日志分支一致）
    let query = args.query || "";
    if (args.minutes) {
      const from = fmtLogTime(new Date(Date.now() - args.minutes * 60000));
      const to = fmtLogTime(new Date());
      const win = `(receive_time geq '${from}' and receive_time leq '${to}')`;
      query = query ? `(${query}) and ${win}` : win;
      console.log(`[agent] ${name} minutes=${args.minutes} → 日志窗口 ${from} ~ ${to}`);
    }
    return await directLog(typeMap[name], logNlogs(args), query);
  }
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



  function isConnected() {
    return !!client;
  }

  function getMcpInfo() {
    return { ...mcpInfo };
  }

  function getDefaultFirewall() {
    return { name: DIRECT_FW.name || "", host: DIRECT_FW.host || "" };
  }

  return {
    connect,
    getDefaultFirewall,
    isConnected,
    getMcpInfo,
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
  };
}

module.exports = { createPanosAdapter };
