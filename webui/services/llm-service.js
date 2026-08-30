const fs = require("node:fs");

const LLM_SEED = {
  deepseek: { label: "DeepSeek", base_url: "https://api.deepseek.com/v1", model: "deepseek-v4-flash", env: "DEEPSEEK_API_KEY" },
  qwen: { label: "通义千问", base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1", model: "Qwen-3.8", env: "QWEN_API_KEY" },
  kimi: { label: "Kimi", base_url: "https://api.moonshot.cn/v1", model: "Kimi K3", env: "KIMI_API_KEY" },
};

function createLlmService({ configFile, choiceFile, environment = process.env, taskLister = () => [], fetcher = global.fetch, logger = console, clock = Date.now, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), maxLogs = 50 }) {
  let providers = {};
  let current = "keyword";
  const logs = [];

  function loadConfig() {
    const data = JSON.parse(JSON.stringify(LLM_SEED));
    let onDisk = {};
    try { onDisk = JSON.parse(fs.readFileSync(configFile, "utf-8")); } catch {}
    const configured = onDisk.providers || {};
    for (const [name, seed] of Object.entries(LLM_SEED)) {
      const disk = configured[name];
      if (disk) {
        data[name] = { ...seed, ...disk };
        if (disk.key) environment[seed.env] = disk.key;
      } else if (environment[seed.env]) {
        data[name] = { ...seed, key: environment[seed.env] };
      }
    }
    for (const [name, disk] of Object.entries(configured)) {
      if (!data[name]) {
        data[name] = { label: disk.label || name, base_url: disk.base_url || "", model: disk.model || "", env: disk.env || (name.toUpperCase() + "_API_KEY"), key: disk.key || "" };
        if (disk.key && data[name].env) environment[data[name].env] = disk.key;
      }
    }
    providers = data;
    return onDisk;
  }

  function loadChoice() {
    try { return JSON.parse(fs.readFileSync(choiceFile, "utf-8")).current; } catch { return null; }
  }

  function initialize() {
    const onDisk = loadConfig();
    const chosen = loadChoice();
    if (chosen && providers[chosen] && providers[chosen].key) current = chosen;
    else if (onDisk._default && providers[onDisk._default] && providers[onDisk._default].key) current = onDisk._default;
    else current = environment.LLM_PROVIDER || Object.keys(providers).find((name) => providers[name].key) || "keyword";
  }

  function saveConfig() {
    const onDisk = { _default: current, providers: {} };
    for (const [name, provider] of Object.entries(providers)) {
      onDisk.providers[name] = { label: provider.label, base_url: provider.base_url, model: provider.model, env: provider.env, key: provider.key };
    }
    fs.writeFileSync(configFile, JSON.stringify(onDisk, null, 2), { mode: 0o600 });
    try { fs.chmodSync(configFile, 0o600); } catch {}
  }

  function saveChoice(name) {
    try { fs.writeFileSync(choiceFile, JSON.stringify({ current: name, updatedAt: new Date(clock()).toISOString() })); } catch {}
  }

  function record(role, input, output, ms) {
    logs.unshift({ ts: new Date(clock()).toLocaleString("zh-CN"), provider: current, role, input: String(input).slice(0, 80), output: String(output || "").slice(0, 200), ms });
    if (logs.length > maxLogs) logs.pop();
  }

  function extractKeyItems(task) {
    const names = new Set();
    const walk = (value) => {
      if (value == null || typeof value !== "object") return;
      if (Array.isArray(value)) { value.forEach(walk); return; }
      for (const key of ["@_name", "name", "rule"]) {
        const item = value[key];
        if (typeof item === "string" && item && !/^(any|entry)$/.test(item)) names.add(item);
      }
      Object.values(value).forEach(walk);
    };
    for (const result of task.result?.results || []) walk(result.data);
    return [...names].slice(0, 8).join(", ");
  }

  function buildConversationContext(conversationId, limit = 5) {
    const tasks = taskLister();
    const pool = conversationId ? tasks.filter((task) => task.conversationId === conversationId) : tasks;
    const recent = pool.filter((task) => ["done", "failed"].includes(task.status) && ["query", "diag", "chat", "inspect"].includes(task.type)).slice(-limit);
    if (!recent.length) return "";
    return "【最近对话上下文】（用户之前问过这些，你回答过；当前问题可能引用它们）\n" + recent.map((task, index) => {
      const result = task.result || {};
      const summary = String(result.summary || result.answer || "").slice(0, 300);
      const items = extractKeyItems(task);
      return `轮${index + 1} 用户问: ${task.input}\n结果: ${summary || "(无摘要)"}${items ? `\n关键条目: ${items}` : ""}`;
    }).join("\n\n");
  }

  function withContext(input, conversationId) {
    const context = buildConversationContext(conversationId);
    return context ? context + "\n\n【用户当前问题】" + input : input;
  }

  async function classify(role, system, input, timeoutMs = 20000) {
    const provider = providers[current];
    if (!provider || !provider.key || !fetcher) return null;
    const effectiveTimeout = current === "kimi" && timeoutMs <= 20000 ? 45000 : timeoutMs;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), effectiveTimeout);
      const startedAt = clock();
      try {
        const response = await fetcher(`${provider.base_url}/chat/completions`, {
          method: "POST",
          signal: controller.signal,
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${provider.key}` },
          body: JSON.stringify({
            model: provider.model,
            ...(current === "kimi" ? {} : { temperature: 0 }),
            messages: [{ role: "system", content: system }, { role: "user", content: input }],
            ...(["deepseek", "qwen", "kimi"].includes(current) ? { thinking: { type: "disabled" } } : {}),
          }),
        });
        if (response.status === 429 && attempt === 0) {
          logger.warn(`[agent] LLM ${current} 429 限流，3s 后重试`);
          await sleep(3000);
          continue;
        }
        if (!response.ok) { logger.error("[agent] LLM http", response.status); return null; }
        const data = await response.json();
        const text = data.choices?.[0]?.message?.content || "";
        record(role, input, text, clock() - startedAt);
        return text;
      } catch (error) {
        logger.error("[agent] LLM error:", error.message);
        record(role, input, "ERROR: " + error.message, clock() - startedAt);
        return null;
      } finally {
        clearTimeout(timer);
      }
    }
    return null;
  }

  async function resolveAction(input, { conversationId, actions }) {
    const list = Object.entries(actions).map(([key, action]) => `${key}: ${action.label}（如"${action.keywords[0]}"）`).join("\n");
    const text = await classify("意图规划",
      `你是防火墙运维意图分类器。从动作列表选一个 key；无关咨询/方案/教学/画图类请求输出 {"action":null}；配置变更请求输出 {"action":"change"}；故障诊断请求输出 {"action":"diag"}；审计/配置变更查询输出 {"action":"audit"}。\n【多轮追问】需结合上下文：追问含义/细节输出 null；追问删除/禁用/封禁输出 change；追问流量/策略分析输出 diag。\n日志类查询若指定时间范围，提取 minutes；非日志查询 minutes 必须为 null。只输出 JSON：{"action":"<key>","minutes":<数字或null>}。\n动作列表：\n${list}\ndiag: 故障诊断`, withContext(input, conversationId));
    if (!text) return null;
    const match = text.match(/"action"\s*:\s*("?)(\w+|null)\1/);
    if (!match) return null;
    if (match[2] === "null") return { action: null, minutes: null };
    const minutesMatch = text.match(/"minutes"\s*:\s*(\d+)/);
    return { action: match[2], minutes: minutesMatch ? Math.max(1, Math.min(1440, Number.parseInt(minutesMatch[1], 10))) : null };
  }

  async function extractChange(input, { conversationId, changeTemplates }) {
    const templates = Object.entries(changeTemplates).map(([key, template]) => `${key}: ${template.label}（参数: ${template.params.join(", ")}）`).join("\n");
    const text = await classify("变更参数提取",
      `你是防火墙配置变更解析器。从模板列表选 template 并提取参数。block_ip/allow_ip 仅用于创建新策略；move_security_rule 仅用于移动已有规则且 name 不能为空。精确规则名填 name，模糊规则名只提取核心子串到 keyword；多个 IP 封禁使用 block_ip_group 和 ips 数组。用户未指定位置时不要传 position。多轮追问只能引用上下文真实条目，不能编造。无法匹配输出 {"template":null}。只输出 JSON：{"template":"<key>","params":{...}}。\n${templates}`, withContext(input, conversationId));
    if (!text) return null;
    try {
      const parsed = JSON.parse((text.match(/\{[\s\S]*\}/) || ["{}"]) [0]);
      if (!parsed.template || !changeTemplates[parsed.template]) return null;
      if (parsed.template === "move_security_rule" && (!parsed.params?.name || !String(parsed.params.name).trim())) {
        const ip = input.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)?.[1];
        if (!ip) return null;
        parsed.template = /放行|允许|白名单|allow/i.test(input) ? "allow_ip" : "block_ip";
        parsed.params = { ip };
      }
      return parsed;
    } catch { return null; }
  }

  async function parseAudit(input) {
    const text = await classify("审计解析", "你是防火墙审计日志查询解析器。提取 minutes（无则 60）和 object（security/address/all）。只输出 JSON。", input);
    if (!text) return { minutes: 60, object: "all" };
    try {
      const parsed = JSON.parse((text.match(/\{[\s\S]*?\}/) || ["{}"]) [0]);
      return { minutes: Number(parsed.minutes) || 60, object: String(parsed.object || "all") };
    } catch { return { minutes: 60, object: "all" }; }
  }

  async function parseDiagnostic(input, conversationId) {
    const text = await classify("诊断规划", "你是网络诊断解析器。判断 connectivity、threat_profile 或 generic，并提取 ip、port、direction、target_label、minutes、probe（仅 ping/traceroute）和 around_time。无法判断输出 {\"type\":null}。只输出 JSON。", withContext(input, conversationId));
    if (!text) return null;
    try {
      const parsed = JSON.parse((text.match(/\{[\s\S]*\}/) || ["{}"]) [0]);
      if (parsed.params?.minutes !== undefined) parsed.params.minutes = Number(parsed.params.minutes) || 60;
      if (parsed.params?.probe !== undefined && !["ping", "traceroute"].includes(parsed.params.probe)) delete parsed.params.probe;
      return parsed;
    } catch { return null; }
  }

  async function synthesizeDiagnostic(input, sections, stats) {
    const context = sections.map((section) => `[${section.step}] ${String(section.result).slice(0, 200)}`).join("\n");
    const statContext = stats ? "\n日志统计(前6):\n" + JSON.stringify(stats).slice(0, 600) : "";
    const timeline = sections.find((section) => section.step === "流量时间线");
    const timelineContext = timeline?.result && timeline.result !== "（无时间线数据）" ? "\n【流量时间线】\n" + timeline.result.slice(0, 600) : "";
    const text = await classify("诊断综合",
      `你是 PAN-OS 防火墙诊断专家。必须基于证据交叉推理：观察缺失不等于否定结论；直接证据优先；PAN-OS zone 是策略匹配核心；相关功能配置和运行数据均为空时，应判断为未配置/未启用而非臆测失败。verdict 开头必须说明数据时间范围，置信度需反映证据强弱。输出 JSON：{"verdict":"","confidence":"高/中/低","confidence_reason":"","evidence":[],"recommendation":""}。\n【用户症状】${input}\n【数据】\n${context}${statContext}${timelineContext}`,
      input, 120000);
    if (!text) return null;
    const match = text.match(/\{[\s\S]*?\}/);
    if (!match) return { verdict: text.slice(0, 300), confidence: "?", recommendation: "" };
    try {
      const parsed = JSON.parse(match[0]);
      return { verdict: String(parsed.verdict || "").slice(0, 600), confidence: ["高", "中", "低"].includes(parsed.confidence) ? parsed.confidence : "?", confidenceReason: String(parsed.confidence_reason || "").slice(0, 200), evidence: Array.isArray(parsed.evidence) ? parsed.evidence.slice(0, 8).map(String) : [], recommendation: String(parsed.recommendation || "").slice(0, 800) };
    } catch { return { verdict: text.slice(0, 300), confidence: "?", recommendation: "" }; }
  }

  async function summarizeQuery(input, action, results, conversationId) {
    const context = results.map((result) => {
      if (result.error) return `[${result.tool}] ERROR: ${result.error}`;
      const data = result.data || {};
      if (typeof data === "string") return `[${result.tool}] ${data.slice(0, 1500)}`;
      const items = Array.isArray(data) ? data : Array.isArray(data.entry) ? data.entry : Array.isArray(data.rules?.entry) ? data.rules.entry : Array.isArray(data.zone?.entry) ? data.zone.entry : null;
      if (!items) return `[${result.tool}] ${JSON.stringify(data).slice(0, 1500)}`;
      const head = items.slice(0, 50).map((item) => {
        if (!item || typeof item !== "object") return String(item).slice(0, 1200);
        const ordered = {};
        for (const key of ["@_name", "name", "action", "disabled", "from", "to", "source", "destination", "service", "application", "uuid", "@_uuid"]) {
          if (key in item) ordered[key] = item[key];
        }
        for (const key of Object.keys(item)) if (!(key in ordered)) ordered[key] = item[key];
        return JSON.stringify(ordered).slice(0, 1200);
      }).join("\n");
      const times = items.map((item) => item?.receive_time || "").filter(Boolean).sort();
      const timeNote = times.length ? `（数据时间范围：${times[0]} → ${times[times.length - 1]}，共 ${items.length} 条）` : "";
      return `[${result.tool}] 共 ${items.length} 条${timeNote}：\n${head}`;
    }).join("\n\n");
    const timeHint = /过去|最近|小时内|分钟|今天|昨天|小时前/.test(input) ? "\n【注意】必须说明实际返回的数据时间范围，若不覆盖用户要求需明确指出。" : "";
    const text = await classify("查询匹配", `你是 PAN-OS 防火墙查询结果分析器。将用户语义映射到真实 zone、地址对象和规则字段，按 action 区分 allow/deny，直接说明匹配数量；无匹配时明确说明。引用条目名或关键字段，回答 1-3 段中文，不堆 JSON。`, `用户问句：${input}${timeHint}\n\n工具结果：\n${context}${buildConversationContext(conversationId) ? "\n\n" + buildConversationContext(conversationId) : ""}`, 30000);
    return text || null;
  }

  async function answerFree(input, { conversationId, firewallContext = "" }) {
    return classify("自由问答", "你是 PAN-OS 防火墙运维专家。基于用户问题提供有深度的分析、配置或排错建议，并指出可进一步验证的系统功能或 CLI 命令。200-400 字，条理清晰，不要编造上下文。", `${firewallContext ? firewallContext + "\n" : ""}用户问题：${withContext(input, conversationId)}`, 60000);
  }

  function getPublicConfig() {
    return { current, providers: Object.fromEntries(Object.entries(providers).map(([name, provider]) => [name, { label: provider.label, model: provider.model, base_url: provider.base_url, env: provider.env, configured: Boolean(provider.key), key_hint: provider.key ? provider.key.slice(0, 4) + "***" + provider.key.slice(-3) : null }])) };
  }

  function saveProvider(input) {
    const { provider, base_url, model, key, env, label } = input;
    if (!provider || !/^[a-z0-9_-]+$/.test(provider)) throw new Error("provider 必填且仅小写字母数字下划线");
    const seed = LLM_SEED[provider] || { label: provider, env: env || provider.toUpperCase() + "_API_KEY" };
    providers[provider] = { label: label || seed.label, base_url: base_url || seed.base_url, model: model || seed.model, env: env || seed.env, key: key || "" };
    saveConfig();
    return { ok: true, provider, configured: Boolean(providers[provider].key) };
  }

  function deleteProvider(provider) {
    if (providers[provider]) delete providers[provider];
    saveConfig();
    return { ok: true };
  }

  function selectProvider(provider) {
    if (provider === "keyword") { current = "keyword"; saveChoice(current); return { ok: true, current }; }
    if (providers[provider]?.key) { current = provider; saveChoice(current); return { ok: true, current }; }
    return { ok: false, provider: providers[provider] || null };
  }

  initialize();
  return { answerFree, buildConversationContext, classify, deleteProvider, extractChange, getCurrent: () => current, getLogs: () => logs, getModel: () => providers[current]?.model || null, getProvider: (name) => providers[name], getPublicConfig, parseAudit, parseDiagnostic, resolveAction, saveProvider, selectProvider, summarizeQuery, synthesizeDiagnostic };
}

module.exports = { createLlmService };
