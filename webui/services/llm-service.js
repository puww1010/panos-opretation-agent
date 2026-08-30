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
      `你是防火墙运维意图分类器。从动作列表选一个 key；若输入与防火墙查询无关输出 {"action":null}；若输入是配置变更请求（创建/删除/封禁/改策略）输出 {"action":"change"}；若输入是故障诊断请求（连不上/不通/访问不了/排查/诊断/健康检查/某IP什么情况/一直扫描/某个具体故障现象）输出 {"action":"diag"}；若输入是审计/配置变更查询（谁改的/审计/变更记录/谁修改/谁删了/配置变更）输出 {"action":"audit"}。
注意：若输入是咨询/方案/教学/画图类请求（如何配置XX、XX是什么、帮我画个拓扑图、最佳实践建议、概念解释等）→ 输出 {"action":null}（系统会用自由问答回答，不要归为 diag）。
【多轮追问】输入前可能附带【最近对话上下文】。若当前问题引用了上下文（如"那条/上面那条/刚才那个/这个结果/它/那个策略/那台设备/结合上面的结果继续/基于刚才的"等指代词或依赖前文才能理解）→ 属于追问：追问上轮结果的含义/细节/为什么 → {"action":null}；追问删除/禁用/封禁具体条目 → {"action":"change"}；追问那条对应的流量/策略分析 → {"action":"diag"}。
【时间窗口 minutes】仅当动作是 traffic、threat、url 等日志查询且用户指定时间范围时提取分钟数：过去4小时=240、过去1小时=60、最近30分钟/半小时=30、最近10分钟=10、今天/最近1天=1440、过去2小时=120、过去6小时=360。用户没提时间 → minutes=null。**如果用户提到时间但动作不是日志查询，minutes 仍为 null**。
只输出 JSON：{"action":"<key>","minutes":<数字或null>}。\n动作列表（含 diag）:\n${list}\ndiag: 故障诊断（连不上/不通/访问不了/排查/诊断/健康检查/什么情况）`, withContext(input, conversationId));
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
      `你是防火墙配置变更解析器。从模板列表选一个 template，并提取参数（ip 为合法 IPv4；name 允许字母/数字/点/下划线/连字符 [a-zA-Z0-9_.-]，规则名必须原样保留）。
【重要区分规则】
- block_ip / allow_ip：用于创建新的封禁/放行策略。即使提到置顶/最顶部，只要是创建新策略就用 block_ip / allow_ip。
- move_security_rule：仅用于移动已有策略，必须有明确的已有规则名 name；"添加一条封禁XX的策略在最顶部" → block_ip；"把 block-social 移到 deny-all 上面" → move_security_rule（name=block-social, where=before, destination=deny-all）。
- move_security_rule 的 where 取值 top/bottom/before/after：上面/之前=before，下/之后=after，最上面=top，最下面=bottom。
- delete_security_rule、set_security_rule_disabled、set_security_rule_enabled：精确规则名填 name；模糊描述只提取最核心搜索子串到 keyword，去掉"的/带/有/含/按/在/里/上/下/规则/名字/名称"等停用词，不能把整段描述塞进 keyword；系统会列候选由用户确认。
- allow_ip：从放行/允许/白名单/allow 输入提取合法 IPv4。
- block_ip / allow_ip / block_ip_group 可用 params.position 指定创建后位置：最顶部=top、最底部=bottom、X上面=before+destination、X下面=after+destination；用户没说位置必须省略 position，避免无脑 top 改变原规则顺序。
- block_ip_group：多个 IP 封禁并放入地址组；提取所有 IPv4 到 params.ips 数组，用户给组名则填 group_name，未给则由系统生成。**绝不能把多个 IP 用逗号拼成一个名字**（PAN-OS 不接受逗号），绝不能用 block_ip 单 IP 模板。
【多轮追问】只可把上下文中真实存在的关键条目解析为 params.name，**禁止编造**；无法确定时 name 留空走 keyword 预检。
若无法匹配模板输出 {"template":null}。只输出 JSON：{"template":"<key>","params":{...}}。\n${templates}`, withContext(input, conversationId));
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
    const text = await classify("审计解析", "你是防火墙审计日志查询解析器。从用户请求中提取：minutes（时间窗口分钟数，如10分钟前=10、最近1小时=60、今天=1440，无则默认60）；object（对象类型：策略=security、地址=address、全部=all）。只输出 JSON：{\"minutes\":<num>,\"object\":\"<type>\"}。", input);
    if (!text) return { minutes: 60, object: "all" };
    try {
      const parsed = JSON.parse((text.match(/\{[\s\S]*?\}/) || ["{}"]) [0]);
      return { minutes: Number(parsed.minutes) || 60, object: String(parsed.object || "all") };
    } catch { return { minutes: 60, object: "all" }; }
  }

  async function parseDiagnostic(input, conversationId) {
    const text = await classify("诊断规划", "你是网络诊断解析器。判断用户症状属于：connectivity（连通性排查，涉及源/目的/IP/端口/连不上/不通/访问不了）、threat_profile（威胁源画像，涉及什么情况/一直扫描/攻击/画像且给定了IP）、generic（通用健康检查）。提取参数：ip（IPv4）、port、direction（inbound/outbound）、target_label（如外网）、minutes（最近10分钟=10、最近1小时=60、今天=1440，无则默认60）、probe（ping/测试连通/探测填 ping；追踪路由/traceroute 填 traceroute；否则不填）、around_time（仅用户指定现象发生具体时间点时填 YYYY/MM/DD HH:MM 或 HH:MM，未指定不填）。【多轮追问】用户引用前文时从上下文提取缺失的 ip/port 等参数。无法判断输出 {\"type\":null}。只输出 JSON：{\"type\":\"<t>\",\"params\":{}}。", withContext(input, conversationId));
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
      `你是 PAN-OS 防火墙诊断专家。**禁止套模板**，必须真正读数据、交叉对照、做证据链推理。
【重要推理原则】
- **观察缺失 ≠ 否定结论**：流量日志没有 X 不等于 X 没发生；可能未到达防火墙、被前置设备丢掉、查询字段不正确、过滤窗口太窄或主机方向问题。涉及未观测到的关键证据时，置信度只能是中或低。
- **直接证据 > 间接推断**。逐段检查用户提到的 IP/主机/对象是否出现及出现次数；未出现可报告为未被防火墙观测到，但不能跳到对象损坏/不存在等结论。
- **PAN-OS zone 是核心**：策略匹配靠 zone，跨 zone 默认拒绝；先列 zone，再列策略。
- 跨子网时 ARP 表空不等于主机不可达；路由缺失推断要克制，需看特定路由和转发。
- 当用户描述与数据明显冲突（例如双方 IP 均未出现），verdict 要明确说明防火墙未观测到其交互，建议先在源主机实测确认前提，不要硬找根因。
- **绝对优先级：功能未配置识别**。当 GP、VPN、IPSec、DHCP、HA 或特定 zone 间路由等相关配置和运行数据全部为空，结论应是**功能未配置 / 未启用 / 未启动**，而不是已配置但失败。流量有 ssl 不等于 GP 连接；reset-both 不等于 GP 被拒绝。
- verdict 开头必须标注本结论基于的数据时间范围（最早 → 最晚）；若用户报告现象时间落在窗口外，明确说明本次数据无法证实/证伪。必须看时间线趋势，解释阶段性 deny/reset 和恢复，而非只给当前快照。
输出 JSON：{"verdict":"一段话根因（开头标注数据时间范围；含[流量]、[策略]、[zone]等证据引用）","confidence":"高/中/低","confidence_reason":"为什么是这个置信度","evidence":["关键证据"],"recommendation":"具体到工具/命令的下一步"}。\n【用户症状】${input}\n【数据】\n${context}${statContext}${timelineContext}`,
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
    const text = await classify("查询匹配", `你是 PAN-OS 防火墙查询结果分析器。用户的问句往往带语义（例如 Internet=源 zone Untrust 或外部，DMZ=目标 zone DMZ 或特定对象）。你需要：
1. **语义映射**：将 Internet、DMZ、内部、外部、特定 IP 映射到实际 zone、地址对象或 any。
2. **匹配筛选**：只从真实数据中选真正满足问题的条目，按 action 区分 allow/deny。
3. **明确回答**：直接说明有/无/几条；无匹配时明确说没有匹配的策略，不能强行凑全放行规则。
4. **完整汇报元数据**：当 get_firewall_info 返回 Dashboard General Information 风格元数据时，主动列出 GP/AV/Threat/WildFire/URL 模块版本与状态、Advanced Routing、Duplicate IP、Plugin DLP、Device Certificate Status、Uptime 等。设备清单/资产查询不能遗漏。
5. 用 @_name 或关键字段引用匹配项；若问题引用前文，优先结合最近对话上下文，不要重复全量查询。
输出 1-3 段简洁中文（≤350 字），不要堆 JSON。`, `用户问句：${input}${timeHint}\n\n工具结果：\n${context}${buildConversationContext(conversationId) ? "\n\n" + buildConversationContext(conversationId) : ""}`, 30000);
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
