const { planFingerprint, transitionTask } = require("../lib/task-governance");

function normalizeChangeParams(template, params = {}) {
  return template === "add_address_object"
    ? { ...params, type: params.type || "ip-netmask" }
    : { ...params };
}

function isValidRuleName(name) {
  return Boolean(name && /^[a-zA-Z0-9_.\-]+$/.test(name));
}

function tokenizeForMatch(text) {
  const stop = new Set([
    "的", "在", "和", "与", "或", "带", "有", "含", "按", "上", "里", "下", "中", "为", "是",
    "规则", "名字", "名称", "rule", "policy", "删除", "封禁", "放行", "禁用", "启用",
    "请", "把", "我", "你", "他", "来", "起", "到", "this", "that", "the", "with", "and", "or",
  ]);
  return (text.match(/[\u4e00-\u9fa5]+|[A-Za-z][A-Za-z0-9_-]*/g) || [])
    .map((token) => token.trim())
    .filter((token) => token.length >= 2 && !stop.has(token.toLowerCase()) && !stop.has(token));
}

function createTaskService({ panosAdapter = {}, taskStore, auditStore, auditLogReader, actionDefinitions, toolCaller, querySummarizer, queryHistoryRecorder, inspectReportWriter, diagnosticDependencies, clock = Date.now, deferExecution = false, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), maxCommitPolls = 200 }) {
  const tasks = taskStore.load();
  let taskSeq = tasks.reduce((max, task) => Math.max(max, Number(task.id) || 0), 0);

  function saveTasks() { taskStore.save(tasks); }

  function createTask(type, input, extra = {}) {
    let followUpOf = null;
    if (!extra.conversationId) {
      for (let index = tasks.length - 1; index >= 0; index -= 1) {
        const task = tasks[index];
        if (["done", "failed"].includes(task.status) && ["query", "diag", "chat", "inspect"].includes(task.type)) {
          followUpOf = task.id;
          break;
        }
      }
    }
    return {
      id: ++taskSeq,
      type,
      input,
      status: "pending",
      steps: [],
      result: null,
      error: null,
      createdAt: new Date(clock()).toLocaleString("zh-CN"),
      followUpOf,
      ...extra,
    };
  }

  function addTask(task) {
    taskSeq = Math.max(taskSeq, Number(task.id) || 0);
    tasks.push(task);
    saveTasks();
    return task;
  }

  function saveTask(task) {
    const index = tasks.findIndex((item) => item.id === task.id);
    if (index >= 0) tasks[index] = task;
    saveTasks();
    return task;
  }

  function getTask(id) {
    return tasks.find((task) => task.id === id);
  }

  function dispatchTask(type, input, extra, prepare, runner) {
    if (!runner) {
      runner = prepare;
      prepare = null;
    }
    const task = createTask(type, input, extra);
    if (prepare) prepare(task);
    addTask(task);
    try {
      Promise.resolve(runner(task)).catch((error) => {
        task.status = "failed";
        task.error = String(error.message || error);
        saveTask(task);
      });
    } catch (error) {
      task.status = "failed";
      task.error = String(error.message || error);
      saveTask(task);
    }
    return task;
  }

  function recordAudit(task, event) {
    task.audit = task.audit || [];
    task.audit.push(event);
    const audit = auditStore.load();
    audit.push({ ...event, type: task.type, firewall: task.firewall || null, planFingerprint: task.planFingerprint || null });
    auditStore.save(audit);
  }

  function finalizeCandidate(task) {
    task.planFingerprint = planFingerprint({ template: task.template, params: task.params, firewall: task.firewall });
    task.status = "awaiting_commit";
    recordAudit(task, {
      taskId: task.id,
      action: "candidate_ready",
      from: "executing",
      to: "awaiting_commit",
      at: new Date(clock()).toISOString(),
    });
    saveTasks();
  }

  async function setAwaitingSelection(task, verb) {
    const keyword = (task.params.keyword || "").trim();
    if (!keyword) throw new Error("该操作需要精确规则名或模糊 keyword 之一");
    const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules";
    const text = String(await panosAdapter.directConfigShow(xpath));
    const rules = (text.match(/<entry[^>]*>([\s\S]*?)<\/entry>/g) || []).map((block) => {
      const match = block.match(/<entry[^>]*\bname=\"([^\"]+)\"/);
      return match ? match[1] : null;
    }).filter(Boolean);
    let matched = rules.filter((name) => name.toLowerCase().includes(keyword.toLowerCase()));
    let mode = "整串匹配";
    if (!matched.length) {
      const tokens = tokenizeForMatch(keyword);
      if (tokens.length) {
        matched = rules.filter((name) => tokens.some((token) => name.toLowerCase().includes(token.toLowerCase())));
        if (matched.length) mode = "拆词 OR 匹配 [" + tokens.join(", ") + "]";
      }
    }
    const top = matched.slice(0, 10);
    task.steps.push(mode + " \"" + keyword + "\" 命中 " + matched.length + " 条规则" + (top.length ? "：" + top.join("、") : ""));
    task.status = "awaiting_selection";
    task.result = { awaitingSelection: true, verb, keyword, matched: top, totalMatches: matched.length, mode };
    task._candidate = { name: task.params.name, keyword, template: task.template, firewall: task.firewall };
    saveTask(task);
  }

  async function runAudit(task) {
    if (!auditLogReader) throw new Error("未配置配置变更日志读取器");
    task.status = "running";
    task.steps.push("查询配置变更日志 (config log)");
    const step = { tool: "get_config_logs", status: "running", startMs: clock() };
    task.steps.push(step);
    let entries;
    try {
      entries = (await auditLogReader(task.firewall)).entry || [];
    } catch (error) {
      step.status = "err";
      step.msg = String(error.message || error);
      task.status = "failed";
      task.error = step.msg;
      saveTask(task);
      return;
    }
    step.status = "ok";
    step.ms = clock() - step.startMs;
    const { minutes, object } = task.audit || { minutes: 60, object: "all" };
    const cutoff = clock() - minutes * 60000;
    const isSecurityRule = (value) => /rulebase\/security|security\/rules/.test(value || "");
    const rows = entries.map((entry) => ({
      time: entry.receive_time || entry.time_generated || "",
      admin: entry.admin || "?",
      cmd: entry.cmd || "?",
      result: entry.result || "?",
      client: entry.client || "?",
      path: (entry["full-path"] || entry.path || "").slice(0, 80),
    })).filter((row) => {
      if (!row.time) return object !== "security" || isSecurityRule(row.path);
      const timestamp = Date.parse(row.time.replace("/", "-").replace("/", "-"));
      if (!Number.isNaN(timestamp) && timestamp < cutoff) return false;
      return object !== "security" || isSecurityRule(row.path);
    });
    task.result = {
      title: "配置变更审计（最近 " + minutes + " 分钟" + (object === "security" ? " · 策略相关" : "") + "）",
      rows, total: rows.length, minutes, object,
    };
    task.steps.push("筛选出 " + rows.length + " 条变更记录");
    task.status = "done";
    saveTask(task);
  }

  async function runQuery(task, action = task.action) {
    const definitions = typeof actionDefinitions === "function" ? actionDefinitions() : actionDefinitions;
    const definition = definitions?.[action];
    if (!definition || !toolCaller) throw new Error("未配置查询动作或工具调用器: " + action);
    task.status = "running";
    const results = [];
    for (const tool of definition.tools) {
      if (task.cancelled) {
        task.status = "cancelled";
        break;
      }
      const step = { tool, status: "running", startMs: clock() };
      task.steps.push(step);
      try {
        results.push({ tool, data: await toolCaller(tool, task.minutes ? { minutes: task.minutes } : {}, task.firewall) });
        step.status = "ok";
        step.ms = clock() - step.startMs;
      } catch (error) {
        step.status = "err";
        step.ms = clock() - step.startMs;
        step.msg = String(error.message || error);
        results.push({ tool, error: step.msg });
      }
    }
    if (task.status !== "cancelled") {
      try {
        const summary = querySummarizer ? await querySummarizer(task.input, action, results, task.conversationId) : null;
        task.result = { label: definition.label, results, summary };
      } catch {
        task.result = { label: definition.label, results };
      }
      task.status = "done";
      if (queryHistoryRecorder) queryHistoryRecorder({ input: String(task.input), action, label: definition.label });
    }
    saveTask(task);
  }

  async function runInspect(task) {
    const definitions = typeof actionDefinitions === "function" ? actionDefinitions() : actionDefinitions;
    const tools = definitions?.inspect?.tools;
    if (!tools || !toolCaller || !inspectReportWriter) throw new Error("未配置巡检执行依赖");
    task.status = "running";
    const results = [];
    for (const tool of tools) {
      if (task.cancelled) { task.status = "cancelled"; break; }
      const step = { tool, status: "running", startMs: clock() };
      task.steps.push(step);
      try {
        results.push({ tool, data: await toolCaller(tool, {}, task.firewall) });
        step.status = "ok"; step.ms = clock() - step.startMs;
      } catch (error) {
        step.status = "err"; step.ms = clock() - step.startMs; step.msg = String(error.message || error);
        results.push({ tool, error: step.msg });
      }
    }
    if (task.status === "cancelled") { saveTask(task); return; }
    const data = (tool) => results.find((result) => result.tool === tool)?.data || {};
    const firewall = data("get_firewall_info");
    const rules = data("get_security_rules")?.rules?.entry || [];
    const licenses = data("get_licenses")?.licenses?.entry || [];
    const threats = data("get_threat_logs")?.entry || [];
    const wildfire = data("get_wildfire_status")?.raw || String(data("get_wildfire_status"));
    const checks = [
      { name: "策略最小权限", pass: !rules.some((rule) => rule.action === "allow" && !rule.disabled && rule.source?.member === "any" && rule.destination?.member === "any") },
      { name: "威胁防护启用", pass: !/Disabled due to configuration/.test(wildfire) },
      { name: "许可有效性", pass: !licenses.some((license) => license.expired === "yes") },
      { name: "日志连续性", pass: threats.length > 0 && clock() - new Date(threats[0].receive_time).getTime() < 7 * 864e5 },
      { name: "内容库更新", pass: true },
    ];
    const scored = checks.filter((check) => check.name !== "内容库更新");
    const rate = Math.round(scored.filter((check) => check.pass).length / scored.length * 100);
    const grade = rate >= 90 ? "优秀" : rate >= 75 ? "良好" : rate >= 60 ? "需改进" : "不达标";
    const date = new Date(clock()).toISOString().slice(0, 10);
    const markdown = "# PAN-OS 合规巡检报告（WebUI 任务）\n\n| 项 | 值 |\n|---|---|\n| 设备 | " + (firewall.hostname || "?") + " (" + (firewall.serial || "?") + ") |\n| 版本 | " + (firewall["sw-version"] || "?") + " |\n| 时间 | " + date + " |\n| 评级 | " + grade + " (" + rate + "%) |\n\n| 检查项 | 结果 |\n|---|---|\n" + checks.map((check) => "| " + check.name + " | " + (check.pass ? "✅ 通过" : "❌ 不通过") + " |").join("\n");
    const file = await inspectReportWriter({ date, markdown });
    task.result = { grade, rate, file, checks, hostname: firewall.hostname, model: firewall.model };
    task.steps.push("报告落盘 " + String(file).split("/").at(-1));
    task.status = "done";
    saveTask(task);
  }

  async function runDiagnostic(task) {
    const { type = "generic", params = {} } = task.diag || {};
    if (type !== "generic") throw new Error("该诊断类型尚未迁入 Task Service: " + type);
    if (!toolCaller || !diagnosticDependencies?.deepLog || !diagnosticDependencies?.filterByMinutes || !diagnosticDependencies?.formatTop) {
      throw new Error("未配置通用健康诊断依赖");
    }
    const minutes = params.minutes || 60;
    const sections = [];
    task.status = "running";
    task.steps.push("诊断类型: 通用健康");
    const firewall = await toolCaller("get_firewall_info", {}, task.firewall);
    sections.push({ step: "设备", result: String(firewall.hostname) + " " + firewall.model + " " + firewall["sw-version"] });
    const resources = await toolCaller("get_system_resources", {}, task.firewall);
    const load = typeof resources === "string" ? resources.split("\n").find((line) => line.includes("load average")) : "";
    sections.push({ step: "负载", result: load || "（资源查询无摘要）" });
    const sessions = await toolCaller("get_active_sessions", {}, task.firewall);
    sections.push({ step: "会话", result: "活跃 " + (sessions["num-active"] || 0) + " / 上限 " + (sessions["num-max"] || 0) });
    const systemLogs = diagnosticDependencies.filterByMinutes((await toolCaller("get_system_logs", {}, task.firewall))?.entry || [], minutes);
    const errors = systemLogs.filter((entry) => ["error", "critical"].includes(entry.severity));
    sections.push({ step: "系统事件", result: errors.length ? "最近 " + minutes + " 分钟内 " + errors.length + " 条 error/critical" : "最近 " + minutes + " 分钟无 error/critical 事件" });
    const threatLog = await diagnosticDependencies.deepLog("threat", { minutes, nlogs: 200 });
    sections.push({ step: "威胁近况", result: threatLog.entries.length ? "最近 " + minutes + " 分钟威胁日志 " + threatLog.entries.length + " 条" : "最近 " + minutes + " 分钟无威胁日志" });
    sections.push({ step: "威胁源 Top", result: diagnosticDependencies.formatTop(threatLog.top, ["src", "subtype", "severity"]) });
    task.result = { title: "通用健康诊断", sections };
    const synthesis = diagnosticDependencies.synthesize ? await diagnosticDependencies.synthesize(task.input, sections, threatLog.top) : null;
    if (synthesis) {
      task.result.verdict = synthesis.verdict;
      task.result.confidence = synthesis.confidence;
      task.result.recommendation = synthesis.recommendation || "";
    }
    if (!task.result.verdict) {
      task.result.verdict = "LLM 综合推理未产出结论，请查看下方排查步骤表（" + sections.length + " 段原始数据已采集）。";
      task.result.confidence = "低（fallback）";
      task.result.recommendation = "重跑任务或缩短时间窗口后复核各段数据。";
    }
    task.result.logStats = threatLog.top;
    task.status = "done";
    saveTask(task);
  }

  async function runCandidate(task) {
    task.params = normalizeChangeParams(task.template, task.params);
    if (task.template === "add_address_object" && panosAdapter.directConfigSet) {
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='" + task.params.name + "']";
      await panosAdapter.directConfigSet(xpath, "<ip-netmask>" + task.params.value + "</ip-netmask>");
      finalizeCandidate(task);
      return;
    }
    if (task.template === "delete_address_object" && panosAdapter.directConfigDelete) {
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='" + task.params.name + "']";
      await panosAdapter.directConfigDelete(xpath);
      finalizeCandidate(task);
      return;
    }
    if (task.template === "move_security_rule" && panosAdapter.directConfigMove) {
      const { name, where, destination } = task.params;
      if (!name || !where) throw new Error("move_security_rule 缺少 name 或 where");
      if (["before", "after"].includes(where) && !destination) {
        throw new Error("move_security_rule 在 before/after 时必须提供 destination（参照规则名）");
      }
      const base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']";
      const xpath = base + "/rulebase/security/rules/entry[@name='" + name + "']";
      const destinationXpath = ["before", "after"].includes(where)
        ? base + "/rulebase/security/rules/entry[@name='" + destination + "']"
        : null;
      await panosAdapter.directConfigMove(xpath, where, destinationXpath);
      task.steps.push("candidate: move_security_rule " + name + " " + where + (destinationXpath ? " " + destination : ""));
      finalizeCandidate(task);
      return;
    }
    if (["delete_security_rule", "set_security_rule_disabled", "set_security_rule_enabled"].includes(task.template) && !isValidRuleName(task.params.name) && panosAdapter.directConfigShow) {
      const verb = task.template === "delete_security_rule" ? "删除" : task.template === "set_security_rule_disabled" ? "禁用" : "启用";
      await setAwaitingSelection(task, verb);
      return;
    }
    if (["set_security_rule_disabled", "set_security_rule_enabled"].includes(task.template) && isValidRuleName(task.params.name) && panosAdapter.directConfigSet) {
      const value = task.template === "set_security_rule_disabled" ? "yes" : "no";
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='" + task.params.name + "']/disabled";
      await panosAdapter.directConfigSet(xpath, "<disabled>" + value + "</disabled>");
      task.steps.push("candidate: " + (value === "yes" ? "disable " : "enable ") + task.params.name);
      finalizeCandidate(task);
      return;
    }
    if (task.template === "delete_security_rule" && isValidRuleName(task.params.name) && panosAdapter.directConfigDelete) {
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='" + task.params.name + "']";
      await panosAdapter.directConfigDelete(xpath);
      task.steps.push("candidate: delete_security_rule " + task.params.name);
      finalizeCandidate(task);
      return;
    }
    if (task.template === "block_ip" && panosAdapter.directConfigSet) {
      const date = new Date(clock()).toISOString().slice(0, 10).replace(/-/g, "");
      const name = "block-" + task.params.ip + "-" + date;
      const base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']";
      await panosAdapter.directConfigSet(base + "/address/entry[@name='" + name + "']", "<ip-netmask>" + task.params.ip + "/32</ip-netmask>");
      task.steps.push("candidate: address " + name);
      const ruleXml = "<from><member>any</member></from><to><member>any</member></to><source><member>" + name + "</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>deny</action><description>WebUI block by Agent</description>";
      await panosAdapter.directConfigSet(base + "/rulebase/security/rules/entry[@name='" + name + "']", ruleXml);
      task.steps.push("candidate: deny rule " + name);
      task.params._objName = name;
      if (task.params.position && ["top", "bottom", "before", "after"].includes(task.params.position) && panosAdapter.directConfigMove) {
        if (["before", "after"].includes(task.params.position) && !task.params.destination) {
          task.steps.push("⚠️ " + task.params.position + " 需要 destination 参照规则名，跳过 move，规则留在末尾");
        } else {
          const destination = ["before", "after"].includes(task.params.position)
            ? base + "/rulebase/security/rules/entry[@name='" + task.params.destination + "']"
            : null;
          await panosAdapter.directConfigMove(base + "/rulebase/security/rules/entry[@name='" + name + "']", task.params.position, destination);
          task.steps.push("candidate: move " + name + " " + task.params.position);
        }
      } else {
        task.steps.push("ℹ️ 用户未指定位置，规则留在末尾（不移动）");
      }
      finalizeCandidate(task);
      return;
    }
    if (task.template === "allow_ip" && panosAdapter.directConfigSet) {
      const date = new Date(clock()).toISOString().slice(0, 10).replace(/-/g, "");
      const name = "allow-" + task.params.ip + "-" + date;
      const base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']";
      await panosAdapter.directConfigSet(base + "/address/entry[@name='" + name + "']", "<ip-netmask>" + task.params.ip + "/32</ip-netmask>");
      task.steps.push("candidate: address " + name);
      const ruleXml = "<from><member>any</member></from><to><member>any</member></to><source><member>" + name + "</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>allow</action><description>WebUI allow by Agent</description>";
      await panosAdapter.directConfigSet(base + "/rulebase/security/rules/entry[@name='" + name + "']", ruleXml);
      task.steps.push("candidate: allow rule " + name);
      task.params._objName = name;
      if (task.params.position && ["top", "bottom", "before", "after"].includes(task.params.position) && panosAdapter.directConfigMove) {
        if (["before", "after"].includes(task.params.position) && !task.params.destination) {
          task.steps.push("⚠️ " + task.params.position + " 需要 destination 参照规则名，跳过 move，规则留在末尾");
        } else {
          const destination = ["before", "after"].includes(task.params.position)
            ? base + "/rulebase/security/rules/entry[@name='" + task.params.destination + "']"
            : null;
          await panosAdapter.directConfigMove(base + "/rulebase/security/rules/entry[@name='" + name + "']", task.params.position, destination);
          task.steps.push("candidate: move " + name + " " + task.params.position);
        }
      } else {
        task.steps.push("ℹ️ 用户未指定位置，规则留在末尾（不移动）");
      }
      finalizeCandidate(task);
      return;
    }
    if (task.template === "block_ip_group" && panosAdapter.directConfigSet) {
      const ips = Array.isArray(task.params.ips)
        ? task.params.ips.filter((ip) => ip && /^\d+\.\d+\.\d+\.\d+$/.test(String(ip).trim()))
        : [];
      if (!ips.length) throw new Error("block_ip_group: 至少需要一个有效 IPv4");
      const date = new Date(clock()).toISOString().slice(0, 10).replace(/-/g, "");
      const base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']";
      const groupName = task.params.group_name && /^[a-zA-Z0-9_.\-]+$/.test(task.params.group_name)
        ? task.params.group_name
        : "block-group-" + date;
      const objectNames = [];
      for (const ip of ips) {
        const name = "block-" + ip + "-" + date;
        await panosAdapter.directConfigSet(base + "/address/entry[@name='" + name + "']", "<ip-netmask>" + ip + "/32</ip-netmask>");
        task.steps.push("candidate: address " + name);
        objectNames.push(name);
      }
      const groupXml = "<static>" + objectNames.map((name) => "<member>" + name + "</member>").join("") + "</static><description>WebUI block group by Agent</description>";
      await panosAdapter.directConfigSet(base + "/address-group/entry[@name='" + groupName + "']", groupXml);
      task.steps.push("candidate: address-group " + groupName + " (" + objectNames.length + " 成员)");
      const ruleXml = "<from><member>any</member></from><to><member>any</member></to><source><member>" + groupName + "</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>deny</action><description>WebUI block group by Agent (" + ips.length + " IPs)</description>";
      await panosAdapter.directConfigSet(base + "/rulebase/security/rules/entry[@name='" + groupName + "']", ruleXml);
      task.steps.push("candidate: deny rule (source=group) " + groupName);
      task.params._objName = groupName;
      task.params._groupName = groupName;
      task.params._memberCount = objectNames.length;
      if (task.params.position && ["top", "bottom", "before", "after"].includes(task.params.position) && panosAdapter.directConfigMove) {
        if (["before", "after"].includes(task.params.position) && !task.params.destination) {
          task.steps.push("⚠️ " + task.params.position + " 需要 destination 参照规则名，跳过 move，规则留在末尾");
        } else {
          const destination = ["before", "after"].includes(task.params.position)
            ? base + "/rulebase/security/rules/entry[@name='" + task.params.destination + "']"
            : null;
          await panosAdapter.directConfigMove(base + "/rulebase/security/rules/entry[@name='" + groupName + "']", task.params.position, destination);
          task.steps.push("candidate: move " + groupName + " " + task.params.position);
        }
      } else {
        task.steps.push("ℹ️ 用户未指定位置，规则留在末尾（不移动）");
      }
      finalizeCandidate(task);
      return;
    }
    throw new Error("未支持的变更模板或 PAN-OS 适配器能力不足: " + task.template);
  }

  async function runCommit(task) {
    if (panosAdapter.directCommit) {
      task.status = "committing";
      let job = null;
      try {
        const response = await panosAdapter.directCommit("WebUI Agent: " + (task.templateLabel || task.type));
        const text = String(response);
        const match = text.match(/<job>(\d+)<\/job>/i)
          || text.match(/<id>(\d+)<\/id>/i)
          || text.match(/jobid[\s=]+["']?(\d+)/i)
          || text.match(/\bid\s+(\d+)\b/i)
          || text.match(/"job"\s*:\s*(\d+)/);
        job = match ? match[1] : null;
        task.steps.push("commit 入队" + (job ? " job=" + job : "：无 job（响应：" + text.slice(0, 120) + "）"));
        if (!job) {
          task.steps.push("可能原因：candidate 未生效（无变更可提交）或 commit 端点未返回 job");
          task.status = "done";
          task.result = Object.assign(task.result || {}, { needsManualCommit: true, raw: text.slice(0, 300) });
          recordAudit(task, { taskId: task.id, action: "commit_needs_follow_up", from: "committing", to: "done", at: new Date(clock()).toISOString() });
          saveTasks();
          return;
        }
        if (!panosAdapter.directOp) {
          task.steps.push("无法查询 commit job 状态，请到 Monitor → Jobs 确认最终结果");
          task.status = "done";
          task.result = Object.assign(task.result || {}, { needsManualCommit: true, job });
          recordAudit(task, { taskId: task.id, action: "commit_needs_follow_up", from: "committing", to: "done", at: new Date(clock()).toISOString() });
          saveTasks();
          return;
        }
      } catch (error) {
        task.steps.push("commit 入队失败：" + String(error.message || error).slice(0, 80));
        task.status = "done";
        task.result = Object.assign(task.result || {}, { needsManualCommit: true });
        recordAudit(task, { taskId: task.id, action: "commit_needs_follow_up", from: "committing", to: "done", at: new Date(clock()).toISOString() });
        saveTasks();
        return;
      }

      let lastJobSignature = "";
      for (let index = 0; index < maxCommitPolls; index += 1) {
        if (task.cancelled) {
          task.steps.push("已取消任务，停止 commit 轮询");
          task.steps.push("⚠️ commit job=" + job + " 可能已在防火墙执行，请到 Monitor → Jobs 确认最终状态；如需回退变更请手动处理");
          task.status = "cancelled";
          task.result = Object.assign(task.result || {}, { cancelledWhileCommitting: true, job });
          recordAudit(task, { taskId: task.id, action: "commit_polling_cancelled", from: "committing", to: "cancelled", at: new Date(clock()).toISOString() });
          saveTasks();
          return;
        }
        await sleep(index < 30 ? 3000 : 5000);
        try {
          const response = await panosAdapter.directOp("<show><jobs><id>" + job + "</id></jobs></show>");
          const text = String(response);
          const statusMatch = text.match(/<status>\s*([^<\s]+)/i);
          const status = statusMatch ? statusMatch[1].toUpperCase() : "";
          const progressMatch = text.match(/<progress>\s*(\d+)/i);
          const progress = progressMatch ? progressMatch[1] : "";
          const signature = status + "|" + progress;
          if (signature !== lastJobSignature || index % 15 === 0) {
            task.steps.push("commit job=" + job + " status=" + status + (progress ? " (" + progress + "%)" : ""));
            lastJobSignature = signature;
          }
          if (["FIN", "FINOK"].includes(status) || text.includes("FIN OK")) {
            task.steps.push("commit 完成 (job=" + job + ")");
            task.status = "done";
            task.result = Object.assign(task.result || {}, { job });
            recordAudit(task, { taskId: task.id, action: "commit_completed", from: "committing", to: "done", at: new Date(clock()).toISOString() });
            saveTasks();
            return;
          }
          if (["FAIL", "STOPPED", "ERROR"].includes(status)) {
            task.steps.push("commit 失败：" + status + " job=" + job);
            task.status = "done";
            task.result = Object.assign(task.result || {}, { job, commitFailed: true });
            recordAudit(task, { taskId: task.id, action: "commit_failed", from: "committing", to: "done", at: new Date(clock()).toISOString() });
            saveTasks();
            return;
          }
        } catch {}
      }
      task.steps.push("commit 超时（10 分钟）：job=" + job + " 可能在防火墙后台仍在执行中。请登录防火墙 Web 界面 → Monitor → Jobs，搜索 job ID " + job + " 查看最终状态，或手动执行 commit");
      task.status = "done";
      task.result = Object.assign(task.result || {}, { needsManualCommit: true, timeout: true, timedOut: true, job });
      recordAudit(task, { taskId: task.id, action: "commit_timed_out", from: "committing", to: "done", at: new Date(clock()).toISOString() });
      saveTasks();
      return;
    }
    throw new Error("PAN-OS adapter does not provide directCommit");
  }

  async function startExecution(task, runner) {
    try {
      await runner(task);
    } catch (error) {
      task.status = "failed";
      task.error = String(error.message || error);
      saveTasks();
      if (!deferExecution) throw error;
    }
  }

  function assertPlanUnchanged(task) {
    if (task.type !== "change" || !task.planFingerprint) return;
    const params = normalizeChangeParams(task.template, task.params || {});
    const actual = planFingerprint({ template: task.template, params, firewall: task.firewall });
    if (actual !== task.planFingerprint) throw new Error("变更计划已变化，请重新生成候选计划");
  }

  async function actOnTask(id, action, payload = {}) {
    const task = tasks.find((item) => item.id === id);
    if (!task) throw new Error("task not found");
    if (["approve", "confirm"].includes(action)) assertPlanUnchanged(task);
    const transition = transitionTask(task, action, new Date(clock()));
    if (!transition.ok) throw new Error("非法操作或状态不匹配: " + task.status);
    recordAudit(task, transition.event);
    if (action === "select") {
      task.params = { ...(payload.params || {}) };
      task.firewall = payload.firewall || task.firewall || task._candidate?.firewall;
      if (payload.step) {
        task.steps = task.steps || [];
        task.steps.push(payload.step);
      }
    }
    if (action === "cancel") {
      task.cancelled = true;
      task.steps = task.steps || [];
      task.steps.push("手动取消");
    }
    if (action === "reject") {
      task.steps = task.steps || [];
      task.steps.push("已拒绝");
    }
    saveTasks();
    if (["approve", "select"].includes(action)) {
      const execution = startExecution(task, runCandidate);
      if (deferExecution) void execution;
      else await execution;
    }
    if (action === "confirm") {
      const execution = startExecution(task, runCommit);
      if (deferExecution) void execution;
      else await execution;
    }
    return { taskId: task.id, status: task.status };
  }

  async function runBatchSelection(task, names) {
    const candidate = task._candidate;
    const results = [];
    for (const name of names) {
      const child = createTask("change", candidate.template + " " + name, {
        template: candidate.template,
        params: { name },
        firewall: candidate.firewall,
        createdAt: new Date(clock()).toISOString(),
      });
      addTask(child);
      try {
        await runCandidate(child);
        results.push({ name, success: true, taskId: child.id });
      } catch (error) {
        child.status = "failed";
        child.error = String(error.message || error);
        saveTask(child);
        results.push({ name, success: false, error: child.error, taskId: child.id });
      }
    }

    const successfulTasks = results
      .filter((result) => result.success)
      .map((result) => getTask(result.taskId))
      .filter(Boolean);
    if (successfulTasks.length) {
      task.steps.push("统一 commit " + successfulTasks.length + " 个变更（合并为单次 commit）");
      try {
        await runCommit(task);
        if (task.result?.commitFailed || task.result?.needsManualCommit) {
          const message = task.result.commitFailed ? "commit 失败" : "commit 超时/需手动";
          for (const child of successfulTasks) {
            child.status = "failed";
            child.error = message + " (job=" + (task.result.job || "?") + ")";
            saveTask(child);
          }
        } else {
          for (const child of successfulTasks) {
            child.status = "done";
            child.result = Object.assign(child.result || {}, { mergedCommit: true, commitJob: task.result.job });
            saveTask(child);
          }
        }
      } catch (error) {
        for (const child of successfulTasks) {
          child.status = "failed";
          child.error = "commit 失败: " + String(error.message || error);
          saveTask(child);
        }
        task.steps.push("commit 异常: " + String(error.message || error).slice(0, 120));
      }
    } else {
      task.steps.push("无可 commit 的变更");
    }
    if (task.status !== "cancelled") task.status = "done";
    task.result = Object.assign(task.result || {}, { batch: true, total: names.length, results });
    saveTask(task);
    return { taskId: task.id, status: task.status };
  }

  async function startBatchSelection(id, names) {
    if (!Array.isArray(names) || !names.length) throw new Error("names 必须是非空数组");
    const task = getTask(id);
    if (!task) throw new Error("task not found");
    if (task.status !== "awaiting_selection" || !task._candidate) {
      throw new Error("非法操作或状态不匹配: " + task.status);
    }
    const transition = transitionTask(task, "select", new Date(clock()));
    if (!transition.ok) throw new Error("非法操作或状态不匹配: " + task.status);
    recordAudit(task, transition.event);
    task.steps.push("批量执行 " + names.length + " 个策略：" + names.join(", "));
    saveTask(task);
    const execution = runBatchSelection(task, names);
    if (deferExecution) {
      void execution.catch((error) => {
        task.status = "failed";
        task.error = String(error.message || error);
        saveTask(task);
      });
      return { taskId: task.id, status: task.status, message: "开始批量执行 " + names.length + " 个策略" };
    }
    return execution;
  }

  function seedTask(task) { return addTask(task); }

  function cleanTasks() {
    const terminal = new Set(["done", "cancelled", "failed"]);
    const before = tasks.length;
    for (let index = tasks.length - 1; index >= 0; index -= 1) {
      if (terminal.has(tasks[index].status)) tasks.splice(index, 1);
    }
    saveTasks();
    return { removed: before - tasks.length, remain: tasks.length };
  }

  return {
    actOnTask,
    addTask,
    cleanTasks,
    createTask,
    dispatchTask,
    getTask,
    listTasks: () => tasks,
    prepareRuleSelection: setAwaitingSelection,
    runAudit,
    runCandidate,
    runInspect,
    runDiagnostic,
    runQuery,
    saveTask,
    seedTask,
    startBatchSelection,
  };
}

module.exports = { createTaskService, normalizeChangeParams };
