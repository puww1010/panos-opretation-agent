function createTaskPlanner({ taskService, llmService, actions, changeTemplates, normalizeChangeParams, planFingerprint, callTool, clock = Date.now }) {
  const sessionGapMs = 5 * 60 * 1000;
  const activeForDedupe = ["pending", "running", "executing", "awaiting_approval", "awaiting_selection", "awaiting_commit"];
  let conversationSequence = 0;

  function providerLabel() { const current = llmService.getCurrent(); return llmService.getProvider?.(current)?.label || current; }
  function nextConversationId() {
    if (!conversationSequence) for (const task of taskService.listTasks()) {
      const match = task.conversationId && String(task.conversationId).match(/^conv-(\d+)$/);
      if (match) conversationSequence = Math.max(conversationSequence, Number(match[1]));
    }
    conversationSequence += 1;
    return "conv-" + conversationSequence;
  }
  function resolveConversation(replyTo) {
    const tasks = taskService.listTasks();
    const target = replyTo && tasks.find((task) => task.id === Number(replyTo));
    if (target) {
      if (!target.conversationId) { target.conversationId = nextConversationId(); taskService.saveTask(target); }
      return { conversationId: target.conversationId, replyTo: target.id };
    }
    const last = tasks[tasks.length - 1];
    const createdAt = last && Date.parse(String(last.createdAt || "").replace(/\//g, "-"));
    if (last && !Number.isNaN(createdAt) && clock() - createdAt < sessionGapMs) {
      if (!last.conversationId) { last.conversationId = nextConversationId(); taskService.saveTask(last); }
      return { conversationId: last.conversationId, replyTo: null };
    }
    return { conversationId: nextConversationId(), replyTo: null };
  }
  function normalizeInput(input) { return String(input || "").toLowerCase().replace(/[\s？?。.！!，,~～`'"、;；:：]+/g, "").replace(/(的|了|呢|啊|呀|嘛|哦|哈)+$/g, "").trim(); }
  function distance(left, right) {
    if (left === right) return 0;
    const rows = Array.from({ length: left.length + 1 }, () => Array(right.length + 1).fill(0));
    for (let row = 0; row <= left.length; row += 1) rows[row][0] = row;
    for (let column = 0; column <= right.length; column += 1) rows[0][column] = column;
    for (let row = 1; row <= left.length; row += 1) for (let column = 1; column <= right.length; column += 1) rows[row][column] = left[row - 1] === right[column - 1] ? rows[row - 1][column - 1] : Math.min(rows[row - 1][column], rows[row][column - 1], rows[row - 1][column - 1]) + 1;
    return rows[left.length][right.length];
  }
  function dedupeActiveTask(input) {
    const normalized = normalizeInput(input);
    if (!normalized) return null;
    const duplicate = taskService.listTasks().find((task) => task.input && activeForDedupe.includes(task.status) && (normalizeInput(task.input) === normalized || distance(normalizeInput(task.input), normalized) <= 3));
    if (!duplicate) return null;
    duplicate.status = "cancelled";
    duplicate.steps.push("🔁 与新提交任务完全一致，被新任务自动取消");
    taskService.saveTask(duplicate);
    return duplicate;
  }
  async function createFreeAnswer(input, firewall, source, conversation) {
    let firewallContext = "";
    try { const firewallInfo = await callTool("get_firewall_info", {}, firewall).catch(() => null); if (firewallInfo?.hostname) firewallContext = `设备: ${firewallInfo.hostname} ${firewallInfo.model} SW${firewallInfo["sw-version"]}`; } catch {}
    const answer = await llmService.answerFree(input, { conversationId: conversation.conversationId, firewallContext });
    const task = taskService.createTask("chat", input, { firewall, source, conversationId: conversation.conversationId, replyTo: conversation.replyTo });
    task.llm = llmService.getCurrent();
    task.decision = `LLM 兜底 → 自由问答（${providerLabel()}）`;
    task.steps.push(task.decision);
    task.result = { answer: answer || "抱歉，LLM 未能给出回答。您可以换个说法，或试试：设备状态 / 安全策略 / 威胁日志 / 完整巡检 / 封禁 1.2.3.4。", sentTo: source === "feishu" ? "feishu" : "web" };
    task.status = "done";
    taskService.addTask(task);
    return { taskId: task.id, status: task.status, type: "chat" };
  }
  async function createTaskFromInput(input, firewall, source, options = {}) {
    dedupeActiveTask(input);
    const conversation = resolveConversation(options.replyTo);
    let action = null, fromLlm = false, minutes = null, nlogs = null;
    for (const [key, value] of Object.entries(actions)) if (key === input || value.label === input) action = key;
    if (!action) { const resolved = await llmService.resolveAction(input, { conversationId: conversation.conversationId, actions }); if (resolved) { action = resolved.action; minutes = resolved.minutes; fromLlm = Boolean(action); } }
    if (action === "traffic" && !minutes) {
      const count = String(input).match(/(?:最新|最近)\s*(\d{1,4})\s*条/);
      if (count) nlogs = Math.max(1, Math.min(1000, Number(count[1])));
      else minutes = 10;
    }
    if (action === "change") {
      const change = await llmService.extractChange(input, { conversationId: conversation.conversationId, changeTemplates });
      if (!change) return { error: "无法解析变更意图（支持：创建/删除地址对象、封禁/放行 IP、移动/删除/禁用/启用安全策略）" };
      const template = changeTemplates[change.template], params = normalizeChangeParams(change.template, change.params);
      const needsPrecheck = ["delete_security_rule", "set_security_rule_disabled", "set_security_rule_enabled"].includes(change.template) && !(params.name && /^[a-zA-Z0-9_.\-]+$/.test(params.name));
      const task = taskService.createTask("change", input, { template: change.template, templateLabel: template.label, params, firewall, source, conversationId: conversation.conversationId, replyTo: conversation.replyTo, status: needsPrecheck ? "awaiting_selection" : "awaiting_approval" });
      task.plan = template.plan(params); task.planFingerprint = planFingerprint({ template: change.template, params, firewall });
      if (needsPrecheck) { try { await taskService.prepareRuleSelection(task, template.label); } catch (error) { task.status = "failed"; task.error = error.message; taskService.saveTask(task); } } else task.steps.push("变更计划已生成，等待审批");
      task.llm = llmService.getCurrent(); taskService.addTask(task); taskService.recordAudit(task, { taskId: task.id, action: "created", from: null, to: task.status, at: new Date(clock()).toISOString() });
      return needsPrecheck && task.status === "awaiting_selection" ? { taskId: task.id, status: task.status, plan: task.plan, candidates: task.result.matched, totalMatches: task.result.totalMatches } : { taskId: task.id, status: task.status, plan: task.plan };
    }
    if (action === "audit") { const audit = await llmService.parseAudit(input); const task = taskService.dispatchTask("audit", input, { firewall, source, audit, conversationId: conversation.conversationId, replyTo: conversation.replyTo }, (item) => { item.llm = llmService.getCurrent(); item.decision = `LLM 规划 → 审计查询（${audit.minutes} 分钟内${audit.object}）（${providerLabel()}）`; item.steps.push(item.decision); }, (item) => taskService.runAudit(item)); return { taskId: task.id, status: task.status, type: "audit" }; }
    if (action === "diag") { const diagnostic = await llmService.parseDiagnostic(input, conversation.conversationId); if (!diagnostic?.type) return createFreeAnswer(input, firewall, source, conversation); const task = taskService.dispatchTask("diag", input, { firewall, source, diag: diagnostic, conversationId: conversation.conversationId, replyTo: conversation.replyTo }, (item) => { item.llm = llmService.getCurrent(); item.decision = `LLM 规划 → 诊断 ${diagnostic.type}（${providerLabel()}）`; item.steps.push(item.decision); }, (item) => taskService.runDiagnostic(item)); return { taskId: task.id, status: task.status, type: "diag" }; }
    if (action === "inspect") { const task = taskService.dispatchTask("inspect", input, { firewall, source, conversationId: conversation.conversationId, replyTo: conversation.replyTo }, null, (item) => taskService.runInspect(item)); return { taskId: task.id, status: task.status, type: "inspect" }; }
    if (action && actions[action]) { const task = taskService.dispatchTask("query", input, { action, firewall, source, minutes, nlogs, conversationId: conversation.conversationId, replyTo: conversation.replyTo }, (item) => { if (fromLlm) item.llm = llmService.getCurrent(); const detail = minutes ? "，时间窗口 " + minutes + " 分钟" : nlogs ? "，最新 " + nlogs + " 条" : ""; item.decision = fromLlm ? `LLM 规划 → 动作 ${action}（${providerLabel()}）${detail}` : `关键词匹配 → 动作 ${action}${detail}`; item.steps.push(item.decision); }, (item) => taskService.runQuery(item, action)); return { taskId: task.id, status: task.status, type: "query", label: actions[action].label }; }
    return createFreeAnswer(input, firewall, source, conversation);
  }
  return { createTaskFromInput };
}

module.exports = { createTaskPlanner };
