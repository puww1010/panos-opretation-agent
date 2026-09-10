function createApiRouter({ dashboardService, llmService, taskService, authService, firewalls = () => [], feishu, actions = () => ({}), isApiPath = (path) => path.startsWith("/api/") }) {
  async function handleDashboard(req, send) {
    if (req.method === "GET" && req.url === "/api/overview") { send(200, await dashboardService.getOverview()); return true; }
    if (req.method === "GET" && req.url === "/api/topology") { send(200, await dashboardService.getTopology()); return true; }
    if (req.method === "GET" && req.url.startsWith("/api/metrics")) {
      const url = new URL(req.url, "http://localhost");
      const minutes = Math.max(1, Math.min(1440, parseInt(url.searchParams.get("minutes") || "120", 10) || 120));
      send(200, dashboardService.getMetrics(minutes));
      return true;
    }
    if (req.method === "GET" && req.url === "/api/history") { send(200, { history: dashboardService.getHistory() }); return true; }
    return false;
  }
  async function handleLlm(req, send, readBody) {
    if (req.method === "POST" && req.url === "/api/llm/reset") { send(200, { current: llmService.getCurrent(), note: "保持用户选择" }); return true; }
    if (req.method === "GET" && req.url === "/api/actions") { send(200, { actions: Object.fromEntries(Object.entries(actions()).map(([key, action]) => [key, action.label])), llm: llmService.getCurrent() !== "keyword", model: llmService.getCurrent() !== "keyword" ? llmService.getModel() : null }); return true; }
    if (req.method === "GET" && req.url === "/api/llm") { send(200, llmService.getPublicConfig()); return true; }
    if (req.method === "GET" && req.url === "/api/llm/log") { send(200, { logs: llmService.getLogs() }); return true; }
    if (req.method === "POST" && req.url === "/api/llm/config") {
      const { provider, base_url, model, key, env, label } = JSON.parse(await readBody());
      try { send(200, llmService.saveProvider({ provider, base_url, model, key, env, label })); }
      catch (error) { send(error.message === "provider 必填且仅小写字母数字下划线" ? 400 : 500, { error: error.message === "provider 必填且仅小写字母数字下划线" ? error.message : "写入 llm-config.json 失败：" + error.message }); }
      return true;
    }
    if (req.method === "POST" && req.url === "/api/llm/config/delete") { const { provider } = JSON.parse(await readBody()); try { send(200, llmService.deleteProvider(provider)); } catch { send(200, { ok: true }); } return true; }
    if (req.method === "POST" && req.url === "/api/llm/select") {
      const { provider } = JSON.parse(await readBody()); const selected = llmService.selectProvider(provider);
      if (selected.ok) { send(200, { current: selected.current }); return true; }
      const value = selected.provider; const signup = { deepseek: "https://platform.deepseek.com", qwen: "https://bailian.console.aliyun.com", kimi: "https://platform.moonshot.cn" };
      send(400, { error: "「" + (value?.label || provider) + "」未配置 API key", hint: "请按以下步骤配置：\n\n1. 申请 API key：\n   " + (signup[provider] || value?.base_url || "https://...") + "\n\n2. 在 webui/start.sh 中添加环境变量：\n   export " + (value?.env || "?") + '=\"你的key\"\n\n3. 重启控制台：\n   cd webui && ./start.sh' });
      return true;
    }
    if (req.method === "POST" && req.url === "/api/llm/test") { const { text } = JSON.parse(await readBody()); const started = Date.now(); const output = await llmService.classify("手动测试", "你是防火墙运维意图分类器。输出 JSON：{\"action\":\"<key>\"}。可选 key：device(设备状态)/security(安全策略)/threat(威胁日志)/traffic(流量日志)/inspect(完整巡检)/change(变更)/diag(诊断)/null(无关)", text || ""); send(200, { output, ms: Date.now() - started, provider: llmService.getCurrent() }); return true; }
    return false;
  }
  async function handleTasks(req, send, readBody, taskCreator, ensureConnected) {
    const parsed = new URL(req.url, "http://localhost");
    const exportMatch = parsed.pathname.match(/^\/api\/task\/(\d+)\/logs\/export$/);
    if (req.method === "GET" && exportMatch) {
      const result = taskService.getTrafficLogPage && taskService.exportTrafficLogs(Number(exportMatch[1]));
      if (!result) { send(404, { error: "该任务的原始流量日志已不在内存中，请重新运行查询" }); return true; }
      send(200, result);
      return true;
    }
    const pageMatch = parsed.pathname.match(/^\/api\/task\/(\d+)\/logs$/);
    if (req.method === "GET" && pageMatch) {
      const page = Math.max(1, parseInt(parsed.searchParams.get("page") || "1", 10) || 1);
      const size = Math.max(1, Math.min(100, parseInt(parsed.searchParams.get("size") || "50", 10) || 50));
      const result = taskService.getTrafficLogPage && taskService.getTrafficLogPage(Number(pageMatch[1]), page, size);
      if (!result) { send(404, { error: "该任务的原始流量日志已不在内存中，请重新运行查询" }); return true; }
      send(200, result);
      return true;
    }
    if (req.method === "GET" && req.url === "/api/tasks") { send(200, { tasks: taskService.listTasks() }); return true; }
    if (req.method === "POST" && req.url === "/api/tasks/clean") { send(200, taskService.cleanTasks()); return true; }
    if (req.method === "POST" && req.url === "/api/task") { const { query, firewall, source, replyTo } = JSON.parse(await readBody()); await ensureConnected(); send(200, await taskCreator(query, firewall, source || "web", { replyTo })); return true; }
    if (req.method === "POST" && req.url.startsWith("/api/task/")) { const parts = req.url.split("/"), id = Number(parts[3]), action = parts[4], name = parts[5] ? decodeURIComponent(parts[5]) : null, task = taskService.getTask(id); if (!task) { send(404, { error: "task not found" }); return true; } try { if (action === "select" && task.status === "awaiting_selection" && task._candidate) send(200, await taskService.actOnTask(id, "select", { params: { name, keyword: task._candidate.keyword }, firewall: task._candidate.firewall, step: `用户从候选选中：${name}` })); else if (action === "select-multi") send(200, await taskService.startBatchSelection(id, JSON.parse(await readBody()).names)); else if (["approve", "reject", "confirm", "cancel"].includes(action)) send(200, await taskService.actOnTask(id, action)); else { send(400, { error: "非法操作或状态不匹配: " + task.status }); return true; } } catch (error) { const message = String(error.message || error); send(message === "变更计划已变化，请重新生成候选计划" ? 409 : 400, { error: message }); } return true; }
    return false;
  }
  async function handleOperations(req, send, readBody) {
    if (req.method === "GET" && req.url === "/api/firewalls") { const list = firewalls(); send(200, { firewalls: list, multi: list.length > 1 }); return true; }
    if (req.url === "/api/feishu/status") { send(200, await feishu.status()); return true; }
    if (req.url === "/api/feishu/send") { const { text } = JSON.parse(await readBody()); if (!text) { send(400, { error: "消息不能为空" }); return true; } send(200, await feishu.send(text)); return true; }
    if (req.url === "/api/feishu/push-report") { const report = feishu.latestReport(); if (!report) { send(400, { error: "没有合规报告" }); return true; } send(200, await feishu.send(report)); return true; }
    return false;
  }
  async function handleAuth(req, send, readBody, touchIfUserAction) {
    const path = req.url.split("?")[0];
    if (req.method === "POST" && path === "/api/auth/login") { let credentials = {}; try { credentials = JSON.parse(await readBody()); } catch {} const login = authService.login(credentials); send(login.ok ? 200 : 401, login.ok ? login : { error: "用户名或密码错误" }); return true; }
    if (!isApiPath(path)) return false;
    if (req.method === "POST" && path === "/api/auth/logout") { send(200, authService.logout(authService.tokenFromRequest(req))); return true; }
    if (req.method === "GET" && path === "/api/auth/check") { const ok = authService.checkRequest(req); send(ok ? 200 : 401, ok ? { ok: true, username: authService.getUsername(), idleMinutes: authService.idleMinutes } : { error: "未认证" }); return true; }
    if (!authService.checkRequest(req)) { send(401, { error: "未认证或登录已过期，请重新登录" }); return true; }
    if (req.method === "POST" && path === "/api/auth/keepalive") { authService.touch(authService.tokenFromRequest(req)); send(200, { ok: true, idleMinutes: authService.idleMinutes }); return true; }
    if (req.method === "POST" && path === "/api/auth/change-password") { let credentials = {}; try { credentials = JSON.parse(await readBody()); } catch {} const changed = authService.changePassword(authService.tokenFromRequest(req), credentials); send(changed.ok ? 200 : 400, changed.ok ? changed : { error: changed.error }); return true; }
    touchIfUserAction(authService.tokenFromRequest(req)); return false;
  }
  return { handleDashboard, handleLlm, handleTasks, handleOperations, handleAuth };
}

module.exports = { createApiRouter };
