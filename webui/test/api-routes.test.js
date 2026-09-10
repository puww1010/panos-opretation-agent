const test = require("node:test");
const assert = require("node:assert/strict");
const { createApiRouter } = require("../routes/api-routes");

test("API router preserves dashboard route methods and payloads", async () => {
  const sent = [];
  const router = createApiRouter({ dashboardService: {
    getOverview: async () => ({ kpi: { device: {} } }),
    getTopology: async () => ({ fw: { hostname: "fw-a" } }),
    getMetrics: (minutes) => ({ series: [], windowMinutes: minutes }),
    getHistory: () => [{ input: "查询" }],
  } });
  const send = (code, body) => sent.push({ code, body });

  assert.equal(await router.handleDashboard({ method: "GET", url: "/api/overview" }, send), true);
  assert.equal(await router.handleDashboard({ method: "GET", url: "/api/metrics?minutes=30" }, send), true);
  assert.equal(await router.handleDashboard({ method: "POST", url: "/api/overview" }, send), false);

  assert.deepEqual(sent, [{ code: 200, body: { kpi: { device: {} } } }, { code: 200, body: { series: [], windowMinutes: 30 } }]);
});

test("API router owns firewall, Feishu, and auth HTTP contracts", async () => {
  const sent = [];
  const touched = [];
  const router = createApiRouter({
    dashboardService: {},
    firewalls: () => [{ name: "fw-a", host: "192.0.2.1" }],
    feishu: {
      status: async () => ({ running: false }),
      send: async (text) => ({ ok: true, text }),
      latestReport: () => null,
    },
    authService: {
      checkRequest: (req) => req.headers?.authorization === "Bearer token",
      changePassword: () => ({ ok: true }),
      getUsername: () => "admin",
      idleMinutes: 0,
      login: ({ username, password }) => username === "admin" && password === "good" ? { ok: true, token: "token" } : { ok: false },
      logout: () => ({ ok: true }),
      tokenFromRequest: () => "token",
      touch: (token) => touched.push(token),
    },
  });
  const send = (code, body) => sent.push({ code, body });
  const body = async () => JSON.stringify({ username: "admin", password: "good" });

  assert.equal(await router.handleOperations({ method: "GET", url: "/api/firewalls" }, send, body), true);
  assert.equal(await router.handleOperations({ method: "POST", url: "/api/feishu/push-report" }, send, body), true);
  assert.equal(await router.handleAuth({ method: "POST", url: "/api/auth/login", headers: {} }, send, body, () => {}), true);
  assert.equal(await router.handleAuth({ method: "GET", url: "/api/tasks", headers: { authorization: "Bearer token" } }, send, body, (token) => touched.push(token)), false);

  assert.deepEqual(sent, [
    { code: 200, body: { firewalls: [{ name: "fw-a", host: "192.0.2.1" }], multi: false } },
    { code: 400, body: { error: "没有合规报告" } },
    { code: 200, body: { ok: true, token: "token" } },
  ]);
  assert.deepEqual(touched, ["token"]);
});

test("LLM manual test retains the legacy action catalog", async () => {
  let prompt = "";
  const router = createApiRouter({
    dashboardService: {},
    llmService: {
      classify: async (_title, value) => { prompt = value; return { action: "device" }; },
      getCurrent: () => "keyword",
    },
  });
  const sent = [];
  const handled = await router.handleLlm({ method: "POST", url: "/api/llm/test" }, (code, body) => sent.push({ code, body }), async () => JSON.stringify({ text: "设备状态" }));

  assert.equal(handled, true);
  assert.match(prompt, /device\(设备状态\).*diag\(诊断\)/);
  assert.equal(sent[0].code, 200);
});

test("task router exposes traffic-log pages and export only through Task Service", async () => {
  const sent = [];
  const calls = [];
  const router = createApiRouter({
    dashboardService: {},
    taskService: {
      getTrafficLogPage: (id, page, size) => { calls.push(["page", id, page, size]); return { page, size, total: 2, rows: [{ action: "allow" }] }; },
      exportTrafficLogs: (id) => { calls.push(["export", id]); return { rows: [{ action: "allow" }, { action: "deny" }] }; },
    },
  });
  const send = (code, body) => sent.push({ code, body });

  assert.equal(await router.handleTasks({ method: "GET", url: "/api/task/42/logs?page=2&size=50" }, send, async () => "", null, null), true);
  assert.equal(await router.handleTasks({ method: "GET", url: "/api/task/42/logs/export" }, send, async () => "", null, null), true);

  assert.deepEqual(calls, [["page", 42, 2, 50], ["export", 42]]);
  assert.deepEqual(sent, [
    { code: 200, body: { page: 2, size: 50, total: 2, rows: [{ action: "allow" }] } },
    { code: 200, body: { rows: [{ action: "allow" }, { action: "deny" }] } },
  ]);
});
