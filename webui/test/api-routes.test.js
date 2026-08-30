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
