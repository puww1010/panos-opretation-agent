const test = require("node:test");
const assert = require("node:assert/strict");
const { exportMonitorReport } = require("../services/monitor/report");
const { renderMonitorReport } = require("../assets/monitor-ui");
const { createApiRouter } = require("../routes/api-routes");
const { createStaticRouter } = require("../routes/static-routes");
const path = require("node:path");

const report = { skillId: "panos-monitor", schemaVersion: 1, skillRevision: "fixture", firewall: "fixture-fw", startedAt: "2026-09-21T00:00:00Z", finishedAt: "2026-09-21T00:01:00Z", minutes: 10, executionStatus: "partial", overallSeverity: "unknown", coverage: { total: 2, valid: 1, partial: 0, error: 0, unsupported: 1, not_applicable: 0, unknown: 0, not_run: 0, percent: 50 }, checks: [{ id: "system", label: '<img src=x onerror="alert(1)">', category: "device_health", categoryLabel: "设备健康", collection: "ok", severity: "ok", findings: [{ metric: "hostname", value: "fixture-fw", severity: "ok", message: "已读取", recommendation: "" }], sources: [{ id: "system", status: "ok", observedAt: "2026-09-21T00:00:00Z" }], evidence: { system: { hostname: "fixture-fw" } } }] };

test("Chinese reports show coverage, preserve evidence and escape untrusted text", () => {
  const html = exportMonitorReport(8, report, "html");
  assert.equal(html.mime, "text/html;charset=utf-8");
  assert.match(html.content, /部分完成/);
  assert.match(html.content, /50%/);
  assert.match(html.content, /设备健康/);
  assert.match(html.content, /证据/);
  assert.doesNotMatch(html.content, /<img src=x|<script|onclick=/);
  assert.match(html.content, /&lt;img/);
  assert.deepEqual(JSON.parse(exportMonitorReport(8, report, "json").content), report);
  assert.throws(() => exportMonitorReport(8, report, "../cfgs/auth.json"), /格式/);
});

test("task UI exposes both report download actions and a missing-data notice", () => {
  const html = renderMonitorReport(8, report);
  assert.match(html, /downloadMonitorReport\(8,'json'\)/);
  assert.match(html, /downloadMonitorReport\(8,'html'\)/);
  assert.match(html, /不代表全部正常/);
});

test("only the public monitor UI module is served and page downloads via authenticated API", () => {
  const router = createStaticRouter({ rootDirectory: path.join(__dirname, "..") });
  const res = { writeHead(code, headers) { this.code = code; this.headers = headers; }, end(body) { this.body = body; } };
  assert.equal(router.handle({ method: "GET", url: "/assets/monitor-ui.js" }, res), true);
  assert.match(res.headers["Content-Type"], /javascript/);
  assert.equal(res.headers["Cache-Control"], "no-store");
  assert.equal(router.handle({ method: "GET", url: "/services/monitor/service.js" }, res), false);
  assert.equal(router.handle({ method: "GET", url: "/assets/../services/monitor/service.js" }, res), false);
  router.handle({ method: "GET", url: "/" }, res);
  assert.ok(res.body.includes("async function downloadMonitorReport"));
  assert.ok(res.body.includes('fjs("/api/task/" + id + "/monitor/export'));
});

test("monitor routes use Task Service and return 404 or 400 for invalid exports", async () => {
  const calls = [], sent = [];
  const router = createApiRouter({ taskService: {
    listMonitorChecks: () => [{ id: "system", label: "设备信息" }],
    exportMonitorReport: (id, format) => { calls.push([id, format]); return id === 8 ? { filename: "fixture.json", content: "{}" } : null; },
  } });
  for (const url of ["/api/monitor/checks", "/api/task/8/monitor/export?format=json", "/api/task/9/monitor/export?format=html", "/api/task/8/monitor/export?format=js"]) {
    assert.equal(await router.handleTasks({ method: "GET", url }, (code, body) => sent.push({ code, body })), true);
  }
  assert.deepEqual(sent.map((item) => item.code), [200, 200, 404, 400]);
  assert.deepEqual(calls, [[8, "json"], [9, "html"]]);
});
