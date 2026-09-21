const test = require("node:test");
const assert = require("node:assert/strict");
const { createMonitorService } = require("../services/monitor/service");
const fixture = { id: "system", category: "device_health", label: "设备信息", sources: ["system"], evaluate: (data) => [{ metric: "设备", value: data.system?.system?.hostname, severity: data.system?.system?.hostname ? "ok" : "unknown", message: "设备信息", recommendation: "" }] };

test("monitor service separates partial coverage from a healthy finding", async () => {
  const progress = [];
  const service = createMonitorService({ definitions: [fixture, { ...fixture, id: "other", sources: ["other"] }], readSource: async (source) => { if (source === "other") throw Object.assign(new Error("raw sensitive URL"), { code: "authentication" }); return { system: { hostname: "fixture-fw" } }; } });
  const report = await service.run({ firewall: "lab", onProgress: (step) => progress.push(step) });
  assert.equal(report.executionStatus, "partial");
  assert.equal(report.coverage.valid, 1);
  assert.equal(report.coverage.error, 1);
  assert.equal(report.coverage.total, 2);
  assert.equal(report.checks[1].collection, "error");
  assert.equal(JSON.stringify(report).includes("raw sensitive URL"), false);
  assert.equal(progress.filter((step) => step.status === "running").length, 2);
});

test("empty collection is unknown and cannot produce an all-green report", async () => {
  const service = createMonitorService({ definitions: [fixture], readSource: async () => ({}) });
  const report = await service.run({ firewall: "lab" });
  assert.equal(report.executionStatus, "partial");
  assert.equal(report.overallSeverity, "unknown");
  assert.equal(report.coverage.unknown, 1);
});

test("late collector results after cancellation cannot finish as done", async () => {
  const ac = new AbortController();
  const service = createMonitorService({ definitions: [fixture], readSource: async () => { ac.abort(); return { system: { hostname: "late" } }; } });
  const report = await service.run({ firewall: "lab", signal: ac.signal });
  assert.equal(report.executionStatus, "cancelled");
  assert.equal(report.coverage.valid, 0);
});

test("monitor service bounds a hung collector and validates selection", async () => {
  const service = createMonitorService({ definitions: [fixture], sourceTimeoutMs: 10, readSource: async () => new Promise(() => {}) });
  const report = await service.run({ firewall: "lab" });
  assert.equal(report.executionStatus, "failed");
  assert.equal(report.checks[0].sources[0].errorCode, "timeout");
  await assert.rejects(() => service.run({ firewall: "lab", checks: ["invalid"] }), /检查项/);
  await assert.rejects(() => service.run({ firewall: "lab", minutes: 0 }), /时间窗口/);
});

test("reports sanitize secrets in evidence without modifying the source object", async () => {
  const data = { system: { hostname: "fixture-fw", token: "YOUR_TOKEN_HERE", authcode: "YOUR_LICENSE_CODE_HERE", key: "YOUR_KEY_HERE", url: "https://example.invalid/?key=YOUR_API_KEY_HERE" } };
  const service = createMonitorService({ definitions: [fixture], readSource: async () => data });
  const report = await service.run({ firewall: "lab" });
  assert.doesNotMatch(JSON.stringify(report), /YOUR_TOKEN_HERE|YOUR_API_KEY_HERE|YOUR_LICENSE_CODE_HERE|YOUR_KEY_HERE/);
  assert.equal(data.system.token, "YOUR_TOKEN_HERE");
});
test("structured findings retain a late critical item beyond evidence preview limits", async () => {
  const findings = Array.from({ length: 60 }, (_, i) => ({ metric: 'item ' + i, severity: i === 59 ? 'critical' : 'ok', message: 'fixture' }));
  const report = await createMonitorService({ definitions: [{ ...fixture, evaluate: () => findings }], readSource: async () => ({}) }).run({ firewall: 'lab' });
  assert.equal(report.checks[0].findings.length, 60);
  assert.equal(report.overallSeverity, 'critical');
  assert.equal(JSON.parse(require('../services/monitor/report').exportMonitorReport(1, report, 'json').content).checks[0].findings.length, 60);
});
test('explicitly disabled HA skips inapplicable diagnostic queries', async () => {
  const calls = [];
  const service = createMonitorService({ readSource: async id => { calls.push(id); if (id !== 'ha_all') throw new Error('must not query disabled HA'); return { enabled: 'no' }; } });
  const report = await service.run({ firewall: 'lab', checks: ['ha_diagnostics'] });
  assert.deepEqual(calls, ['ha_all']);
  assert.equal(report.coverage.not_applicable, 1);
  assert.equal(report.executionStatus, 'completed');
});
