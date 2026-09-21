const test = require("node:test");
const assert = require("node:assert/strict");
const { createPanosAdapter } = require("../adapters/panos-adapter");

test("monitor reader accepts only fixed read sources and preserves the selected firewall", async () => {
  const calls = [];
  const adapter = createPanosAdapter({ callMcpTool: async (...args) => { calls.push(args); return { system: { hostname: "fixture-fw" } }; } });
  assert.equal(typeof adapter.readMonitorSource, "function");
  const result = await adapter.readMonitorSource("system", "lab-b");
  assert.equal(result.system.hostname, "fixture-fw");
  assert.equal(calls[0][2], "lab-b");
  assert.equal(calls[0][0], "run_op_command");
  assert.equal(calls[0][1].command, "<show><system><info/></system></show>");
  await assert.rejects(() => adapter.readMonitorSource("<request><restart><system/></restart></request>", "lab-b"), /未允许/);
  assert.equal(calls.length, 1);
});

test("monitor reader detects MCP error text and never includes raw credentials in errors", async () => {
  const adapter = createPanosAdapter({ callMcpTool: async () => ({ raw: "Error: HTTP 403 https://example.invalid/api/?key=YOUR_API_KEY_HERE" }) });
  assert.equal(typeof adapter.readMonitorSource, "function");
  await assert.rejects(() => adapter.readMonitorSource("system", "lab"), (error) => error.code === "authentication" && !error.message.includes("YOUR_API_KEY_HERE"));
});

test("monitor reader honors cancellation before starting a request", async () => {
  let calls = 0;
  const adapter = createPanosAdapter({ callMcpTool: async () => { calls += 1; return {}; } });
  const controller = new AbortController(); controller.abort();
  assert.equal(typeof adapter.readMonitorSource, "function");
  await assert.rejects(() => adapter.readMonitorSource("system", "lab", { signal: controller.signal }), { name: "AbortError" });
  assert.equal(calls, 0);
});

test("threat monitoring uses a bounded device-clock window and exposes truncation", async () => {
  const calls = [];
  const adapter = createPanosAdapter({ callMcpTool: async (name, args, firewall) => {
    calls.push({ name, args, firewall });
    if (name === "run_op_command") return { system: { time: "2026/09/21 14:30:00" } };
    return { "@_count": 1000, entry: Array.from({ length: 1000 }, () => ({ receive_time: "2026/09/21 14:29:00", severity: "high" })) };
  } });
  const logs = await adapter.readMonitorSource("threat_logs", "lab-b", { minutes: 10 });
  assert.equal(calls[1].name, "get_threat_logs");
  assert.equal(calls[1].firewall, "lab-b");
  assert.equal(calls[1].args.nlogs, 1000);
  assert.match(calls[1].args.query, /2026\/09\/21 14:20:00/);
  assert.match(calls[1].args.query, /2026\/09\/21 14:30:00/);
  assert.equal(logs.window.complete, false);
  assert.equal(logs.window.clock, "device");
});

test("unavailable device clock never silently queries an assumed time window", async () => {
  let calls = 0;
  const adapter = createPanosAdapter({ callMcpTool: async () => { calls += 1; return { system: { time: "?" } }; } });
  await assert.rejects(() => adapter.readMonitorSource("threat_logs", "lab", { minutes: 10 }), /时间/);
  assert.equal(calls, 1);
});

test("certificate monitoring reuses the existing read tool and retains only public metadata", async () => {
  const adapter = createPanosAdapter({ callMcpTool: async (tool) => {
    assert.equal(tool, "get_certificates");
    return { certificate: { entry: { "@_name": "fixture-cert", "not-valid-after": "2027-01-01", "private-key": "YOUR_PRIVATE_KEY_HERE", passphrase: "YOUR_PASSPHRASE_HERE" } } };
  } });
  const data = await adapter.readMonitorSource("certificates", "lab");
  assert.doesNotMatch(JSON.stringify(data), /YOUR_PRIVATE_KEY_HERE|YOUR_PASSPHRASE_HERE/);
  assert.equal(data.scope, "candidate/shared");
  assert.equal(data.certificates.entry[0]["not-valid-after"], "2027-01-01");
});
test('deprecated CLI and invalid argument responses cannot look like successful evidence', async () => {
  for (const data of ['Command deprecated in Advanced Routing Mode.', { raw: 'Error: show -> zone-protection -> zone is invalid' }, { raw: 'Error: invalid client cli' }]) {
    const adapter = createPanosAdapter({ callMcpTool: async () => data });
    await assert.rejects(() => adapter.readMonitorSource('routing', 'lab'), { code: 'unsupported' });
  }
});
