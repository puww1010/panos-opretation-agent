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
test('compliance sources use the existing fixed tools with selected firewall and cancellation', async () => {
  for (const [source, expected] of [['security_rules', 'get_security_rules'], ['wildfire', 'get_wildfire_status'], ['content_versions', 'get_content_versions']]) {
    const controller = new AbortController();
    const adapter = createPanosAdapter({ callMcpTool: async (tool, args, firewall, options) => {
      assert.equal(tool, expected);
      assert.deepEqual(args, {});
      assert.equal(firewall, 'lab-b');
      assert.equal(options.signal, controller.signal);
      return { success: true, data: { observed: true } };
    } });
    assert.deepEqual(await adapter.readMonitorSource(source, 'lab-b', { signal: controller.signal }), { observed: true });
  }
});
test('traffic logs use a capped device window and return counts without traffic details', async () => {
  const calls = [];
  const adapter = createPanosAdapter({ callMcpTool: async (tool, args, firewall, options) => {
    calls.push({ tool, args, firewall, signal: options.signal });
    if (tool === 'run_op_command') return { system: { time: '2026/09/21 00:05:00' } };
    return { entry: Array.from({ length: 1000 }, () => ({ receive_time: '2026/09/21 00:04:00', src: '192.0.2.1' })) };
  } });
  const controller = new AbortController();
  const data = await adapter.readMonitorSource('traffic_logs', 'lab-b', { minutes: 10, signal: controller.signal });
  assert.equal(calls[1].tool, 'get_traffic_logs');
  assert.equal(calls[1].args.nlogs, 1000);
  assert.match(calls[1].args.query, /2026\/09\/20 23:55:00/);
  assert.match(calls[1].args.query, /2026\/09\/21 00:05:00/);
  assert(calls.every(call => call.firewall === 'lab-b' && call.signal === controller.signal));
  assert.equal(data.count, 1000);
  assert.equal(data.window.complete, false);
  assert.equal(data.window.clock, 'device');
  assert.deepEqual(Object.keys(data).sort(), ['count', 'window']);
});
test('traffic monitoring never queries logs using a missing or invalid device time', async () => {
  for (const time of [undefined, '?', '2026/02/30 10:00:00']) {
    let calls = 0;
    const adapter = createPanosAdapter({ callMcpTool: async () => { calls += 1; return { system: { time } }; } });
    await assert.rejects(() => adapter.readMonitorSource('traffic_logs', 'lab'), { code: 'clock' });
    assert.equal(calls, 1);
  }
});
test('traffic empty counts are valid observations but unknown response shapes fail collection', async () => {
  for (const data of [{ '@_count': 0 }, { entry: [] }]) {
    const adapter = createPanosAdapter({ callMcpTool: async tool => tool === 'run_op_command' ? { time: '2026/09/21 10:00:00' } : data });
    const result = await adapter.readMonitorSource('traffic_logs', 'lab');
    assert.equal(result.count, 0);
    assert.equal(result.window.complete, true);
  }
  const adapter = createPanosAdapter({ callMcpTool: async tool => tool === 'run_op_command' ? { time: '2026/09/21 10:00:00' } : { status: 'success' } });
  await assert.rejects(() => adapter.readMonitorSource('traffic_logs', 'lab'), { code: 'response' });
});
test('traffic collection rejects malformed rows, coerced zero counts and responses over the cap', async () => {
  for (const data of [{ '@_count': false }, { '@_count': '' }, { entry: 'unexpected' }, { entry: [null] }, { entry: [{}] }, { entry: [], '@_count': 2 }, { entry: Array.from({ length: 1001 }, () => ({ receive_time: '2026/09/21 09:59:00' })) }]) {
    const adapter = createPanosAdapter({ callMcpTool: async tool => tool === 'run_op_command' ? { time: '2026/09/21 10:00:00' } : data });
    await assert.rejects(() => adapter.readMonitorSource('traffic_logs', 'lab'), { code: 'response' });
  }
});
test('traffic observations require a recognizable receive time within the requested device window', async () => {
  for (const entry of [{ unexpected: 'row' }, { receive_time: '?' }, { receive_time: '2026/09/21 09:30:00' }, { receive_time: '2026/09/21 10:01:00' }]) {
    const adapter = createPanosAdapter({ callMcpTool: async tool => tool === 'run_op_command' ? { time: '2026/09/21 10:00:00' } : { entry } });
    await assert.rejects(() => adapter.readMonitorSource('traffic_logs', 'lab'), { code: 'response' });
  }
});
test('threat logs apply the same response and timestamp validation as traffic logs', async () => {
  for (const data of [{ entry: 'unexpected' }, { entry: [{ receive_time: '2026/09/21 09:00:00' }] }, { entry: [{ severity: 'high' }] }, { '@_count': false }, { entry: [], '@_count': 1 }]) {
    const calls = [];
    const adapter = createPanosAdapter({ callMcpTool: async tool => {
      calls.push(tool);
      return tool === 'run_op_command' ? { time: '2026/09/21 10:00:00' } : data;
    } });
    await assert.rejects(() => adapter.readMonitorSource('threat_logs', 'lab', { minutes: 10 }), { code: 'response' });
    assert.deepEqual(calls, ['run_op_command', 'get_threat_logs']);
  }
});
test('valid threat logs retain entries after bounded device-window validation', async () => {
  const entry = [{ receive_time: '2026/09/21 09:59:00', severity: 'high' }];
  const adapter = createPanosAdapter({ callMcpTool: async tool => tool === 'run_op_command' ? { time: '2026/09/21 10:00:00' } : { entry, '@_count': 1 } });
  const result = await adapter.readMonitorSource('threat_logs', 'lab', { minutes: 10 });
  assert.deepEqual(result.entry, entry);
  assert.equal(result.count, 1);
  assert.equal(result.window.complete, true);
});
