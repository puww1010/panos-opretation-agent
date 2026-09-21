'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createMonitorService } = require('../services/monitor/service');
const { createPanosAdapter } = require('../adapters/panos-adapter');
const ids = ['policy_hygiene', 'wildfire', 'content_versions', 'logging_health'];
function check(id) {
  assert(createMonitorService().listChecks().some(item => item.id === id), `missing check ${id}`);
  return require('../services/monitor/compliance-checks').complianceChecks.find(item => item.id === id);
}
const rule = overrides => ({ '@_name': 'fixture-rule', action: 'allow', disabled: 'no', source: { member: '192.0.2.1' }, destination: { member: '198.51.100.1' }, ...overrides });
const window = { start: '2026/09/21 10:00:00', end: '2026/09/21 10:10:00', clock: 'device', minutes: 10, limit: 1000, complete: true };
const logs = (count, changes = {}) => ({ count, window: { ...window, ...changes } });

test('four compliance checks register fixed existing read sources and categories', () => {
  const { SOURCES } = require('../services/monitor/sources');
  const { CATEGORIES } = require('../services/monitor/service');
  for (const id of ids) {
    const definition = check(id);
    assert(Object.hasOwn(CATEGORIES, definition.category));
    for (const source of definition.sources) assert(Object.hasOwn(SOURCES, source));
  }
});
for (const id of ids) test(`${id}: missing or unrecognized responses remain unknown`, () => {
  const definition = check(id);
  for (const value of [undefined, {}, { unexpected: 'healthy' }]) {
    const result = definition.evaluate(Object.fromEntries(definition.sources.map(source => [source, value])));
    assert(result.some(item => item.severity === 'unknown'));
    assert(!result.some(item => item.severity === 'ok'));
  }
});
test('policy recognizes scoped rules with string and array members', () => {
  for (const member of ['192.0.2.1', ['192.0.2.1'], { '#text': '192.0.2.1' }]) {
    const result = check('policy_hygiene').evaluate({ security_rules: { rules: { entry: rule({ source: { member } }) } } });
    assert(result.some(item => item.severity === 'ok'));
    assert(!result.some(item => ['warning', 'critical', 'unknown'].includes(item.severity)));
    assert.match(result[0].message, /vsys1/);
  }
});
test('policy flags explicitly active allow-any-any in either member representation', () => {
  for (const member of ['any', ['any']]) {
    const result = check('policy_hygiene').evaluate({ security_rules: { entry: rule({ source: { member }, destination: { member } }) } });
    assert(result.some(item => ['warning', 'critical'].includes(item.severity)));
  }
});
test('policy handles explicit disabled and denies without inferring broader protection', () => {
  for (const disabled of ['yes', true]) {
    const result = check('policy_hygiene').evaluate({ security_rules: { entry: rule({ disabled, source: { member: 'any' }, destination: { member: 'any' } }) } });
    assert(result.every(item => item.severity === 'info'));
    assert.match(result[0].message, /停用/);
  }
  assert(check('policy_hygiene').evaluate({ security_rules: { entry: rule({ action: 'deny' }) } }).every(item => item.severity === 'info'));
});
test('policy empty lists, malformed members and missing activation never look healthy', () => {
  for (const entry of [[], '', { unexpected: true }, rule({ disabled: undefined }), rule({ action: undefined }), rule({ source: { member: [] } }), rule({ destination: { member: true } })]) {
    const result = check('policy_hygiene').evaluate({ security_rules: { rules: { entry } } });
    assert(result.some(item => item.severity === 'unknown'));
    assert(!result.some(item => item.severity === 'ok'));
  }
});
test('policy preserves malformed rows and late risks under the existing finding bound', () => {
  const entry = [...Array.from({ length: 120 }, (_, index) => rule({ '@_name': `allowed-${index}` })), { unexpected: 'row' }, rule({ '@_name': 'broad-last', source: { member: 'any' }, destination: { member: 'any' } })];
  const result = check('policy_hygiene').evaluate({ security_rules: { entry } });
  assert.equal(result.length, 100);
  assert(result.some(item => ['warning', 'critical'].includes(item.severity) && item.metric.includes('broad-last')));
  assert(result.some(item => item.severity === 'unknown'));
});
test('WildFire recognizes explicit connection and configuration states', () => {
  for (const wildfire of [{ status: 'connected' }, 'Connection status: Connected']) assert(check('wildfire').evaluate({ wildfire }).some(item => item.severity === 'ok'));
  for (const wildfire of [{ status: 'disconnected' }, { enabled: false }, 'Disabled due to configuration', 'Connection status: disconnected']) assert(check('wildfire').evaluate({ wildfire }).some(item => ['warning', 'critical'].includes(item.severity)));
});
test('WildFire unrelated positive or negative text does not manufacture a state', () => {
  for (const wildfire of ['WildFire statistics collected', 'No connection failures observed', 'Error count: 0', { enabled: true }, { status: 'unrecognized' }]) {
    const result = check('wildfire').evaluate({ wildfire });
    assert(result.some(item => item.severity === 'unknown'));
    assert(!result.some(item => item.severity === 'ok'));
  }
});
test('WildFire retains disconnected and unknown states beside connected entries', () => {
  for (const wildfire of [{ entry: [{ status: 'connected' }, { status: 'disconnected' }, { status: 'unrecognized' }] }, 'Connection status: connected\nConnection status: disconnected\nConnection status: unrecognized']) {
    const result = check('wildfire').evaluate({ wildfire });
    assert(result.some(item => item.severity === 'warning'));
    assert(result.some(item => item.severity === 'unknown'));
  }
});
test('WildFire incomplete named entries stay visible beside a connected entry', () => {
  const result = check('wildfire').evaluate({ wildfire: { entry: [{ name: 'cloud-a', status: 'connected' }, { name: 'cloud-b' }] } });
  assert(result.some(item => item.severity === 'unknown'));
});
test('WildFire disabled cloud does not hide unknown or connected sibling clouds', async () => {
  for (const includeConnected of [false, true]) {
    const entry = [{ name: 'cloud-a', enabled: false }, { name: 'cloud-b' }];
    if (includeConnected) entry.push({ name: 'cloud-c', status: 'connected' });
    const result = check('wildfire').evaluate({ wildfire: { entry } });
    assert(result.some(item => item.severity === 'unknown'));
    assert(result.some(item => item.metric.includes('cloud-a') && item.severity === 'warning'));
    assert(result.some(item => item.metric.includes('cloud-b') && item.severity === 'unknown'));
    if (includeConnected) assert(result.some(item => item.metric.includes('cloud-c') && item.value === 'connected'));
    const service = createMonitorService({ readSource: async () => ({ entry }) });
    const report = await service.run({ firewall: 'lab', checks: ['wildfire'] });
    assert.equal(report.executionStatus, 'partial');
    assert.equal(report.coverage.partial, 1);
    assert.equal(report.coverage.percent, 0);
  }
});
test('content versions are observations with freshness unknown without a verified baseline', () => {
  for (const content_versions of [{ 'content-updates': { entry: { version: '8999-9999', current: 'yes' } } }, { 'av-version': '5000-6000', 'threat-version': '8999-9999' }]) {
    const result = check('content_versions').evaluate({ content_versions });
    assert(result.some(item => item.severity === 'info' && /version/.test(item.metric)));
    assert(result.some(item => item.metric === 'content freshness' && item.severity === 'unknown'));
    assert(!result.some(item => item.severity === 'ok'));
  }
});
test('empty content lists and malformed version fields remain unknown', () => {
  for (const content_versions of [{ entry: [] }, { entry: { version: false } }, { version: '' }, { jobs: { result: 'OK' } }]) assert(check('content_versions').evaluate({ content_versions }).every(item => item.severity === 'unknown'));
});
test('recent traffic and threat evidence never proves uninterrupted logging', () => {
  const result = check('logging_health').evaluate({ traffic_logs: logs(10), threat_logs: logs(1) });
  assert.equal(result.filter(item => item.severity === 'info').length, 2);
  assert(result.some(item => item.metric === 'logging continuity' && item.severity === 'unknown'));
  assert(!result.some(item => item.severity === 'ok'));
});
test('zero logs cannot distinguish quiet traffic from a logging interruption', () => {
  const result = check('logging_health').evaluate({ traffic_logs: logs(0), threat_logs: logs(0) });
  assert(result.every(item => item.severity === 'unknown'));
  assert(result.some(item => /无法区分/.test(item.message)));
});
test('logging count limits and incomplete coverage remain explicit', () => {
  const result = check('logging_health').evaluate({ traffic_logs: logs(1000, { complete: true }), threat_logs: logs(2, { complete: false }) });
  assert.equal(result.filter(item => item.metric.endsWith('coverage') && item.severity === 'unknown').length, 2);
  assert(result.filter(item => item.severity === 'info').every(item => item.window.complete === false));
});
test('logging rejects invalid device windows and malformed counts', () => {
  for (const sample of [logs(-1), logs(true), logs(1001), logs(0, { clock: 'host' }), logs(0, { start: '2026/09/21 09:00:00' }), logs(0, { end: '2026/02/30 10:10:00' }), logs(0, { limit: 20 }), logs(0, { complete: undefined })]) {
    const result = check('logging_health').evaluate({ traffic_logs: sample, threat_logs: sample });
    assert(result.every(item => item.severity === 'unknown'));
  }
});
test('monitor shares threat collection with logging health and redacts full policy findings', async () => {
  const calls = [];
  const adapter = createPanosAdapter({ callMcpTool: async (tool, args, firewall, options) => {
    calls.push({ tool, args, firewall, signal: options.signal });
    if (tool === 'run_op_command') return { system: { time: window.end } };
    if (tool === 'get_security_rules') return { rules: { entry: rule({ '@_name': 'fixture?token=YOUR_TOKEN_HERE', source: { member: 'any' }, destination: { member: 'any' } }) } };
    return { entry: [{ receive_time: '2026/09/21 10:09:00' }] };
  } });
  const service = createMonitorService({ readSource: adapter.readMonitorSource });
  const report = await service.run({ firewall: 'lab-b', checks: ['policy_hygiene', 'threat_logs', 'logging_health'] });
  assert.equal(calls.filter(call => call.tool === 'get_threat_logs').length, 1);
  assert.equal(calls.filter(call => call.tool === 'get_traffic_logs').length, 1);
  assert(calls.every(call => call.firewall === 'lab-b' && call.signal instanceof AbortSignal));
  assert.equal(report.executionStatus, 'partial');
  assert.doesNotMatch(JSON.stringify(report), /YOUR_TOKEN_HERE/);
  assert(report.checks.find(item => item.id === 'policy_hygiene').findings.some(item => item.severity === 'warning'));
});
test('invalid threat responses remain unknown in logging health and share the cached failure', async () => {
  for (const threat of [{ entry: 'unexpected' }, { entry: [{ receive_time: '2026/09/21 09:00:00' }] }]) {
    const calls = [];
    const adapter = createPanosAdapter({ callMcpTool: async tool => {
      calls.push(tool);
      return tool === 'run_op_command' ? { time: '2026/09/21 10:00:00' } : tool === 'get_threat_logs' ? threat : { entry: [] };
    } });
    const service = createMonitorService({ readSource: adapter.readMonitorSource });
    const report = await service.run({ firewall: 'lab', minutes: 10, checks: ['threat_logs', 'logging_health'] });
    const logging = report.checks.find(item => item.id === 'logging_health');
    assert(logging.sources.some(item => item.id === 'threat_logs' && item.errorCode === 'response'));
    assert(logging.findings.some(item => item.metric === 'threat_logs events' && item.severity === 'unknown'));
    assert(!logging.findings.some(item => item.metric === 'threat_logs events' && item.severity === 'info'));
    assert.equal(report.checks.find(item => item.id === 'threat_logs').collection, 'error');
    assert.equal(calls.filter(tool => tool === 'get_threat_logs').length, 1);
    assert.equal(calls.filter(tool => tool === 'get_traffic_logs').length, 1);
    assert.equal(calls.length, 4);
  }
});
