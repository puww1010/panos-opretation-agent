const test = require('node:test');
const assert = require('node:assert/strict');
let basicChecks = [];
let helpers = {};
try { ({ basicChecks } = require('../services/monitor/basic-checks')); helpers = require('../services/monitor/helpers'); }
catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
const now = new Date('2026-09-21T00:00:00Z');
function evaluate(id, data) {
  const check = basicChecks.find(item => item.id === id);
  assert.ok(check, `${id} check exists`);
  return check.evaluate(data, { now, minutes: 60 });
}
const fixtures = {
  system: [{ system: { 'operational-mode': 'normal', uptime: '12 days, 01:00:00' } }, { system: { 'operational-mode': 'maintenance', uptime: '0 days, 01:00:00' } }],
  environmentals: [{ environmentals: { fans: { entry: { '@_name': 'Fan1', status: 'ok' } } } }, { environmentals: { 'power-supply': { entry: { '@_name': 'PS1', status: 'failed' } } } }],
  resources: [{ resources: { second: { 'cpu-load-average': '15' }, memory: { percent: '35' } }, management_resources: '%Cpu(s): 2.0 us, 3.0 sy, 95.0 id\nMiB Mem : 1000 total, 600 free, 400 used' }, { resources: { second: { 'cpu-load-average': '96' }, memory: { percent: '92' } }, management_resources: '%Cpu(s): 97.0 us, 1.0 sy, 2.0 id' }],
  sessions: [{ sessions: { 'num-active': '0', 'num-max': '1000' } }, { sessions: { 'num-active': '980', 'num-max': '1000' } }],
  interfaces: [{ interfaces: { hw: { entry: { '@_name': 'ethernet1/1', state: 'up' } } } }, { interfaces: { hw: { entry: { '@_name': 'ethernet1/1', state: 'down', 'admin-state': 'up' } } } }],
  ha: [{ ha: { enabled: 'yes', group: { 'local-info': { state: 'active' }, 'peer-info': { state: 'passive' } } } }, { ha: { enabled: 'yes', group: { 'local-info': { state: 'active' }, 'peer-info': { state: 'down' } } } }],
  license: [{ license: { licenses: { entry: { feature: 'Threat', expires: '2027/09/21' } } } }, { license: { licenses: { entry: { feature: 'Threat', expires: '2026/09/01' } } } }],
  certificates: [{ certificates: { entry: { '@_name': 'device', 'not-valid-after': '2027-09-21T00:00:00Z' } } }, { certificates: { entry: { '@_name': 'device', 'not-valid-after': '2026-09-25T00:00:00Z' } } }]
};
for (const [id, [healthy, risk]] of Object.entries(fixtures)) {
  test(`${id}: positive evidence`, () => {
    const findings = evaluate(id, healthy);
    assert.ok(findings.some(f => f.severity === 'ok'));
    assert.ok(!findings.some(f => ['warning', 'critical'].includes(f.severity)));
    for (const f of findings) for (const key of ['metric', 'value', 'unit', 'severity', 'message', 'recommendation']) assert.ok(Object.hasOwn(f, key));
  });
  test(`${id}: risk evidence`, () => assert.ok(evaluate(id, risk).some(f => ['warning', 'critical'].includes(f.severity))));
  test(`${id}: missing or unrecognized evidence is unknown`, () => {
    for (const data of [{}, { [id]: { nonsense: 'healthy' } }]) {
      const findings = evaluate(id, data);
      assert.ok(findings.length);
      assert.ok(findings.every(f => f.severity === 'unknown'));
    }
  });
}
test('strict numbers reject empty, unknown, partial and nonfinite values', () => {
  assert.equal(typeof helpers.toNumber, 'function');
  for (const input of [null, undefined, '', ' ', '?', '42foo', Infinity, true, [], {}]) assert.equal(helpers.toNumber(input), null);
  assert.equal(helpers.toNumber('0'), 0);
  assert.equal(helpers.toNumber('1.25'), 1.25);
});
test('CPU load averages do not become MP percentages', () => {
  const findings = evaluate('resources', { management_resources: 'load average: 99.5, 98.1, 96.0' });
  assert.ok(findings.every(f => f.severity === 'unknown'));
});
test('resources distinguish CPU planes and window', () => {
  const findings = evaluate('resources', fixtures.resources[0]);
  assert.ok(findings.some(f => f.plane === 'DP' && f.window === 'second' && f.value === 15));
  assert.ok(findings.some(f => f.plane === 'MP' && f.metric.includes('cpu') && f.value === 5));
});
test('HA explicitly disabled is not applicable', () => {
  const findings = evaluate('ha', { ha: { enabled: 'no' } });
  assert.equal(findings[0].severity, 'info');
  assert.equal(findings[0].applicability, 'not_applicable');
});
test('unused down port without admin evidence is informational', () => {
  assert.equal(evaluate('interfaces', { interfaces: { entry: { '@_name': 'ethernet1/4', state: 'down' } } })[0].severity, 'info');
});
test('invalid dates and absent expiry remain unknown', () => {
  for (const id of ['license', 'certificates']) {
    for (const entry of [{ '@_name': 'test' }, { '@_name': 'test', expires: 'garbage', 'not-valid-after': '?' }]) {
      assert.ok(evaluate(id, { [id]: { entry } }).every(f => f.severity === 'unknown'));
    }
  }
});
test('zero session capacity cannot be healthy', () => assert.ok(evaluate('sessions', { sessions: { 'num-active': 1, 'num-max': 0 } }).some(f => f.severity === 'unknown')));
test('unrecognized sensor status and missing HA peer stay unknown', () => {
  assert.equal(evaluate('environmentals', { environmentals: { fans: { entry: { status: '?' } } } })[0].severity, 'unknown');
  assert.ok(evaluate('ha', { ha: { enabled: 'yes', local: { state: 'active' } } }).some(f => f.severity === 'unknown'));
});
test('finite bounded tree helpers support attributes and singleton entries', () => {
  assert.equal(typeof helpers.field, 'function');
  assert.equal(helpers.field({ a: { b: 0 } }, ['b']), 0);
  assert.deepEqual(helpers.entries({ box: { entry: { '@_name': 'one' } } }), [{ '@_name': 'one' }]);
  const cyclic = {}; cyclic.self = cyclic;
  assert.equal(helpers.field(cyclic, ['missing']), undefined);
});
test('named interface missing state stays visible beside healthy interface', () => {
  const findings = evaluate('interfaces', { interfaces: { hw: { entry: [
    { '@_name': 'ethernet1/1', state: 'up' }, { '@_name': 'ethernet1/2' }
  ] } } });
  assert.ok(findings.some(f => f.metric.includes('ethernet1/2') && f.severity === 'unknown'));
});
test('MP memory mixed unit totals cannot produce healthy utilization', () => {
  for (const memory of ['Mem: 1000m total, 1g used', 'Mem: 1000 total, 1g used']) {
    const findings = evaluate('resources', { management_resources: memory });
    assert.equal(findings.find(f => f.plane === 'MP' && f.metric === 'memory').severity, 'unknown');
  }
  const sameUnits = evaluate('resources', { management_resources: 'Mem: 1000m total, 950m used' });
  assert.equal(sameUnits.find(f => f.plane === 'MP' && f.metric === 'memory').severity, 'critical');
});
test('expiry calendar validation rejects rollover dates', () => {
  for (const id of ['license', 'certificates']) {
    for (const expiry of ['2027-02-30', '2027/02/29', '2027-04-31', 'Feb 30 2027']) {
      const findings = evaluate(id, { [id]: { entry: { '@_name': 'test', expires: expiry, 'not-valid-after': expiry } } });
      assert.equal(findings[0].severity, 'unknown', expiry);
    }
    const findings = evaluate(id, { [id]: { entry: { '@_name': 'test', expires: '2028-02-29', 'not-valid-after': '2028-02-29' } } });
    assert.equal(findings[0].severity, 'ok');
  }
});
test('real interface hw and ifnet views are not counted twice', () => {
  const findings = evaluate('interfaces', { interfaces: { hw: { entry: { name: 'ethernet1/3', state: 'up' } }, ifnet: { entry: { name: 'ethernet1/3', ip: '192.0.2.1/24' } } } });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'ok');
});
test('DP core histories use mean percentages with an explicit window', () => {
  const findings = evaluate('resources', { resources: { 'data-processors': { dp0: { second: { 'cpu-load-average': { entry: [{ coreid: 0, value: '10,20' }, { coreid: 1, value: '30,40' }] } } } } } });
  assert.ok(findings.some(f => f.plane === 'DP' && f.window === 'second' && f.value === 25));
  assert.ok(findings.some(f => f.plane === 'DP' && f.metric === 'memory' && f.severity === 'unknown'));
});
test('MP CPU uses us+sy+ni, not load average or IO wait', () => {
  const findings = evaluate('resources', { management_resources: '%Cpu(s): 2.0 us, 3.0 sy, 1.0 ni, 64.0 id, 30.0 wa' });
  assert.equal(findings.find(f => f.plane === 'MP' && f.metric === 'cpu').value, 6);
});
