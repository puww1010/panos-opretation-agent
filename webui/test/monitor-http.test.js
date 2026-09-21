const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { createApp } = require('../app');
const { createApiRouter } = require('../routes/api-routes');
const { createStaticRouter } = require('../routes/static-routes');
const { createAuthService } = require('../services/auth-service');
const { createMonitorService } = require('../services/monitor/service');
const { parseMonitorRequest } = require('../services/monitor/request');

test('monitor HTTP catalog and exports require authentication; invalid scope is 400', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'monitor-http-'));
  const auth = createAuthService({ authFile: path.join(dir, 'auth.json'), environment: { PANOS_WEB_PASSWORD: 'TEST_PASSWORD_NOT_REAL' }, logger: { warn() {} } });
  const taskService = { listMonitorChecks: createMonitorService().listChecks, exportMonitorReport: id => id === 1 ? { filename: 'fixture.json', content: '{}' } : null };
  const app = createApp({ apiRouter: createApiRouter({ authService: auth, taskService }), staticRouter: createStaticRouter({ rootDirectory: path.join(__dirname, '..') }), buildSecurityHeaders: () => ({}), ensureConnected: async () => {}, touchIfUserAction() {}, createTask: async input => parseMonitorRequest(input) });
  app.listen(0, '127.0.0.1'); await once(app, 'listening');
  t.after(async () => { await new Promise(resolve => app.close(resolve)); fs.rmSync(dir, { recursive: true, force: true }); });
  const base = 'http://127.0.0.1:' + app.address().port;
  for (const endpoint of ['/api/monitor/checks', '/api/task/1/monitor/export', '/api/task']) assert.equal((await fetch(base + endpoint)).status, 401);
  const login = await (await fetch(base + '/api/auth/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'TEST_PASSWORD_NOT_REAL' }) })).json();
  assert.equal(login.ok, true);
  const headers = { authorization: 'Bearer ' + login.token };
  const catalog = await (await fetch(base + '/api/monitor/checks', { headers })).json();
  assert.equal(catalog.checks.length, 29);
  assert.equal(new Set(catalog.checks.map(c => c.id)).size, 29);
  assert.equal(new Set(catalog.checks.map(c => c.category)).size, 8);
  assert.equal((await fetch(base + '/api/task/1/monitor/export', { headers })).status, 200);
  assert.equal((await fetch(base + '/api/task/2/monitor/export', { headers })).status, 404);
  assert.equal((await fetch(base + '/api/task/1/monitor/export?format=js', { headers })).status, 400);
  assert.equal((await fetch(base + '/api/task', { method: 'POST', headers, body: JSON.stringify({ query: '深度健康巡检 不存在项' }) })).status, 400);
  assert.equal((await fetch(base + '/api/auth/check', { headers }).then(r => r.json())).idleMinutes, auth.idleMinutes);
  await fetch(base + '/api/auth/logout', { method: 'POST', headers });
  assert.equal((await fetch(base + '/api/monitor/checks', { headers })).status, 401);
});

test('monitor request selection is bounded and leaves legacy inspection alone', () => {
  assert.equal(parseMonitorRequest('完整巡检'), null);
  assert.equal(parseMonitorRequest('深度健康巡检 基础').checks.length, 8);
  assert.deepEqual(parseMonitorRequest('深度巡检 证书、许可证'), { minutes: 10, checks: ['certificates', 'license'] });
  assert.equal(parseMonitorRequest('深度巡检 设备健康').category, 'device_health');
  assert.equal(parseMonitorRequest('深度巡检 威胁日志 最近5分钟').minutes, 5);
  assert.throws(() => parseMonitorRequest('深度巡检 最近999分钟'), { code: 'MONITOR_INPUT' });
});
