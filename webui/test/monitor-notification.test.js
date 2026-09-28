const test = require('node:test');
const assert = require('node:assert/strict');
const { createTaskService } = require('../services/task-service');
const { createApiRouter } = require('../routes/api-routes');
const { createStaticRouter } = require('../routes/static-routes');
const { createTaskPlanner } = require('../services/task-planner');
const { createMonitorService } = require('../services/monitor/service');
const { createApp } = require('../app');
const { createAuthService } = require('../services/auth-service');
const { once } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function report(overrides = {}) {
  return { schemaVersion: 1, firewall: 'TEST-LAB', startedAt: '2026-09-21T01:00:00Z', finishedAt: '2026-09-21T01:01:00Z', minutes: 5, executionStatus: 'partial', overallSeverity: 'warning', coverage: { total: 2, valid: 1, partial: 0, unsupported: 1, unknown: 0, error: 0, not_applicable: 0, not_run: 0, percent: 50 }, checks: [{ id: 'license', label: '许可证', severity: 'warning', findings: [{ metric: 'expiry', severity: 'warning', message: '测试许可即将过期' }] }, { id: 'routing', label: '路由', severity: 'unknown', findings: [{ severity: 'unknown', message: '设备不支持此查询' }] }], ...overrides };
}
function emptyService() { return createTaskService({ taskStore: { load: () => [], save() {} }, auditStore: { load: () => [], save() {} } }); }
function service() {
  const taskService = emptyService();
  taskService.seedTask({ id: 1, type: 'inspect', status: 'done', steps: [], result: { grade: '优秀', rate: 100, checks: [{ name: '旧检查', pass: true }] } });
  taskService.seedTask({ id: 7, type: 'monitor', status: 'done', steps: [], result: { monitor: report() } });
  taskService.seedTask({ id: 8, type: 'monitor', status: 'running', steps: [], result: { monitor: report({ executionStatus: 'running' }) } });
  return taskService;
}

test('notification and exports use the same persisted report, preserving legacy history', () => {
  const tasks = service();
  const old = JSON.stringify(tasks.getTask(1));
  assert.equal(typeof tasks.getMonitorReportNotification, 'function');
  const notice = tasks.getMonitorReportNotification({ taskId: 7 });
  const exported = JSON.parse(tasks.exportMonitorReport(7, 'json').content);
  assert.equal(notice.taskId, 7);
  for (const value of ['#7', exported.firewall, exported.finishedAt, '部分完成', '50%', '不支持 1', exported.checks[0].findings[0].message]) assert.ok(notice.text.includes(value), value);
  assert.equal(tasks.getMonitorReportNotification().taskId, 7);
  for (const id of [1, 8, 999]) assert.equal(tasks.getMonitorReportNotification({ taskId: id }), null);
  assert.equal(JSON.stringify(tasks.getTask(1)), old);
  assert.equal(tasks.runInspect, undefined);
});

test('notification chooses newest finished report, includes cancellation and signals omitted detail', () => {
  const tasks = service();
  tasks.seedTask({ id: 6, type: 'monitor', status: 'cancelled', steps: [], result: { monitor: report({ finishedAt: '2026-09-21T02:00:00Z', executionStatus: 'cancelled', checks: Array.from({ length: 40 }, (_, i) => ({ label: '测试项目' + i, findings: [{ severity: i === 39 ? 'critical' : 'info', message: i === 39 ? '末尾严重风险' : '观察信息' }] })) }) } });
  const notice = tasks.getMonitorReportNotification();
  assert.equal(notice.taskId, 6);
  assert.match(notice.text, /已取消/);
  assert.match(notice.text, /末尾严重风险/);
  assert.match(notice.text, /省略/);
  assert.ok(notice.text.length <= 4500);
});

test('Feishu POST sends the selected report and returns its ID; invalid requests do not send', async () => {
  const tasks = service(), messages = [], responses = [];
  const router = createApiRouter({ taskService: tasks, feishu: { send: async text => { messages.push(text); return { ok: true }; }, latestReport: () => { throw new Error('legacy report must not be read'); } } });
  const call = async (method, body) => router.handleOperations({ method, url: '/api/feishu/push-report' }, (code, result) => responses.push({ code, result }), async () => body);
  await call('POST', '{"taskId":7}');
  assert.equal(messages[0], tasks.getMonitorReportNotification({ taskId: 7 }).text);
  assert.deepEqual(responses.at(-1), { code: 200, result: { ok: true, taskId: 7 } });
  await call('POST', '');
  assert.equal(messages.length, 2);
  for (const body of ['{', 'null', '{"taskId":0}', '{"taskId":"7"}']) { await call('POST', body); assert.equal(responses.at(-1).code, 400); }
  await call('POST', '{"taskId":1}'); assert.equal(responses.at(-1).code, 404);
  await call('POST', '{"taskId":8}'); assert.equal(responses.at(-1).code, 404);
  assert.equal(await call('GET', ''), false);
  assert.equal(messages.length, 2);
  assert.equal(emptyService().getMonitorReportNotification(), null);
});

test('authenticated HTTP aliases, export and Feishu share the real Task Service report', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unified-monitor-http-'));
  const authService = createAuthService({ authFile: path.join(dir, 'auth.json'), environment: { PANOS_WEB_PASSWORD: 'TEST_PASSWORD_NOT_REAL' }, logger: { warn() {} } });
  const monitorService = createMonitorService({ definitions: [{ id: 'system', label: '系统', category: 'device_health', sources: ['system'], evaluate: () => [{ severity: 'ok', message: '演示设备可读取' }] }], readSource: async () => ({ hostname: 'TEST-ONLY' }) });
  const tasks = createTaskService({ taskStore: { load: () => [], save() {} }, auditStore: { load: () => [], save() {} }, monitorService });
  const planner = createTaskPlanner({ taskService: tasks, actions: { monitor: { label: '深度健康巡检' } }, llmService: { resolveAction: () => { throw new Error('fixed aliases must not invoke LLM'); } } });
  const messages = [];
  const router = createApiRouter({ taskService: tasks, authService, feishu: { send: async text => { messages.push(text); return { ok: true }; } } });
  const app = createApp({ apiRouter: router, staticRouter: createStaticRouter({ rootDirectory: path.join(__dirname, '..') }), buildSecurityHeaders: () => ({}), ensureConnected: async () => {}, touchIfUserAction() {}, createTask: (...args) => planner.createTaskFromInput(...args) });
  app.listen(0, '127.0.0.1'); await once(app, 'listening');
  t.after(async () => { await new Promise(resolve => app.close(resolve)); fs.rmSync(dir, { recursive: true, force: true }); });
  const base = 'http://127.0.0.1:' + app.address().port;
  assert.equal((await fetch(base + '/api/feishu/push-report', { method: 'POST' })).status, 401);
  const login = await (await fetch(base + '/api/auth/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: 'TEST_PASSWORD_NOT_REAL' }) })).json();
  assert.equal(login.ok, true);
  const headers = { authorization: 'Bearer ' + login.token, 'content-type': 'application/json' };
  let id;
  for (const query of ['深度健康巡检', '完整巡检', '巡检', 'inspect']) {
    const response = await fetch(base + '/api/task', { method: 'POST', headers, body: JSON.stringify({ query, firewall: 'TEST-LAB' }) });
    assert.equal(response.status, 200);
    const created = await response.json();
    assert.equal(created.type, 'monitor'); id = created.taskId;
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(tasks.getTask(id).status, 'done');
  }
  const exported = await (await fetch(base + '/api/task/' + id + '/monitor/export?format=json', { headers })).json();
  const data = JSON.parse(exported.content);
  const notificationUrl = base + '/api/task/' + id + '/monitor/notification';
  assert.equal((await fetch(notificationUrl)).status, 401);
  const notificationResponse = await fetch(notificationUrl, { headers });
  assert.equal(notificationResponse.status, 200);
  const notification = await notificationResponse.json();
  assert.equal(notification.taskId, id);
  assert.equal(messages.length, 0);
  const pushed = await (await fetch(base + '/api/feishu/push-report', { method: 'POST', headers, body: JSON.stringify({ taskId: id }) })).json();
  assert.deepEqual(pushed, { ok: true, taskId: id });
  assert.equal(messages.length, 1);
  assert.equal(messages[0], tasks.getMonitorReportNotification({ taskId: id }).text);
  assert.equal(messages[0], notification.text);
  assert.ok(messages[0].includes(data.firewall));
  assert.ok(messages[0].includes(data.checks[0].findings[0].message));
});
