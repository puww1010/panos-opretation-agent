const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { renderMonitorReport } = require('../assets/monitor-ui');
const html = fs.readFileSync(path.join(__dirname, '../index.html'), 'utf8');

test('sidebar, overview and quick task list expose only the unified inspection entry', () => {
  assert.ok(html.includes("openAssistant('深度健康巡检')"));
  assert.ok(html.includes("quickTask('深度健康巡检')"));
  assert.ok(!/(?:openAssistant|quickTask)\('完整巡检'\)/.test(html));
  const quick = html.slice(html.indexOf('function renderQuickButtons()'), html.indexOf('function toggleTrouble()'));
  const buttons = [], submitted = [], input = {};
  const document = { getElementById: id => id === 'q' ? input : { innerHTML: '', appendChild: b => buttons.push(b) }, createElement: () => ({}) };
  vm.runInNewContext(quick + ';renderQuickButtons()', { document, BTN_LABELS: { monitor: '深度健康巡检', inspect: '完整巡检', device: '设备状态' }, submit: () => submitted.push(input.value), toggleTrouble() {}, ic: () => '' });
  assert.equal(buttons.filter(b => b.textContent === '深度健康巡检').length, 1);
  assert.equal(buttons.filter(b => b.textContent === '完整巡检').length, 0);
  buttons.find(b => b.textContent === '深度健康巡检').onclick();
  assert.deepEqual(submitted, ['深度健康巡检']);
});

test('legacy report renderer remains visible and explicitly historical', () => {
  assert.ok(html.includes('t.type === "inspect" && t.result'));
  assert.ok(html.includes('历史完整巡检报告'));
  assert.ok(html.includes('t.result.grade'));
  assert.ok(html.includes('t.result.checks'));
});

test('report push button binds exact task ID and disappears from offline reports', () => {
  const report = { checks: [], coverage: {}, executionStatus: 'completed' };
  assert.match(renderMonitorReport(19, report), /pushMonitorReport\(19\)/);
  assert.doesNotMatch(renderMonitorReport(19, report, { controls: false }), /pushMonitorReport|onclick=/);
  const code = html.slice(html.indexOf('async function pushMonitorReport'), html.indexOf('async function downloadMonitorReport'));
  assert.match(code, /fjs\("\/api\/feishu\/push-report"/);
  assert.match(code, /JSON\.stringify\(\{ taskId: id \}\)/);
  const latest = html.slice(html.indexOf('async function feishuPushReport()'));
  assert.match(latest, /fjs\("\/api\/feishu\/push-report"/);
});
