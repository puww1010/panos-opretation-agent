const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { renderMonitorReport } = require('../assets/monitor-ui');
const html = fs.readFileSync(path.join(__dirname, '../index.html'), 'utf8');

test('sidebar, overview and quick task list expose only the unified inspection entry', () => {
  assert.ok(!html.includes("openAssistant('深度健康巡检')"));
  assert.equal(html.match(/onclick="quickTask\('深度健康巡检'\)"/g).length, 2);
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

function taskEntryHarness(fetch) {
  const elements = { q: { value: '', focus() {} }, submitBtn: { disabled: false }, liveTxt: { textContent: '' } };
  const views = [], refreshes = [];
  const context = vm.createContext({
    document: { getElementById: id => elements[id] }, fetch,
    showView: view => views.push(view), autoGrow() {}, requestAnimationFrame: callback => callback(),
    currentFirewall: () => 'TEST_FIREWALL', pulseLiveBadge() {},
    clearReplyChip() {}, pollTasks: () => refreshes.push(true),
  });
  const functions = [
    html.slice(html.indexOf('function quickTask('), html.indexOf('function openOpsOverview(')),
    html.slice(html.indexOf('function openAssistant('), html.indexOf('function updateSideBadge(')),
    html.slice(html.indexOf('async function submit()'), html.indexOf('async function selectLLM()')),
  ];
  vm.runInContext('let _replyToTaskId = null;\n' + functions.join('\n'), context);
  return { context, elements, views, refreshes };
}

test('sidebar inspection click creates a task without another Send click', async () => {
  const requests = [];
  const h = taskEntryHarness(async (url, options) => {
    requests.push({ url, body: JSON.parse(options.body) });
    return { json: async () => ({ id: 1 }) };
  });
  const onclick = html.match(/<button class="side-item" onclick="([^"]+)">[^\n]*<span class="txt">深度健康巡检/)?.[1];
  assert.ok(onclick, 'sidebar inspection button must exist');
  vm.runInContext(onclick, h.context);
  await new Promise(setImmediate);
  assert.deepEqual(requests, [{ url: '/api/task', body: { query: '深度健康巡检', firewall: 'TEST_FIREWALL' } }]);
  assert.deepEqual(h.views, ['chat']);
  assert.equal(h.elements.q.value, '');
  assert.equal(h.elements.submitBtn.disabled, false);
  assert.equal(h.refreshes.length, 1);
});

test('rapid inspection clicks share the existing in-flight submission guard', async () => {
  const requests = [];
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const h = taskEntryHarness((url, options) => { requests.push(JSON.parse(options.body)); return pending; });
  vm.runInContext("quickTask('深度健康巡检'); quickTask('深度健康巡检'); submit();", h.context);
  assert.equal(requests.length, 1);
  assert.equal(h.elements.submitBtn.disabled, true);
  release({ json: async () => ({ id: 1 }) });
  await new Promise(setImmediate);
  assert.equal(h.elements.submitBtn.disabled, false);
  assert.equal(h.refreshes.length, 1);
});

test('inspection creation errors retain the request and restore the send button', async () => {
  const h = taskEntryHarness(async () => ({ json: async () => ({ error: 'TEST_MONITOR_BUSY' }) }));
  vm.runInContext("quickTask('深度健康巡检');", h.context);
  await new Promise(setImmediate);
  assert.equal(h.elements.q.value, '深度健康巡检');
  assert.equal(h.elements.submitBtn.disabled, false);
  assert.match(h.elements.liveTxt.textContent, /TEST_MONITOR_BUSY/);
  assert.equal(h.refreshes.length, 0);
});

test('other assistant entry points still only fill and focus the composer', () => {
  let requests = 0;
  const h = taskEntryHarness(() => { requests++; });
  vm.runInContext("openAssistant('设备状态');", h.context);
  assert.equal(h.elements.q.value, '设备状态');
  assert.equal(requests, 0);
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
