const test = require("node:test");
const assert = require("node:assert/strict");
const { createTaskService } = require("../services/task-service");
const { createTaskPlanner } = require("../services/task-planner");
const { createMonitorService } = require("../services/monitor/service");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const definition = { id: "system", category: "device_health", label: "设备信息", sources: ["system"], evaluate: () => [{ metric: "设备", severity: "ok", message: "可读取", value: "fixture" }] };
function memoryStore() { const value = []; return { load: () => value, save: () => {} }; }
function makeService(readSource) {
  return createTaskService({ taskStore: memoryStore(), auditStore: memoryStore(), monitorService: createMonitorService({ definitions: [definition], readSource }) });
}

test("all fixed inspection aliases create monitor tasks without calling an LLM", async () => {
  const tasks = [];
  const service = { listTasks: () => [], dispatchTask(type, input, extra) { const task = { id: tasks.length + 1, type, input, status: "pending", steps: [], ...extra }; tasks.push(task); return task; } };
  const planner = createTaskPlanner({ actions: { inspect: { label: "完整巡检" } }, taskService: service, llmService: { resolveAction: () => { throw new Error("LLM must not be called"); } } });
  const result = await planner.createTaskFromInput("深度健康巡检", "lab", "web");
  assert.equal(result.type, "monitor");
  assert.equal(tasks[0].monitor.minutes, 10);
  for (const input of ["完整巡检", "巡检", "inspect", "请执行完整巡检 基础 最近5分钟"]) {
    const result = await planner.createTaskFromInput(input, "lab", "web");
    assert.equal(result.type, "monitor");
  }
  assert.ok(tasks.every(task => task.type === "monitor"));
  assert.equal(tasks.at(-1).monitor.minutes, 5);
  assert.equal(tasks.at(-1).monitor.checks.length, 8);
});

test("LLM classification cannot widen an unparsed monitor scope or discard its time window", async () => {
  const tasks = [];
  const planner = createTaskPlanner({
    actions: { monitor: { label: "深度健康巡检" } },
    taskService: { listTasks: () => [], dispatchTask(type, input, extra) { const task = { id: 1, type, input, status: "pending", ...extra }; tasks.push(task); return task; } },
    llmService: { resolveAction: async () => ({ action: "monitor", minutes: 5 }) },
  });
  await assert.rejects(() => planner.createTaskFromInput("帮我做深度巡检，只查威胁日志最近5分钟", "lab", "web"), { code: "MONITOR_INPUT" });
  assert.equal(tasks.length, 0);
});

test("monitor Task Service persists real progress and separates partial completion", async () => {
  const service = makeService(async () => { throw new Error("connection refused"); });
  assert.equal(typeof service.runMonitor, "function");
  const task = service.createTask("monitor", "深度巡检", { firewall: "lab", monitor: { minutes: 10 } }); service.addTask(task);
  await service.runMonitor(task);
  assert.equal(task.status, "failed");
  assert.equal(task.result.monitor.executionStatus, "failed");
  assert.equal(task.steps[0].status, "err");
  assert.ok(task.audit.some((event) => event.action === "monitor_started"));
  assert.ok(task.audit.some((event) => event.action === "monitor_finished"));
});

test("cancellation aborts monitoring and rejects a second scan of the same device", async () => {
  let started;
  const startedPromise = new Promise((resolve) => { started = resolve; });
  const service = makeService(async () => { started(); return new Promise(() => {}); });
  assert.equal(typeof service.runMonitor, "function");
  const task = service.createTask("monitor", "深度巡检", { firewall: "lab" }); service.addTask(task);
  const execution = service.runMonitor(task); await startedPromise;
  const other = service.createTask("monitor", "另一巡检", { firewall: "lab" });
  await assert.rejects(() => service.runMonitor(other), /已有.*巡检/);
  await service.actOnTask(task.id, "cancel");
  await execution;
  assert.equal(task.status, "cancelled");
  assert.equal(task.result.monitor.executionStatus, "cancelled");
});

test("monitor reports and audit survive persistence while interrupted scans recover as failed", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "monitor-store-test-"));
  try {
    const taskFile = path.join(dir, "tasks.json"), auditFile = path.join(dir, "audit.json");
    fs.writeFileSync(taskFile, "[]"); fs.writeFileSync(auditFile, "[]");
    const logger = { log() {}, warn() {}, error() {} };
    const service = createTaskService({ taskFile, auditFile, logger, monitorService: createMonitorService({ definitions: [definition], readSource: async () => ({}) }) });
    assert.equal(typeof service.runMonitor, "function");
    const task = service.createTask("monitor", "深度巡检", { firewall: "lab" }); service.addTask(task); await service.runMonitor(task);
    const interrupted = service.createTask("monitor", "中断", { status: "running" }); service.addTask(interrupted); await service.flushPersistence();
    const restored = createTaskService({ taskFile, auditFile, logger });
    const loaded = restored.listTasks();
    assert.equal(loaded[0].result.monitor.skillId, "panos-monitor");
    assert.equal(loaded[1].status, "failed");
    assert.ok(restored.listAuditEvents().some((event) => event.action === "monitor_finished"));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test("legacy fuzzy dedupe cannot silently cancel a live monitor", async () => {
  const monitor = { id: 1, type: 'monitor', input: '深度健康巡检', status: 'running', steps: [] };
  const planner = createTaskPlanner({ actions: { inspect: { label: '深度健康巡' } }, taskService: { listTasks: () => [monitor], saveTask() {}, dispatchTask: () => ({ id: 2, status: 'pending' }) } });
  await assert.rejects(() => planner.createTaskFromInput('深度健康巡', 'lab', 'web'), { code: 'MONITOR_INPUT' });
  assert.equal(monitor.status, 'running');
});

test("cancelled monitor report and audit remain cancelled after store recovery", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "monitor-cancel-recovery-"));
  try {
    const options = { taskFile: path.join(dir, "tasks.json"), auditFile: path.join(dir, "audit.json"), logger: { log() {}, warn() {}, error() {} } };
    let started;
    const ready = new Promise(resolve => { started = resolve; });
    const service = createTaskService({ ...options, monitorService: createMonitorService({ definitions: [definition], readSource: async () => { started(); return new Promise(() => {}); } }) });
    const task = service.createTask("monitor", "完整巡检", { firewall: "lab" }); service.addTask(task);
    const execution = service.runMonitor(task); await ready;
    await service.actOnTask(task.id, "cancel"); await execution; await service.flushPersistence();
    const report = service.exportMonitorReport(task.id, "json");
    const restored = createTaskService(options);
    assert.equal(restored.getTask(task.id).status, "cancelled");
    assert.equal(restored.getTask(task.id).result.monitor.executionStatus, "cancelled");
    assert.deepEqual(restored.exportMonitorReport(task.id, "json"), report);
    assert.ok(restored.getMonitorReportNotification({ taskId: task.id }).text.includes("已取消"));
    assert.ok(restored.listAuditEvents().some(event => event.action === "monitor_finished" && event.to === "cancelled"));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
