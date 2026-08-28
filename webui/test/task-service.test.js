const test = require("node:test");
const assert = require("node:assert/strict");

const { createTaskService, normalizeChangeParams } = require("../services/task-service");
const { planFingerprint } = require("../lib/task-governance");

function memoryStore(initial = []) {
  let value = initial;
  return { load: () => value, save: (next) => { value = next; } };
}

test("approval records audit before candidate execution", async () => {
  const executed = [];
  const service = createTaskService({
    panosAdapter: { directConfigSet: async () => { executed.push("candidate"); return "<response status='success'/>"; } },
    taskStore: memoryStore(), auditStore: memoryStore(), clock: () => 1700000000000,
  });
  service.seedTask({ id: 7, type: "change", status: "awaiting_approval", template: "add_address_object", params: { name: "example", value: "198.51.100.2" }, steps: [] });
  const result = await service.actOnTask(7, "approve");
  assert.equal(result.status, "awaiting_commit");
  assert.equal(service.listTasks()[0].audit[0].action, "approve");
  assert.deepEqual(executed, ["candidate"]);
});

test("address-object candidate is finalized with an audit record", async () => {
  const writes = [];
  const service = createTaskService({
    panosAdapter: { directConfigSet: async (xpath, xml) => { writes.push({ xpath, xml }); return "ok"; } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({
    id: 11, type: "change", status: "awaiting_approval", template: "add_address_object",
    params: { name: "example", value: "198.51.100.2" }, firewall: "lab", steps: [],
  });
  await service.actOnTask(11, "approve");
  const task = service.getTask(11);
  assert.equal(task.status, "awaiting_commit");
  assert.equal(task.audit.at(-1).action, "candidate_ready");
  assert.deepEqual(writes, [{
    xpath: "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='example']",
    xml: "<ip-netmask>198.51.100.2</ip-netmask>",
  }]);
});

test("address-object deletion is finalized through the task service", async () => {
  const deletes = [];
  const service = createTaskService({
    panosAdapter: { directConfigDelete: async (xpath) => { deletes.push(xpath); return "ok"; } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({
    id: 14, type: "change", status: "awaiting_approval", template: "delete_address_object",
    params: { name: "obsolete-object" }, firewall: "lab", steps: [],
  });
  await service.actOnTask(14, "approve");
  assert.equal(service.getTask(14).status, "awaiting_commit");
  assert.deepEqual(deletes, [
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='obsolete-object']",
  ]);
});

test("address-object plan parameters use ip-netmask by default", () => {
  assert.equal(normalizeChangeParams("add_address_object", { name: "example", value: "198.51.100.2" }).type, "ip-netmask");
});

test("approval rejects a change whose plan fingerprint no longer matches", async () => {
  const service = createTaskService({
    panosAdapter: { directConfigSet: async () => { throw new Error("must not execute"); } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({
    id: 8, type: "change", status: "awaiting_approval", template: "add_address_object",
    params: { name: "example", value: "198.51.100.2", type: "ip-netmask" }, steps: [],
    firewall: "lab", planFingerprint: planFingerprint({
      template: "add_address_object", params: { name: "example", value: "203.0.113.9", type: "ip-netmask" }, firewall: "lab",
    }),
  });
  await assert.rejects(service.actOnTask(8, "approve"), /变更计划已变化/);
  assert.equal(service.listTasks()[0].status, "awaiting_approval");
});

test("cancellation is persisted and emits an audit record", async () => {
  const auditStore = memoryStore();
  const service = createTaskService({ panosAdapter: {}, taskStore: memoryStore(), auditStore });
  service.seedTask({ id: 9, type: "query", status: "running", steps: [] });
  const result = await service.actOnTask(9, "cancel");
  assert.equal(result.status, "cancelled");
  assert.equal(service.listTasks()[0].cancelled, true);
  assert.equal(auditStore.load()[0].action, "cancel");
});

test("rule selection persists the selected parameters before starting candidate execution", async () => {
  const started = [];
  const service = createTaskService({
    taskStore: memoryStore(), auditStore: memoryStore(),
    candidateRunner: async (task) => { started.push({ id: task.id, params: task.params }); },
  });
  service.seedTask({
    id: 10, type: "change", status: "awaiting_selection", template: "delete_security_rule",
    params: { keyword: "legacy" }, steps: [], _candidate: { firewall: "lab" },
  });
  const result = await service.actOnTask(10, "select", {
    params: { name: "legacy-rule", keyword: "legacy" },
    step: "用户从候选选中：legacy-rule",
  });
  assert.equal(result.status, "executing");
  assert.deepEqual(service.listTasks()[0].params, { name: "legacy-rule", keyword: "legacy" });
  assert.deepEqual(started, [{ id: 10, params: { name: "legacy-rule", keyword: "legacy" } }]);
});

test("task creation resumes IDs from persisted history and persists the new task", () => {
  const taskStore = memoryStore([{ id: 12, type: "query", status: "done", input: "旧任务", steps: [] }]);
  const service = createTaskService({ panosAdapter: {}, taskStore, auditStore: memoryStore() });
  const task = service.createTask("query", "新任务", { firewall: "lab" });
  service.addTask(task);
  assert.equal(task.id, 13);
  assert.equal(task.status, "pending");
  assert.equal(taskStore.load().at(-1), task);
});
