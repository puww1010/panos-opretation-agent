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

test("security-rule move is executed and finalized through the task service", async () => {
  const moves = [];
  const service = createTaskService({
    panosAdapter: { directConfigMove: async (...args) => { moves.push(args); return "ok"; } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({
    id: 15, type: "change", status: "awaiting_approval", template: "move_security_rule",
    params: { name: "allow-web", where: "before", destination: "deny-all" }, firewall: "lab", steps: [],
  });
  await service.actOnTask(15, "approve");
  assert.equal(service.getTask(15).status, "awaiting_commit");
  assert.deepEqual(moves, [[
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='allow-web']",
    "before",
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='deny-all']",
  ]]);
});

test("security-rule disable and enable are finalized through the task service", async () => {
  const writes = [];
  const service = createTaskService({
    panosAdapter: { directConfigSet: async (...args) => { writes.push(args); return "ok"; } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({ id: 21, type: "change", status: "awaiting_approval", template: "set_security_rule_disabled", params: { name: "allow-web" }, steps: [] });
  service.seedTask({ id: 22, type: "change", status: "awaiting_approval", template: "set_security_rule_enabled", params: { name: "allow-admin" }, steps: [] });
  await service.actOnTask(21, "approve");
  await service.actOnTask(22, "approve");
  assert.equal(service.getTask(21).status, "awaiting_commit");
  assert.equal(service.getTask(22).status, "awaiting_commit");
  assert.deepEqual(writes, [
    ["/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='allow-web']/disabled", "<disabled>yes</disabled>"],
    ["/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='allow-admin']/disabled", "<disabled>no</disabled>"],
  ]);
});

test("security-rule deletion is finalized through the task service", async () => {
  const deletes = [];
  const service = createTaskService({
    panosAdapter: { directConfigDelete: async (xpath) => { deletes.push(xpath); return "ok"; } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({ id: 23, type: "change", status: "awaiting_approval", template: "delete_security_rule", params: { name: "obsolete-rule" }, steps: [] });
  await service.actOnTask(23, "approve");
  assert.equal(service.getTask(23).status, "awaiting_commit");
  assert.deepEqual(deletes, [
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='obsolete-rule']",
  ]);
});

test("fuzzy security-rule deletion waits for a running-config selection", async () => {
  const reads = [];
  const service = createTaskService({
    panosAdapter: {
      directConfigShow: async (xpath) => {
        reads.push(xpath);
        return '<entry name="legacy-web"><description>old</description></entry><entry name="legacy-admin"><description>old</description></entry><entry name="current-web"><description>new</description></entry>';
      },
    },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({
    id: 24, type: "change", status: "awaiting_approval", template: "delete_security_rule",
    params: { keyword: "legacy" }, firewall: "lab", steps: [],
  });
  await service.actOnTask(24, "approve");
  const task = service.getTask(24);
  assert.equal(task.status, "awaiting_selection");
  assert.deepEqual(task.result, {
    awaitingSelection: true, verb: "删除", keyword: "legacy",
    matched: ["legacy-web", "legacy-admin"], totalMatches: 2, mode: "整串匹配",
  });
  assert.deepEqual(reads, [
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules",
  ]);
});

test("single IP block candidate creates an address object and deny rule", async () => {
  const writes = [];
  const service = createTaskService({
    panosAdapter: { directConfigSet: async (...args) => { writes.push(args); return "ok"; } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({
    id: 25, type: "change", status: "awaiting_approval", template: "block_ip",
    params: { ip: "198.51.100.8" }, steps: [],
  });
  await service.actOnTask(25, "approve");
  const task = service.getTask(25);
  assert.equal(task.status, "awaiting_commit");
  assert.equal(writes.length, 2);
  assert.match(writes[0][0], /address\/entry\[@name='block-198\.51\.100\.8-/);
  assert.equal(writes[0][1], "<ip-netmask>198.51.100.8/32</ip-netmask>");
  assert.match(writes[1][0], /rulebase\/security\/rules\/entry\[@name='block-198\.51\.100\.8-/);
  assert.match(writes[1][1], /<action>deny<\/action>/);
});

test("single IP allow candidate creates an address object and allow rule", async () => {
  const writes = [];
  const service = createTaskService({
    panosAdapter: { directConfigSet: async (...args) => { writes.push(args); return "ok"; } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({
    id: 26, type: "change", status: "awaiting_approval", template: "allow_ip",
    params: { ip: "198.51.100.9" }, steps: [],
  });
  await service.actOnTask(26, "approve");
  const task = service.getTask(26);
  assert.equal(task.status, "awaiting_commit");
  assert.equal(writes.length, 2);
  assert.match(writes[0][0], /address\/entry\[@name='allow-198\.51\.100\.9-/);
  assert.equal(writes[0][1], "<ip-netmask>198.51.100.9/32</ip-netmask>");
  assert.match(writes[1][0], /rulebase\/security\/rules\/entry\[@name='allow-198\.51\.100\.9-/);
  assert.match(writes[1][1], /<action>allow<\/action>/);
});

test("IP group block candidate creates members, group, and deny rule", async () => {
  const writes = [];
  const service = createTaskService({
    panosAdapter: { directConfigSet: async (...args) => { writes.push(args); return "ok"; } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({
    id: 27, type: "change", status: "awaiting_approval", template: "block_ip_group",
    params: { ips: ["198.51.100.10", "198.51.100.11"], group_name: "blocked-test-group" }, steps: [],
  });
  await service.actOnTask(27, "approve");
  const task = service.getTask(27);
  assert.equal(task.status, "awaiting_commit");
  assert.equal(task.params._groupName, "blocked-test-group");
  assert.equal(task.params._memberCount, 2);
  assert.equal(writes.length, 4);
  assert.match(writes[0][0], /address\/entry\[@name='block-198\.51\.100\.10-/);
  assert.match(writes[1][0], /address\/entry\[@name='block-198\.51\.100\.11-/);
  assert.equal(writes[2][0], "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='blocked-test-group']");
  assert.match(writes[2][1], /<member>block-198\.51\.100\.10-/);
  assert.match(writes[3][0], /rulebase\/security\/rules\/entry\[@name='blocked-test-group'\]/);
  assert.match(writes[3][1], /<source><member>blocked-test-group<\/member><\/source>/);
  assert.match(writes[3][1], /<action>deny<\/action>/);
});

test("batch rule selection creates child tasks and performs one merged commit", async () => {
  let commits = 0;
  const service = createTaskService({
    panosAdapter: {
      directCommit: async () => { commits += 1; return "<job>46</job>"; },
      directOp: async () => "<status>FIN</status>",
      directConfigDelete: async () => "ok",
    },
    taskStore: memoryStore(), auditStore: memoryStore(), sleep: async () => {},
  });
  service.seedTask({
    id: 24, type: "change", status: "awaiting_selection", template: "delete_security_rule",
    firewall: "lab", steps: [], _candidate: { template: "delete_security_rule", firewall: "lab" },
  });
  const result = await service.startBatchSelection(24, ["legacy-a", "legacy-b"]);
  assert.equal(result.status, "done");
  assert.equal(commits, 1);
  const tasks = service.listTasks();
  assert.equal(tasks.length, 3);
  assert.equal(tasks[0].result.batch, true);
  assert.deepEqual(tasks.slice(1).map((task) => task.status), ["done", "done"]);
  assert.deepEqual(tasks.slice(1).map((task) => task.result.mergedCommit), [true, true]);
});

test("commit without a job is recorded as requiring manual follow-up", async () => {
  const service = createTaskService({
    panosAdapter: { directCommit: async () => "<response status='success'/>" },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({ id: 16, type: "change", status: "awaiting_commit", templateLabel: "创建地址对象", steps: [] });
  await service.actOnTask(16, "confirm");
  const task = service.getTask(16);
  assert.equal(task.status, "done");
  assert.equal(task.result.needsManualCommit, true);
  assert.equal(task.audit.at(-1).action, "commit_needs_follow_up");
});

test("commit job completion is finalized through the task service", async () => {
  const operations = [];
  const service = createTaskService({
    panosAdapter: {
      directCommit: async () => "<job>42</job>",
      directOp: async (command) => { operations.push(command); return "<status>FIN</status><progress>100</progress>"; },
    },
    taskStore: memoryStore(), auditStore: memoryStore(), sleep: async () => {},
  });
  service.seedTask({ id: 17, type: "change", status: "awaiting_commit", templateLabel: "创建地址对象", steps: [] });
  await service.actOnTask(17, "confirm");
  const task = service.getTask(17);
  assert.equal(task.status, "done");
  assert.equal(task.result.job, "42");
  assert.equal(task.audit.at(-1).action, "commit_completed");
  assert.deepEqual(operations, ["<show><jobs><id>42</id></jobs></show>"]);
});

test("commit job failure is finalized through the task service", async () => {
  const service = createTaskService({
    panosAdapter: {
      directCommit: async () => "<job>43</job>",
      directOp: async () => "<status>FAIL</status>",
    },
    taskStore: memoryStore(), auditStore: memoryStore(), sleep: async () => {},
  });
  service.seedTask({ id: 18, type: "change", status: "awaiting_commit", steps: [] });
  await service.actOnTask(18, "confirm");
  const task = service.getTask(18);
  assert.equal(task.status, "done");
  assert.equal(task.result.commitFailed, true);
  assert.equal(task.audit.at(-1).action, "commit_failed");
});

test("commit cancellation stops polling and records the job", async () => {
  let service;
  service = createTaskService({
    panosAdapter: {
      directCommit: async () => "<job>44</job>",
      directOp: async () => "<status>ACT</status><progress>1</progress>",
    },
    taskStore: memoryStore(), auditStore: memoryStore(),
    sleep: async () => { service.getTask(19).cancelled = true; },
  });
  service.seedTask({ id: 19, type: "change", status: "awaiting_commit", steps: [] });
  await service.actOnTask(19, "confirm");
  const task = service.getTask(19);
  assert.equal(task.status, "cancelled");
  assert.equal(task.result.job, "44");
  assert.equal(task.audit.at(-1).action, "commit_polling_cancelled");
});

test("commit polling timeout requires manual follow-up", async () => {
  const service = createTaskService({
    panosAdapter: {
      directCommit: async () => "<job>45</job>",
      directOp: async () => "<status>ACT</status><progress>1</progress>",
    },
    taskStore: memoryStore(), auditStore: memoryStore(), sleep: async () => {}, maxCommitPolls: 1,
  });
  service.seedTask({ id: 20, type: "change", status: "awaiting_commit", steps: [] });
  await service.actOnTask(20, "confirm");
  const task = service.getTask(20);
  assert.equal(task.status, "done");
  assert.equal(task.result.needsManualCommit, true);
  assert.equal(task.result.timeout, true);
  assert.equal(task.audit.at(-1).action, "commit_timed_out");
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
  const deletes = [];
  const service = createTaskService({
    panosAdapter: { directConfigDelete: async (xpath) => { deletes.push(xpath); return "ok"; } },
    taskStore: memoryStore(), auditStore: memoryStore(),
  });
  service.seedTask({
    id: 10, type: "change", status: "awaiting_selection", template: "delete_security_rule",
    params: { keyword: "legacy" }, steps: [], _candidate: { firewall: "lab" },
  });
  const result = await service.actOnTask(10, "select", {
    params: { name: "legacy-rule", keyword: "legacy" },
    step: "用户从候选选中：legacy-rule",
  });
  assert.equal(result.status, "awaiting_commit");
  assert.deepEqual(service.listTasks()[0].params, { name: "legacy-rule", keyword: "legacy" });
  assert.deepEqual(deletes, [
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='legacy-rule']",
  ]);
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

test("task dispatch persists prepared state before starting its runner and records runner failures", async () => {
  const taskStore = memoryStore();
  const service = createTaskService({ panosAdapter: {}, taskStore, auditStore: memoryStore() });
  const task = service.dispatchTask("query", "设备状态", {}, (created) => {
    created.decision = "准备完成";
  }, async (created) => {
    assert.equal(taskStore.load()[0], created);
    assert.equal(taskStore.load()[0].decision, "准备完成");
    created.status = "running";
    await Promise.resolve();
    throw new Error("runner failed");
  });
  assert.equal(task.status, "running");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(service.getTask(task.id).status, "failed");
  assert.match(service.getTask(task.id).error, /runner failed/);
});
