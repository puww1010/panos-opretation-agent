const test = require("node:test");
const assert = require("node:assert/strict");
const { createTaskPlanner } = require("../services/task-planner");

test("task planner gives a new address-object plan the ip-netmask default", async () => {
  const saved = [];
  const planner = createTaskPlanner({
    actions: { change: { label: "变更" } },
    changeTemplates: { add_address_object: { label: "创建地址对象", plan: (params) => `类型:${params.type}` } },
    callTool: async () => null,
    llmService: {
      extractChange: async () => ({ template: "add_address_object", params: { name: "example", value: "203.0.113.10" } }),
      getCurrent: () => "keyword",
      resolveAction: async () => ({ action: "change" }),
    },
    normalizeChangeParams: (_template, params) => ({ ...params, type: params.type || "ip-netmask" }),
    planFingerprint: () => "fingerprint",
    taskService: {
      addTask: (task) => saved.push(task),
      createTask: (_type, input, extra) => ({ id: 1, input, steps: [], ...extra }),
      listTasks: () => [],
      recordAudit: () => {},
    },
  });

  const result = await planner.createTaskFromInput("创建地址对象", "lab", "web");
  assert.equal(result.plan, "类型:ip-netmask");
  assert.equal(saved[0].params.type, "ip-netmask");
});

test("traffic queries default to ten minutes while explicit windows and counts win", async () => {
  const tasks = [];
  const planner = createTaskPlanner({
    actions: { traffic: { label: "流量日志" } },
    callTool: async () => null,
    llmService: {
      getCurrent: () => "keyword",
      resolveAction: async (input) => input.includes("30分钟")
        ? { action: "traffic", minutes: 30 }
        : { action: "traffic", minutes: null },
    },
    taskService: {
      dispatchTask: (_type, input, extra, prepare) => {
        const task = { id: tasks.length + 1, input, status: "pending", steps: [], ...extra };
        prepare(task);
        tasks.push(task);
        return task;
      },
      listTasks: () => [],
    },
  });

  await planner.createTaskFromInput("流量日志", "lab", "web");
  await planner.createTaskFromInput("最近30分钟流量日志", "lab", "web");
  await planner.createTaskFromInput("最新20条流量日志", "lab", "web");

  assert.equal(tasks[0].minutes, 10);
  assert.equal(tasks[1].minutes, 30);
  assert.equal(tasks[2].minutes, null);
  assert.equal(tasks[2].nlogs, 20);
});
