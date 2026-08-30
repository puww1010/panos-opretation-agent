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
