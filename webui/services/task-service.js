const { planFingerprint, transitionTask } = require("../lib/task-governance");

function normalizeChangeParams(template, params = {}) {
  return template === "add_address_object"
    ? { ...params, type: params.type || "ip-netmask" }
    : { ...params };
}

function createTaskService({ panosAdapter = {}, taskStore, auditStore, clock = Date.now, candidateRunner, commitRunner, deferExecution = false }) {
  const tasks = taskStore.load();
  let taskSeq = tasks.reduce((max, task) => Math.max(max, Number(task.id) || 0), 0);

  function saveTasks() { taskStore.save(tasks); }

  function createTask(type, input, extra = {}) {
    let followUpOf = null;
    if (!extra.conversationId) {
      for (let index = tasks.length - 1; index >= 0; index -= 1) {
        const task = tasks[index];
        if (["done", "failed"].includes(task.status) && ["query", "diag", "chat", "inspect"].includes(task.type)) {
          followUpOf = task.id;
          break;
        }
      }
    }
    return {
      id: ++taskSeq,
      type,
      input,
      status: "pending",
      steps: [],
      result: null,
      error: null,
      createdAt: new Date(clock()).toLocaleString("zh-CN"),
      followUpOf,
      ...extra,
    };
  }

  function addTask(task) {
    taskSeq = Math.max(taskSeq, Number(task.id) || 0);
    tasks.push(task);
    saveTasks();
    return task;
  }

  function saveTask(task) {
    const index = tasks.findIndex((item) => item.id === task.id);
    if (index >= 0) tasks[index] = task;
    saveTasks();
    return task;
  }

  function recordAudit(task, event) {
    task.audit = task.audit || [];
    task.audit.push(event);
    const audit = auditStore.load();
    audit.push({ ...event, type: task.type, firewall: task.firewall || null, planFingerprint: task.planFingerprint || null });
    auditStore.save(audit);
  }

  async function runCandidate(task) {
    task.params = normalizeChangeParams(task.template, task.params);
    if (task.template === "add_address_object") {
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='" + task.params.name + "']";
      await panosAdapter.directConfigSet(xpath, "<ip-netmask>" + task.params.value + "</ip-netmask>");
      task.planFingerprint = planFingerprint({ template: task.template, params: task.params, firewall: task.firewall });
      task.status = "awaiting_commit";
      recordAudit(task, {
        taskId: task.id,
        action: "candidate_ready",
        from: "executing",
        to: "awaiting_commit",
        at: new Date(clock()).toISOString(),
      });
      saveTasks();
      return;
    }
    if (candidateRunner) return candidateRunner(task);
    task.status = "executing";
    saveTasks();
  }

  async function runCommit(task) {
    if (commitRunner) return commitRunner(task);
  }

  async function startExecution(task, runner) {
    try {
      await runner(task);
    } catch (error) {
      task.status = "failed";
      task.error = String(error.message || error);
      saveTasks();
      if (!deferExecution) throw error;
    }
  }

  function assertPlanUnchanged(task) {
    if (task.type !== "change" || !task.planFingerprint) return;
    const params = normalizeChangeParams(task.template, task.params || {});
    const actual = planFingerprint({ template: task.template, params, firewall: task.firewall });
    if (actual !== task.planFingerprint) throw new Error("变更计划已变化，请重新生成候选计划");
  }

  async function actOnTask(id, action, payload = {}) {
    const task = tasks.find((item) => item.id === id);
    if (!task) throw new Error("task not found");
    if (["approve", "confirm"].includes(action)) assertPlanUnchanged(task);
    const transition = transitionTask(task, action, new Date(clock()));
    if (!transition.ok) throw new Error("非法操作或状态不匹配: " + task.status);
    recordAudit(task, transition.event);
    if (action === "select") {
      task.params = { ...(payload.params || {}) };
      task.firewall = payload.firewall || task.firewall || task._candidate?.firewall;
      if (payload.step) {
        task.steps = task.steps || [];
        task.steps.push(payload.step);
      }
    }
    if (action === "cancel") {
      task.cancelled = true;
      task.steps = task.steps || [];
      task.steps.push("手动取消");
    }
    if (action === "reject") {
      task.steps = task.steps || [];
      task.steps.push("已拒绝");
    }
    saveTasks();
    if (["approve", "select"].includes(action)) {
      const execution = startExecution(task, runCandidate);
      if (deferExecution) void execution;
      else await execution;
    }
    if (action === "confirm") {
      const execution = startExecution(task, runCommit);
      if (deferExecution) void execution;
      else await execution;
    }
    return { taskId: task.id, status: task.status };
  }

  function seedTask(task) { return addTask(task); }

  function cleanTasks() {
    const terminal = new Set(["done", "cancelled", "failed"]);
    const before = tasks.length;
    for (let index = tasks.length - 1; index >= 0; index -= 1) {
      if (terminal.has(tasks[index].status)) tasks.splice(index, 1);
    }
    saveTasks();
    return { removed: before - tasks.length, remain: tasks.length };
  }

  return {
    actOnTask,
    addTask,
    cleanTasks,
    createTask,
    getTask: (id) => tasks.find((task) => task.id === id),
    listTasks: () => tasks,
    runCandidate,
    saveTask,
    seedTask,
  };
}

module.exports = { createTaskService, normalizeChangeParams };
