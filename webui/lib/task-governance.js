const crypto = require("crypto");

const TRANSITIONS = {
  approve: { from: ["awaiting_approval"], to: "executing" },
  reject: { from: ["awaiting_approval"], to: "cancelled" },
  confirm: { from: ["awaiting_commit"], to: "committing" },
  select: { from: ["awaiting_selection"], to: "executing" },
  cancel: { from: ["pending", "running", "executing", "committing", "awaiting_approval", "awaiting_selection", "awaiting_commit"], to: "cancelled" },
};

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function planFingerprint(plan) {
  return crypto.createHash("sha256").update(stableJson(plan)).digest("hex");
}

function createAuditEvent(task, action, from, to, now) {
  return {
    taskId: task.id,
    action,
    from,
    to,
    at: now.toISOString(),
  };
}

function transitionTask(task, action, now = new Date()) {
  const transition = TRANSITIONS[action];
  if (!transition || !transition.from.includes(task.status)) {
    return { ok: false, task, event: null };
  }

  const from = task.status;
  task.status = transition.to;
  const event = createAuditEvent(task, action, from, transition.to, now);
  task.audit = Array.isArray(task.audit) ? task.audit : [];
  task.audit.push(event);
  return { ok: true, task, event };
}

module.exports = { planFingerprint, transitionTask };
