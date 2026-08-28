const test = require("node:test");
const assert = require("node:assert/strict");

const { planFingerprint, transitionTask } = require("../lib/task-governance");

test("approval moves only an awaiting approval task to executing and records an event", () => {
  const task = { id: 7, status: "awaiting_approval", audit: [] };
  const result = transitionTask(task, "approve", new Date("2026-08-27T12:00:00.000Z"));

  assert.equal(result.ok, true);
  assert.equal(task.status, "executing");
  assert.deepEqual(result.event, {
    taskId: 7,
    action: "approve",
    from: "awaiting_approval",
    to: "executing",
    at: "2026-08-27T12:00:00.000Z",
  });
  assert.deepEqual(task.audit, [result.event]);
});

test("commit confirmation is rejected before a task reaches awaiting commit", () => {
  const task = { id: 7, status: "awaiting_approval", audit: [] };
  const result = transitionTask(task, "confirm", new Date("2026-08-27T12:00:00.000Z"));

  assert.equal(result.ok, false);
  assert.equal(task.status, "awaiting_approval");
  assert.equal(task.audit.length, 0);
});

test("rule selection moves only an awaiting selection task to executing", () => {
  const selected = transitionTask({ id: 8, status: "awaiting_selection", audit: [] }, "select");
  const rejected = transitionTask({ id: 9, status: "awaiting_approval", audit: [] }, "select");

  assert.equal(selected.ok, true);
  assert.equal(selected.task.status, "executing");
  assert.equal(selected.event.action, "select");
  assert.equal(rejected.ok, false);
  assert.equal(rejected.task.status, "awaiting_approval");
});

test("cancellation is rejected after a task has reached a terminal state", () => {
  const task = { id: 7, status: "done", audit: [] };
  const result = transitionTask(task, "cancel", new Date("2026-08-27T12:00:00.000Z"));

  assert.equal(result.ok, false);
  assert.equal(task.status, "done");
});

test("the same change plan has a stable fingerprint and a changed target does not", () => {
  const first = { template: "disable_rule", params: { name: "rule-a" }, firewall: "fw-a" };
  const samePlanDifferentKeyOrder = { firewall: "fw-a", params: { name: "rule-a" }, template: "disable_rule" };
  const changed = { template: "disable_rule", params: { name: "rule-b" }, firewall: "fw-a" };

  assert.equal(planFingerprint(first), planFingerprint(samePlanDifferentKeyOrder));
  assert.notEqual(planFingerprint(first), planFingerprint(changed));
});
