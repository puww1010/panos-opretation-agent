const { planFingerprint, transitionTask } = require("../lib/task-governance");

function normalizeChangeParams(template, params = {}) {
  return template === "add_address_object"
    ? { ...params, type: params.type || "ip-netmask" }
    : { ...params };
}

function createTaskService({ panosAdapter = {}, taskStore, auditStore, clock = Date.now, candidateRunner, deferExecution = false, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), maxCommitPolls = 200 }) {
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

  function getTask(id) {
    return tasks.find((task) => task.id === id);
  }

  function dispatchTask(type, input, extra, prepare, runner) {
    if (!runner) {
      runner = prepare;
      prepare = null;
    }
    const task = createTask(type, input, extra);
    if (prepare) prepare(task);
    addTask(task);
    try {
      Promise.resolve(runner(task)).catch((error) => {
        task.status = "failed";
        task.error = String(error.message || error);
        saveTask(task);
      });
    } catch (error) {
      task.status = "failed";
      task.error = String(error.message || error);
      saveTask(task);
    }
    return task;
  }

  function recordAudit(task, event) {
    task.audit = task.audit || [];
    task.audit.push(event);
    const audit = auditStore.load();
    audit.push({ ...event, type: task.type, firewall: task.firewall || null, planFingerprint: task.planFingerprint || null });
    auditStore.save(audit);
  }

  function finalizeCandidate(task) {
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
  }

  async function runCandidate(task) {
    task.params = normalizeChangeParams(task.template, task.params);
    if (task.template === "add_address_object" && panosAdapter.directConfigSet) {
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='" + task.params.name + "']";
      await panosAdapter.directConfigSet(xpath, "<ip-netmask>" + task.params.value + "</ip-netmask>");
      finalizeCandidate(task);
      return;
    }
    if (task.template === "delete_address_object" && panosAdapter.directConfigDelete) {
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='" + task.params.name + "']";
      await panosAdapter.directConfigDelete(xpath);
      finalizeCandidate(task);
      return;
    }
    if (task.template === "move_security_rule" && panosAdapter.directConfigMove) {
      const { name, where, destination } = task.params;
      if (!name || !where) throw new Error("move_security_rule 缺少 name 或 where");
      if (["before", "after"].includes(where) && !destination) {
        throw new Error("move_security_rule 在 before/after 时必须提供 destination（参照规则名）");
      }
      const base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']";
      const xpath = base + "/rulebase/security/rules/entry[@name='" + name + "']";
      const destinationXpath = ["before", "after"].includes(where)
        ? base + "/rulebase/security/rules/entry[@name='" + destination + "']"
        : null;
      await panosAdapter.directConfigMove(xpath, where, destinationXpath);
      task.steps.push("candidate: move_security_rule " + name + " " + where + (destinationXpath ? " " + destination : ""));
      finalizeCandidate(task);
      return;
    }
    if (["set_security_rule_disabled", "set_security_rule_enabled"].includes(task.template) && task.params.name && panosAdapter.directConfigSet) {
      const value = task.template === "set_security_rule_disabled" ? "yes" : "no";
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='" + task.params.name + "']/disabled";
      await panosAdapter.directConfigSet(xpath, "<disabled>" + value + "</disabled>");
      task.steps.push("candidate: " + (value === "yes" ? "disable " : "enable ") + task.params.name);
      finalizeCandidate(task);
      return;
    }
    if (task.template === "delete_security_rule" && task.params.name && panosAdapter.directConfigDelete) {
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='" + task.params.name + "']";
      await panosAdapter.directConfigDelete(xpath);
      task.steps.push("candidate: delete_security_rule " + task.params.name);
      finalizeCandidate(task);
      return;
    }
    if (task.template === "block_ip" && panosAdapter.directConfigSet) {
      const date = new Date(clock()).toISOString().slice(0, 10).replace(/-/g, "");
      const name = "block-" + task.params.ip + "-" + date;
      const base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']";
      await panosAdapter.directConfigSet(base + "/address/entry[@name='" + name + "']", "<ip-netmask>" + task.params.ip + "/32</ip-netmask>");
      task.steps.push("candidate: address " + name);
      const ruleXml = "<from><member>any</member></from><to><member>any</member></to><source><member>" + name + "</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>deny</action><description>WebUI block by Agent</description>";
      await panosAdapter.directConfigSet(base + "/rulebase/security/rules/entry[@name='" + name + "']", ruleXml);
      task.steps.push("candidate: deny rule " + name);
      task.params._objName = name;
      if (task.params.position && ["top", "bottom", "before", "after"].includes(task.params.position) && panosAdapter.directConfigMove) {
        if (["before", "after"].includes(task.params.position) && !task.params.destination) {
          task.steps.push("⚠️ " + task.params.position + " 需要 destination 参照规则名，跳过 move，规则留在末尾");
        } else {
          const destination = ["before", "after"].includes(task.params.position)
            ? base + "/rulebase/security/rules/entry[@name='" + task.params.destination + "']"
            : null;
          await panosAdapter.directConfigMove(base + "/rulebase/security/rules/entry[@name='" + name + "']", task.params.position, destination);
          task.steps.push("candidate: move " + name + " " + task.params.position);
        }
      } else {
        task.steps.push("ℹ️ 用户未指定位置，规则留在末尾（不移动）");
      }
      finalizeCandidate(task);
      return;
    }
    if (candidateRunner) return candidateRunner(task);
    task.status = "executing";
    saveTasks();
  }

  async function runCommit(task) {
    if (panosAdapter.directCommit) {
      task.status = "committing";
      let job = null;
      try {
        const response = await panosAdapter.directCommit("WebUI Agent: " + (task.templateLabel || task.type));
        const text = String(response);
        const match = text.match(/<job>(\d+)<\/job>/i)
          || text.match(/<id>(\d+)<\/id>/i)
          || text.match(/jobid[\s=]+["']?(\d+)/i)
          || text.match(/\bid\s+(\d+)\b/i)
          || text.match(/"job"\s*:\s*(\d+)/);
        job = match ? match[1] : null;
        task.steps.push("commit 入队" + (job ? " job=" + job : "：无 job（响应：" + text.slice(0, 120) + "）"));
        if (!job) {
          task.steps.push("可能原因：candidate 未生效（无变更可提交）或 commit 端点未返回 job");
          task.status = "done";
          task.result = Object.assign(task.result || {}, { needsManualCommit: true, raw: text.slice(0, 300) });
          recordAudit(task, { taskId: task.id, action: "commit_needs_follow_up", from: "committing", to: "done", at: new Date(clock()).toISOString() });
          saveTasks();
          return;
        }
        if (!panosAdapter.directOp) {
          task.steps.push("无法查询 commit job 状态，请到 Monitor → Jobs 确认最终结果");
          task.status = "done";
          task.result = Object.assign(task.result || {}, { needsManualCommit: true, job });
          recordAudit(task, { taskId: task.id, action: "commit_needs_follow_up", from: "committing", to: "done", at: new Date(clock()).toISOString() });
          saveTasks();
          return;
        }
      } catch (error) {
        task.steps.push("commit 入队失败：" + String(error.message || error).slice(0, 80));
        task.status = "done";
        task.result = Object.assign(task.result || {}, { needsManualCommit: true });
        recordAudit(task, { taskId: task.id, action: "commit_needs_follow_up", from: "committing", to: "done", at: new Date(clock()).toISOString() });
        saveTasks();
        return;
      }

      let lastJobSignature = "";
      for (let index = 0; index < maxCommitPolls; index += 1) {
        if (task.cancelled) {
          task.steps.push("已取消任务，停止 commit 轮询");
          task.steps.push("⚠️ commit job=" + job + " 可能已在防火墙执行，请到 Monitor → Jobs 确认最终状态；如需回退变更请手动处理");
          task.status = "cancelled";
          task.result = Object.assign(task.result || {}, { cancelledWhileCommitting: true, job });
          recordAudit(task, { taskId: task.id, action: "commit_polling_cancelled", from: "committing", to: "cancelled", at: new Date(clock()).toISOString() });
          saveTasks();
          return;
        }
        await sleep(index < 30 ? 3000 : 5000);
        try {
          const response = await panosAdapter.directOp("<show><jobs><id>" + job + "</id></jobs></show>");
          const text = String(response);
          const statusMatch = text.match(/<status>\s*([^<\s]+)/i);
          const status = statusMatch ? statusMatch[1].toUpperCase() : "";
          const progressMatch = text.match(/<progress>\s*(\d+)/i);
          const progress = progressMatch ? progressMatch[1] : "";
          const signature = status + "|" + progress;
          if (signature !== lastJobSignature || index % 15 === 0) {
            task.steps.push("commit job=" + job + " status=" + status + (progress ? " (" + progress + "%)" : ""));
            lastJobSignature = signature;
          }
          if (["FIN", "FINOK"].includes(status) || text.includes("FIN OK")) {
            task.steps.push("commit 完成 (job=" + job + ")");
            task.status = "done";
            task.result = Object.assign(task.result || {}, { job });
            recordAudit(task, { taskId: task.id, action: "commit_completed", from: "committing", to: "done", at: new Date(clock()).toISOString() });
            saveTasks();
            return;
          }
          if (["FAIL", "STOPPED", "ERROR"].includes(status)) {
            task.steps.push("commit 失败：" + status + " job=" + job);
            task.status = "done";
            task.result = Object.assign(task.result || {}, { job, commitFailed: true });
            recordAudit(task, { taskId: task.id, action: "commit_failed", from: "committing", to: "done", at: new Date(clock()).toISOString() });
            saveTasks();
            return;
          }
        } catch {}
      }
      task.steps.push("commit 超时（10 分钟）：job=" + job + " 可能在防火墙后台仍在执行中。请登录防火墙 Web 界面 → Monitor → Jobs，搜索 job ID " + job + " 查看最终状态，或手动执行 commit");
      task.status = "done";
      task.result = Object.assign(task.result || {}, { needsManualCommit: true, timeout: true, timedOut: true, job });
      recordAudit(task, { taskId: task.id, action: "commit_timed_out", from: "committing", to: "done", at: new Date(clock()).toISOString() });
      saveTasks();
      return;
    }
    throw new Error("PAN-OS adapter does not provide directCommit");
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

  async function runBatchSelection(task, names) {
    const candidate = task._candidate;
    const results = [];
    for (const name of names) {
      const child = createTask("change", candidate.template + " " + name, {
        template: candidate.template,
        params: { name },
        firewall: candidate.firewall,
        createdAt: new Date(clock()).toISOString(),
      });
      addTask(child);
      try {
        await runCandidate(child);
        results.push({ name, success: true, taskId: child.id });
      } catch (error) {
        child.status = "failed";
        child.error = String(error.message || error);
        saveTask(child);
        results.push({ name, success: false, error: child.error, taskId: child.id });
      }
    }

    const successfulTasks = results
      .filter((result) => result.success)
      .map((result) => getTask(result.taskId))
      .filter(Boolean);
    if (successfulTasks.length) {
      task.steps.push("统一 commit " + successfulTasks.length + " 个变更（合并为单次 commit）");
      try {
        await runCommit(task);
        if (task.result?.commitFailed || task.result?.needsManualCommit) {
          const message = task.result.commitFailed ? "commit 失败" : "commit 超时/需手动";
          for (const child of successfulTasks) {
            child.status = "failed";
            child.error = message + " (job=" + (task.result.job || "?") + ")";
            saveTask(child);
          }
        } else {
          for (const child of successfulTasks) {
            child.status = "done";
            child.result = Object.assign(child.result || {}, { mergedCommit: true, commitJob: task.result.job });
            saveTask(child);
          }
        }
      } catch (error) {
        for (const child of successfulTasks) {
          child.status = "failed";
          child.error = "commit 失败: " + String(error.message || error);
          saveTask(child);
        }
        task.steps.push("commit 异常: " + String(error.message || error).slice(0, 120));
      }
    } else {
      task.steps.push("无可 commit 的变更");
    }
    if (task.status !== "cancelled") task.status = "done";
    task.result = Object.assign(task.result || {}, { batch: true, total: names.length, results });
    saveTask(task);
    return { taskId: task.id, status: task.status };
  }

  async function startBatchSelection(id, names) {
    if (!Array.isArray(names) || !names.length) throw new Error("names 必须是非空数组");
    const task = getTask(id);
    if (!task) throw new Error("task not found");
    if (task.status !== "awaiting_selection" || !task._candidate) {
      throw new Error("非法操作或状态不匹配: " + task.status);
    }
    const transition = transitionTask(task, "select", new Date(clock()));
    if (!transition.ok) throw new Error("非法操作或状态不匹配: " + task.status);
    recordAudit(task, transition.event);
    task.steps.push("批量执行 " + names.length + " 个策略：" + names.join(", "));
    saveTask(task);
    const execution = runBatchSelection(task, names);
    if (deferExecution) {
      void execution.catch((error) => {
        task.status = "failed";
        task.error = String(error.message || error);
        saveTask(task);
      });
      return { taskId: task.id, status: task.status, message: "开始批量执行 " + names.length + " 个策略" };
    }
    return execution;
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
    dispatchTask,
    getTask,
    listTasks: () => tasks,
    runCandidate,
    saveTask,
    seedTask,
    startBatchSelection,
  };
}

module.exports = { createTaskService, normalizeChangeParams };
