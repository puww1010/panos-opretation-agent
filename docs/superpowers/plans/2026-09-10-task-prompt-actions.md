# 任务中心用户提问操作 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为任务中心每个用户提问气泡增加复制、修改和重新发送操作，以复用原始问法而不更改历史任务。

**Architecture:** 改动仅位于 `webui/index.html`。用户气泡复用已有的悬停操作条样式；复制和修改只操作浏览器状态，重新发送直接调用既有 `POST /api/task` 接口并传入原始 `input` 与当前防火墙，不传 `replyTo`。

**Tech Stack:** Node.js 内置测试框架、原生浏览器 JavaScript、现有静态资源路由。

## Global Constraints

- 只操作用户气泡，不改变机器人回复气泡的操作。
- 不新增 API、服务层、任务持久化字段或任务状态。
- 修改只回填输入框，不自动发送，也不保留 `replyTo`。
- 重新发送只发送原始 `input` 和当前防火墙，不附带 `replyTo` 或 `@#任务号`。
- 不输出、读取或提交任何认证凭据。

---

### Task 1: 为用户提问操作建立页面契约测试

**Files:**
- Modify: `webui/test/static-routes.test.js`
- Test: `webui/test/static-routes.test.js`

**Interfaces:**
- Consumes: `createStaticRouter({ rootDirectory }).handle(req, res)`，返回含 `index.html` 的响应正文。
- Produces: 一个断言页面包含用户提问操作按钮及其前端行为函数的回归测试。

- [ ] **Step 1: 写入失败测试**

在 `webui/test/static-routes.test.js` 末尾添加：

```js
test("task center exposes copy, edit, and resend actions for user prompts", () => {
  const router = createStaticRouter({ rootDirectory: path.join(__dirname, "..") });
  const root = response();

  assert.equal(router.handle({ method: "GET", url: "/" }, root), true);
  assert.match(root.state.body, /copyTaskPrompt\(/);
  assert.match(root.state.body, /editTaskPrompt\(/);
  assert.match(root.state.body, /resendTaskPrompt\(/);
  assert.match(root.state.body, /复制提问/);
  assert.match(root.state.body, /修改提问/);
  assert.match(root.state.body, /重新发送/);
});
```

- [ ] **Step 2: 验证测试确实失败**

运行：

```bash
node --test webui/test/static-routes.test.js
```

预期：新增测试失败，原因是页面尚未包含 `copyTaskPrompt`、`editTaskPrompt` 和 `resendTaskPrompt`。

- [ ] **Step 3: 保留失败测试，不修改其他测试**

不修改 API Router、Task Service 或既有静态路由测试；失败测试只约束页面契约。

### Task 2: 实现用户提问的复制、修改与重新发送

**Files:**
- Modify: `webui/index.html:2321-2390`
- Test: `webui/test/static-routes.test.js`

**Interfaces:**
- Consumes: `_taskCache` 中的任务对象 `{ id, input }`、`currentFirewall()`、`pollTasks()`、`clearReplyChip()`、`autoGrow()` 和既有 `POST /api/task`。
- Produces:
  - `copyTaskPrompt(id)`：复制任务的 `input`。
  - `editTaskPrompt(id)`：清除回复关联并回填输入框。
  - `resendTaskPrompt(id)`：以 `{ query: task.input, firewall: currentFirewall() }` 创建新的普通请求。

- [ ] **Step 1: 先运行 Task 1 的失败测试**

运行：

```bash
node --test webui/test/static-routes.test.js
```

预期：用户提问操作测试仍失败，证明尚未写入生产实现。

- [ ] **Step 2: 在现有 `copyTaskText` 附近增加最小前端函数**

新增三个函数，遵循以下行为：

```js
async function copyTaskPrompt(id) {
  const task = _taskCache.find((item) => item.id === id);
  if (!task) return;
  await navigator.clipboard.writeText(task.input);
}

function editTaskPrompt(id) {
  const task = _taskCache.find((item) => item.id === id);
  const input = document.getElementById("q");
  if (!task || !input) return;
  clearReplyChip();
  input.value = task.input;
  autoGrow(input);
  focusInput();
}

async function resendTaskPrompt(id) {
  const task = _taskCache.find((item) => item.id === id);
  if (!task) return;
  const response = await fetch("/api/task", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: task.input, firewall: currentFirewall() }),
  });
  const data = await response.json();
  if (data.error) throw new Error(data.error);
  pollTasks();
}
```

实现时必须沿用现有 `copyTaskText` 的剪贴板降级复制和状态提示；`resendTaskPrompt` 必须捕获错误并写入现有 `liveTxt` 状态区，不能让未处理 Promise 显示为页面异常。

- [ ] **Step 3: 在用户气泡渲染中加入悬停操作条**

将 `renderTaskMessages(t, animate)` 的用户气泡结构改为在输入和元信息之后追加：

```js
'<div class="msg-actions">' +
  '<button onclick="copyTaskPrompt(' + t.id + ')">' + ic("copy", "sm") + ' 复制提问</button>' +
  '<button onclick="editTaskPrompt(' + t.id + ')">' + ic("pencil", "sm") + ' 修改提问</button>' +
  '<button onclick="resendTaskPrompt(' + t.id + ')">' + ic("zap", "sm") + ' 重新发送</button>' +
'</div>'
```

保持现有 `.msg-actions` 的悬停显示样式，不新增布局组件。

- [ ] **Step 4: 验证页面契约测试通过**

运行：

```bash
node --test webui/test/static-routes.test.js
```

预期：全部静态路由测试通过，新增测试确认三个操作和函数均存在。

- [ ] **Step 5: 运行全量回归**

运行：

```bash
node --test webui/test/*.test.js
git diff --check
```

预期：所有测试通过，`git diff --check` 无输出。

- [ ] **Step 6: 提交实现与测试**

运行：

```bash
git add webui/index.html webui/test/static-routes.test.js
git commit -m "feat: add task prompt actions"
```

预期：只提交用户提问操作和对应的页面契约测试。
