# 后端监控布局调整 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将常态数据流状态移出顶部固定横幅，改为侧栏底部的低干扰连接状态，并将后端地址与四接口检测收进设置中的后端监控面板。

**Architecture:** 保留现有 `beat`、`pulseLiveBadge`、`testBackend` 和四接口检测逻辑，不增加 API 或改动认证。页面仅重组现有 DOM：侧栏底部展示当前状态；设置菜单提供面板入口；警告和错误继续通过临时顶部提示获得高可见性。

**Tech Stack:** 原生 HTML、CSS、浏览器 JavaScript、Node.js 内置测试运行器。

## Global Constraints

- 不改动防火墙配置、任务数据、认证 API 或运行时配置文件。
- 健康状态正常时不占用顶部固定区域；异常时才显示临时顶部提示。
- 手动检测继续检查 `/api/overview`、`/api/llm`、`/api/tasks`、`/api/feishu/status`。
- 仅修改本任务涉及的 `webui/index.html` 与静态页面契约测试。

---

### Task 1: 先固定后端监控页面契约

**Files:**
- Modify: `webui/test/static-routes.test.js`
- Modify: `webui/index.html`

**Interfaces:**
- Consumes: 静态路由 `createStaticRouter({ rootDirectory }).handle(req, res)`。
- Produces: 页面中可被验证的 `sideConnectionStatus`、`showBackendMonitor()` 和“后端监控”入口。

- [x] **Step 1: 写入失败的静态页面测试**

```js
test("backend monitoring is available from settings while data flow status lives in the sidebar", () => {
  const router = createStaticRouter({ rootDirectory: path.join(__dirname, "..") });
  const root = response();
  assert.equal(router.handle({ method: "GET", url: "/" }, root), true);
  assert.match(root.state.body, /id="sideConnectionStatus"/);
  assert.match(root.state.body, /后端监控/);
  assert.match(root.state.body, /function showBackendMonitor\(\)/);
  assert.doesNotMatch(root.state.body, /position:fixed;top:0;left:50%/);
});
```

- [x] **Step 2: 运行测试并确认失败**

Run: `node --test webui/test/static-routes.test.js`

Expected: FAIL，因为当前页面没有 `sideConnectionStatus` 或 `showBackendMonitor()`，且仍有顶部固定状态横幅。

- [x] **Step 3: 最小化实现 DOM 与呈现逻辑**

```js
function showBackendMonitor() {
  // 打开只读面板，显示当前地址、最近心跳和四接口检测结果。
}

function pulseLiveBadge(state) {
  // 更新侧栏连接状态；仅在 warn/err 时显示临时顶部提示。
}
```

- [x] **Step 4: 运行测试并确认通过**

Run: `node --test webui/test/static-routes.test.js`

Expected: PASS，页面包含新入口且不再有正常状态的顶部固定横幅。

### Task 2: 验证完整回归并独立提交

**Files:**
- Modify: `webui/index.html`
- Modify: `webui/test/static-routes.test.js`

**Interfaces:**
- Consumes: Task 1 的侧栏状态与后端监控面板。
- Produces: 可刷新使用、不会影响现有 Dashboard/Task/LLM/认证路由的页面布局。

- [x] **Step 1: 运行全量测试**

Run: `node --test webui/test/*.test.js`

Expected: 所有测试通过。

- [x] **Step 2: 检查差异边界**

Run: `git diff --check && git diff -- webui/index.html webui/test/static-routes.test.js`

Expected: 没有空白错误，且只涉及状态条、后端监控入口/面板及测试。

- [ ] **Step 3: 独立提交**

```bash
git add webui/index.html webui/test/static-routes.test.js
git commit -m "feat(ops): move backend monitoring into settings"
```

- [ ] **Step 4: 验证提交边界**

Run: `git show --stat --oneline --summary HEAD && git status --short`

Expected: 提交只包含本任务页面与测试；既有运行时配置、CPU 文案和文档改动不被纳入。
