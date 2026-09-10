const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { createStaticRouter } = require("../routes/static-routes");

function response() {
  const state = { status: null, headers: null, body: null };
  return {
    state,
    end(body) { state.body = body; },
    writeHead(status, headers = {}) { state.status = status; state.headers = headers; },
  };
}

test("static router serves the root page and rejects traversal-like paths", () => {
  const router = createStaticRouter({ rootDirectory: path.join(__dirname, "..") });
  const root = response();
  assert.equal(router.handle({ method: "GET", url: "/" }, root), true);
  assert.equal(root.state.status, 200);
  assert.match(root.state.headers["Content-Type"], /text\/html/);
  assert.match(root.state.body, /<!-- build:/);

  const traversal = response();
  assert.equal(router.handle({ method: "GET", url: "/assets/%2e%2e/server.js" }, traversal), false);
  assert.equal(traversal.state.status, null);
});

test("dashboard labels management CPU as an OS estimate, not the native WebUI metric", () => {
  const router = createStaticRouter({ rootDirectory: path.join(__dirname, "..") });
  const root = response();

  assert.equal(router.handle({ method: "GET", url: "/" }, root), true);
  assert.match(root.state.body, /管理面 OS CPU 估算/);
  assert.match(root.state.body, /show system resources 的 us \+ sy \+ ni 汇总/);
  assert.doesNotMatch(root.state.body, /Load 与防火墙 WebUI 一致/);
});

test("topology page exposes data-driven views, semantic zoom, and a node detail drawer", () => {
  const router = createStaticRouter({ rootDirectory: path.join(__dirname, "..") });
  const root = response();

  assert.equal(router.handle({ method: "GET", url: "/" }, root), true);
  assert.match(root.state.body, /id="topoModeStructure"/);
  assert.match(root.state.body, /id="topoModeRisk"/);
  assert.match(root.state.body, /id="topoDrawer"/);
  assert.match(root.state.body, /function setTopoMode\(mode\)/);
  assert.match(root.state.body, /function syncTopoSemanticZoom\(\)/);
  assert.match(root.state.body, /ARP 推断邻居关系/);
});

test("sidebar is organized around operations work and uses live risk and approval badges", () => {
  const router = createStaticRouter({ rootDirectory: path.join(__dirname, "..") });
  const root = response();

  assert.equal(router.handle({ method: "GET", url: "/" }, root), true);
  assert.match(root.state.body, /运行态/);
  assert.match(root.state.body, /处置与变更/);
  assert.match(root.state.body, /分析与追溯/);
  assert.match(root.state.body, /资产与保障/);
  assert.match(root.state.body, /协作与系统/);
  assert.match(root.state.body, /id="sideRiskBadge"/);
  assert.match(root.state.body, /id="sideApprovalBadge"/);
  assert.match(root.state.body, /function openOpsOverview\(\)/);
  assert.match(root.state.body, /function openTaskCenter\(mode\)/);
});

test("backend monitoring is available from settings while data flow status lives in the sidebar", () => {
  const router = createStaticRouter({ rootDirectory: path.join(__dirname, "..") });
  const root = response();

  assert.equal(router.handle({ method: "GET", url: "/" }, root), true);
  assert.match(root.state.body, /id="sideConnectionStatus"/);
  assert.match(root.state.body, /后端监控/);
  assert.match(root.state.body, /function showBackendMonitor\(\)/);
  assert.doesNotMatch(root.state.body, /position:fixed;top:0;left:50%/);
});
