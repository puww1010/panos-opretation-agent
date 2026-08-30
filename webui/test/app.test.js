const test = require("node:test");
const assert = require("node:assert/strict");
const { once } = require("node:events");
const { createApp } = require("../app");

async function request(server, path, headers = {}) {
  const response = await fetch("http://127.0.0.1:" + server.address().port + path, { headers });
  return { status: response.status, body: await response.json() };
}

test("app preserves static, auth, API router, and 404 dispatch order", async (t) => {
  const calls = [];
  const staticRouter = { handle: (_req, res) => { calls.push("static"); if (_req.url === "/asset") { res.writeHead(204); res.end(); return true; } return false; } };
  const apiRouter = {
    handleAuth: async (req, send) => { calls.push("auth"); if (req.url === "/blocked") { send(401, { error: "blocked" }); return true; } return false; },
    handleDashboard: async (req, send) => { calls.push("dashboard"); if (req.url === "/dashboard") { send(200, { ok: "dashboard" }); return true; } return false; },
    handleLlm: async () => { calls.push("llm"); return false; },
    handleTasks: async () => { calls.push("tasks"); return false; },
    handleOperations: async () => { calls.push("operations"); return false; },
  };
  const app = createApp({ apiRouter, staticRouter, buildSecurityHeaders: () => ({ "X-Test": "yes" }), createTask: async () => ({}), ensureConnected: async () => {}, touchIfUserAction: () => {} });
  app.listen(0, "127.0.0.1");
  await once(app, "listening");
  t.after(() => app.close());

  assert.equal((await fetch("http://127.0.0.1:" + app.address().port + "/asset")).status, 204);
  assert.deepEqual(await request(app, "/blocked"), { status: 401, body: { error: "blocked" } });
  assert.deepEqual(await request(app, "/dashboard"), { status: 200, body: { ok: "dashboard" } });
  assert.deepEqual(await request(app, "/missing"), { status: 404, body: { error: "Not Found" } });
  assert.deepEqual(calls, ["static", "static", "auth", "static", "auth", "dashboard", "static", "auth", "dashboard", "llm", "tasks", "operations"]);
});
