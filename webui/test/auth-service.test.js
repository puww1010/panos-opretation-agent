const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const { createAuthService } = require("../services/auth-service");

const hash = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");

test("auth service authenticates, preserves disabled idle timeout, and invalidates sessions on password change", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "panos-auth-service-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const authFile = path.join(directory, "auth.json");
  fs.writeFileSync(authFile, JSON.stringify({ username: "admin", password_hash: hash("old-password"), sessions: {}, internal_token: "internal" }));
  let now = 1_700_000_000_000;
  const service = createAuthService({ authFile, clock: () => now, randomToken: () => "session-token" });

  assert.equal(service.idleMinutes, 0);
  assert.deepEqual(service.login({ username: "admin", password: "old-password" }), { ok: true, token: "session-token", username: "admin", expiresIn: 604800, idleMinutes: 0 });
  assert.equal(service.checkRequest({ headers: { authorization: "Bearer session-token" }, url: "/api/tasks" }), true);
  now += 60 * 60 * 1000;
  assert.equal(service.checkRequest({ headers: { authorization: "Bearer session-token" }, url: "/api/tasks" }), true);
  assert.deepEqual(service.changePassword("session-token", { old_password: "old-password", new_password: "new-password" }), { ok: true, message: "密码已修改，请重新登录" });
  assert.equal(service.checkRequest({ headers: { authorization: "Bearer session-token" }, url: "/api/tasks" }), false);
  assert.equal(service.checkRequest({ headers: { authorization: "Bearer internal" }, url: "/api/tasks" }), true);
});
