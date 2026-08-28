const test = require("node:test");
const assert = require("node:assert/strict");

const { buildSecurityHeaders, isSameOriginApiPath, shouldAttachAuthorization } = require("../lib/security");

test("JSON API responses receive baseline browser security headers", () => {
  const headers = buildSecurityHeaders("application/json; charset=utf-8");

  assert.equal(headers["Content-Type"], "application/json; charset=utf-8");
  assert.equal(headers["X-Content-Type-Options"], "nosniff");
  assert.equal(headers["X-Frame-Options"], "DENY");
  assert.equal(headers["Referrer-Policy"], "same-origin");
  assert.equal(headers["Permissions-Policy"], "camera=(), microphone=(), geolocation=()");
});

test("only relative API paths are accepted as same-origin API paths", () => {
  assert.equal(isSameOriginApiPath("/api/tasks"), true);
  assert.equal(isSameOriginApiPath("/api/task/17/approve"), true);
  assert.equal(isSameOriginApiPath("https://example.test/api/tasks"), false);
  assert.equal(isSameOriginApiPath("//example.test/api/tasks"), false);
  assert.equal(isSameOriginApiPath("/assets/agent-logo.png"), false);
});

test("authorization is attached only to same-origin API requests", () => {
  const origin = "http://localhost:8080";

  assert.equal(shouldAttachAuthorization("/api/tasks", origin), true);
  assert.equal(shouldAttachAuthorization("http://localhost:8080/api/tasks", origin), true);
  assert.equal(shouldAttachAuthorization("https://example.test/api/tasks", origin), false);
  assert.equal(shouldAttachAuthorization("/assets/agent-logo.png", origin), false);
});
