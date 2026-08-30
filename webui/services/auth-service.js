const crypto = require("node:crypto");
const fs = require("node:fs");

function createAuthService({ authFile, environment = process.env, clock = Date.now, randomToken = () => crypto.randomBytes(32).toString("hex"), logger = console } = {}) {
  const hash = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");
  const sessionDays = 7;
  const idleMinutes = 0;
  let data = null;
  let lastWrite = 0;

  function save() { fs.writeFileSync(authFile, JSON.stringify(data, null, 2)); }
  function load() {
    try { if (fs.existsSync(authFile)) data = JSON.parse(fs.readFileSync(authFile, "utf-8")); }
    catch (error) { logger.error("[auth] auth.json 解析失败，重建:", String(error.message || error)); }
    if (!data || typeof data !== "object") data = { username: "admin", password_hash: "", sessions: {}, internal_token: "" };
    data.sessions = data.sessions || {};
    for (const token of Object.keys(data.sessions)) if (typeof data.sessions[token] === "number") data.sessions[token] = { exp: data.sessions[token], lastSeen: clock() };
    if (!data.password_hash) {
      const password = environment.PANOS_WEB_PASSWORD || crypto.randomBytes(6).toString("base64").replace(/[^a-zA-Z0-9]/g, "").slice(0, 10);
      data.password_hash = hash(password);
      logger.warn("[auth] 首次启动已创建 WebUI 登录凭据，请通过受控方式读取或修改 auth.json。");
    }
    if (!data.internal_token) data.internal_token = environment.PANOS_WEB_INTERNAL_TOKEN || crypto.randomBytes(24).toString("hex");
    save();
  }

  function tokenFromRequest(req) {
    const header = req.headers?.authorization || "";
    let token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
    if (!token && req.url?.includes("token=")) token = decodeURIComponent((req.url.match(/[?&]token=([^&]*)/) || [])[1] || "");
    return token;
  }
  function valid(token) {
    const session = data.sessions[token];
    if (!token || !session) return false;
    if (clock() > session.exp) { delete data.sessions[token]; save(); return false; }
    return true;
  }
  function checkRequest(req) {
    const token = tokenFromRequest(req);
    return Boolean(token) && (token === data.internal_token || valid(token));
  }
  function login(credentials = {}) {
    if (credentials.username !== data.username || hash(credentials.password || "") !== data.password_hash) return { ok: false };
    const token = randomToken();
    data.sessions[token] = { exp: clock() + sessionDays * 864e5, lastSeen: clock() };
    save();
    return { ok: true, token, username: data.username, expiresIn: sessionDays * 86400, idleMinutes };
  }
  function logout(token) { if (token && data.sessions[token]) { delete data.sessions[token]; save(); } return { ok: true }; }
  function touch(token) {
    if (!token || token === data.internal_token || !data.sessions[token]) return;
    data.sessions[token].lastSeen = clock();
    if (clock() - lastWrite > 60000) { lastWrite = clock(); save(); }
  }
  function changePassword(token, credentials = {}) {
    if (!valid(token)) return { ok: false, error: "未认证或登录已过期，请重新登录" };
    const oldPassword = String(credentials.old_password || ""), newPassword = String(credentials.new_password || "");
    if (hash(oldPassword) !== data.password_hash) return { ok: false, error: "旧密码不正确" };
    if (newPassword.length < 8) return { ok: false, error: "新密码至少 8 位" };
    if (newPassword === oldPassword) return { ok: false, error: "新密码不能与旧密码相同" };
    data.password_hash = hash(newPassword); data.sessions = {}; save();
    return { ok: true, message: "密码已修改，请重新登录" };
  }
  load();
  return { idleMinutes, checkRequest, changePassword, getUsername: () => data.username, isInternalToken: (token) => token === data.internal_token, login, logout, tokenFromRequest, touch };
}

module.exports = { createAuthService };
