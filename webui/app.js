const http = require("node:http");

function createApp({ apiRouter, staticRouter, buildSecurityHeaders, createTask, ensureConnected, touchIfUserAction }) {
  return http.createServer(async (req, res) => {
    for (const [name, value] of Object.entries(buildSecurityHeaders())) res.setHeader(name, value);
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    const send = (code, body) => { res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" }); res.end(JSON.stringify(body)); };
    const readBody = () => new Promise((resolve) => { let value = ""; req.on("data", (chunk) => (value += chunk)); req.on("end", () => resolve(value)); });
    try {
      if (staticRouter.handle(req, res)) return;
      if (await apiRouter.handleAuth(req, send, readBody, (token) => touchIfUserAction(req, token))) return;
      if (await apiRouter.handleDashboard(req, send)) return;
      if (await apiRouter.handleLlm(req, send, readBody)) return;
      if (await apiRouter.handleTasks(req, send, readBody, createTask, ensureConnected)) return;
      if (await apiRouter.handleOperations(req, send, readBody)) return;
      send(404, { error: "Not Found" });
    } catch (error) { send(500, { error: String(error.message || error) }); }
  });
}

module.exports = { createApp };
