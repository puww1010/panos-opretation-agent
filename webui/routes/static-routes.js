const fs = require("node:fs");
const path = require("node:path");

function createStaticRouter({ rootDirectory }) {
  const root = fs.realpathSync(rootDirectory);
  const mimeByExtension = { ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".svg": "image/svg+xml", ".gif": "image/gif", ".ico": "image/x-icon", ".webp": "image/webp", ".woff2": "font/woff2" };

  function handle(req, res) {
    if (req.url === "/favicon.ico") { res.writeHead(204); res.end(); return true; }
    if (req.method !== "GET") return false;
    let requestPath;
    try { requestPath = decodeURIComponent(req.url.split("?")[0]); } catch { return false; }
    if (requestPath === "/" || requestPath === "/index.html") {
      let html = fs.readFileSync(path.join(root, "index.html"), "utf-8");
      html = html.replace("<body>", "<body><!-- build: " + Date.now().toString(36) + " -->");
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store, no-cache, must-revalidate" });
      res.end(html);
      return true;
    }
    if (!requestPath.startsWith("/assets/") && !/^\/[a-zA-Z0-9_.\-]+$/.test(requestPath)) return false;
    const candidate = path.join(root, requestPath);
    if (!fs.existsSync(candidate)) return false;
    const real = fs.realpathSync(candidate);
    if (!real.startsWith(root + path.sep)) return false;
    const mime = mimeByExtension[path.extname(real).toLowerCase()];
    if (!mime) return false;
    res.writeHead(200, { "Content-Type": mime, "Cache-Control": "public, max-age=3600" });
    res.end(fs.readFileSync(real));
    return true;
  }

  return { handle };
}

module.exports = { createStaticRouter };
