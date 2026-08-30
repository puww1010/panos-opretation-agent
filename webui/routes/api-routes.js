function createApiRouter({ dashboardService }) {
  async function handleDashboard(req, send) {
    if (req.method === "GET" && req.url === "/api/overview") { send(200, await dashboardService.getOverview()); return true; }
    if (req.method === "GET" && req.url === "/api/topology") { send(200, await dashboardService.getTopology()); return true; }
    if (req.method === "GET" && req.url.startsWith("/api/metrics")) {
      const url = new URL(req.url, "http://localhost");
      const minutes = Math.max(1, Math.min(1440, parseInt(url.searchParams.get("minutes") || "120", 10) || 120));
      send(200, dashboardService.getMetrics(minutes));
      return true;
    }
    if (req.method === "GET" && req.url === "/api/history") { send(200, { history: dashboardService.getHistory() }); return true; }
    return false;
  }
  return { handleDashboard };
}

module.exports = { createApiRouter };
