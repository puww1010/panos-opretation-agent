const { renderMonitorReport, styles } = require("../../assets/monitor-ui");
const { sanitize } = require("./service");

function exportMonitorReport(taskId, report, format = "json") {
  if (!["json", "html"].includes(format)) throw new Error("报告格式仅支持 json 或 html");
  const safe = sanitize(report);
  const filename = "panos-monitor-task-" + Number(taskId) + "." + format;
  if (format === "json") return { filename, mime: "application/json;charset=utf-8", content: JSON.stringify(safe, null, 2) };
  return { filename, mime: "text/html;charset=utf-8", content: '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>防火墙深度健康巡检报告</title><style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 20px;color:#24324a;background:#f8fafc}' + styles + '</style></head><body>' + renderMonitorReport(taskId, safe, { controls: false }) + '</body></html>' };
}

module.exports = { exportMonitorReport };
