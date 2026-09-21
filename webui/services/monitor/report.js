const { renderMonitorReport, styles } = require("../../assets/monitor-ui");
const { sanitize } = require("./service");

function exportMonitorReport(taskId, report, format = "json") {
  if (!["json", "html"].includes(format)) throw new Error("报告格式仅支持 json 或 html");
  const safe = sanitize(report);
  const filename = "panos-monitor-task-" + Number(taskId) + "." + format;
  if (format === "json") return { filename, mime: "application/json;charset=utf-8", content: JSON.stringify(safe, null, 2) };
  return { filename, mime: "text/html;charset=utf-8", content: '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>防火墙深度健康巡检报告</title><style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 20px;color:#24324a;background:#f8fafc}' + styles + '</style></head><body>' + renderMonitorReport(taskId, safe, { controls: false }) + '</body></html>' };
}

function formatMonitorNotification(taskId, report) {
  const safe = sanitize(report);
  const status = { completed: "完成", partial: "部分完成", cancelled: "已取消", failed: "失败" };
  const severity = { critical: "严重", warning: "警告", unknown: "未知", info: "信息", ok: "正常" };
  const c = safe.coverage || {};
  const lines = [
    `【深度健康巡检 #${Number(taskId)}】`,
    `设备：${String(safe.firewall || "未知").slice(0, 120)}`,
    `开始：${safe.startedAt || "未知"}；结束：${safe.finishedAt || "未知"}`,
    `结果：${status[safe.executionStatus] || "未知"}；风险：${severity[safe.overallSeverity] || "未知"}`,
    `覆盖率 ${c.percent ?? "未知"}%（不是健康得分）；共 ${c.total ?? "未知"} 项`,
    `有效 ${c.valid ?? 0}，部分 ${c.partial ?? 0}，不适用 ${c.not_applicable ?? 0}，不支持 ${c.unsupported ?? 0}，未知 ${c.unknown ?? 0}，错误 ${c.error ?? 0}，未执行 ${c.not_run ?? 0}`,
    `日志请求窗口：${safe.minutes ?? "未知"} 分钟；其他指标按各自采样口径。`,
  ];
  const rank = { critical: 0, warning: 1, unknown: 2, info: 3, ok: 4 };
  const findings = (safe.checks || []).flatMap(check => (check.findings || []).map(finding => ({ label: check.label, ...finding }))).sort((a, b) => (rank[a.severity] ?? 2) - (rank[b.severity] ?? 2));
  for (const item of findings.slice(0, 10)) lines.push(`· [${severity[item.severity] || "未知"}] ${String(item.label || item.metric || "检查").slice(0, 80)}：${String(item.message || "无说明").slice(0, 220)}`);
  const shortened = findings.length > 10 || findings.slice(0, 10).some(item => String(item.message || "").length > 220 || String(item.label || item.metric || "").length > 80);
  if (shortened) lines.push(`摘要已省略部分明细（共 ${findings.length} 条判断）；请查看完整报告。`);
  lines.push(`此摘要与任务 #${Number(taskId)} 的 JSON / HTML 导出使用同一份已保存报告；请在控制台查看全部证据和覆盖缺口。`);
  return lines.join("\n");
}

module.exports = { exportMonitorReport, formatMonitorNotification };
