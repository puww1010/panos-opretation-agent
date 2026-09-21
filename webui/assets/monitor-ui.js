(function (root) {
  const statusLabels = { completed: "完成", partial: "部分完成", failed: "失败", cancelled: "已取消", running: "运行中", ok: "正常", info: "信息", warning: "告警", critical: "严重", unknown: "未知", error: "采集失败", unsupported: "暂不支持", not_applicable: "不适用", not_run: "未执行" };
  const esc = (value) => String(value ?? "—").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
  const label = (value) => statusLabels[value] || "未知";
  const styles = `.mon-report{font-size:13px;line-height:1.65;overflow-wrap:anywhere}.mon-report h3{margin:0 0 8px}.mon-meta{color:var(--muted,#64748b);font-size:12px}.mon-metrics{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}.mon-metric{flex:1;min-width:105px;border:1px solid var(--border,#dbe3ef);border-radius:9px;padding:10px;background:var(--panel-bg,#f8fafc)}.mon-metric strong{display:block;font-size:19px}.mon-note{padding:10px 12px;border-left:3px solid #e7aa31;background:var(--warn-bg2,#fff8e8);color:var(--text,#334155);margin:10px 0}.mon-report details{border:1px solid var(--border,#dbe3ef);border-radius:9px;padding:10px;margin-top:9px}.mon-report summary{cursor:pointer;font-weight:600;display:list-item}.mon-badge{display:inline-block;border-radius:5px;padding:1px 7px;margin:0 4px;font-size:11px;background:#e8eef7;color:#475569}.mon-warning{background:#fff0cc;color:#895500}.mon-critical,.mon-error{background:#fee2e2;color:#a71919}.mon-ok{background:#dcfce7;color:#166534}.mon-findings{display:grid;gap:8px;margin:10px 0}.mon-finding{border-left:3px solid var(--border,#cbd5e1);padding:4px 10px}.mon-finding p{margin:3px 0}.mon-report pre{max-height:260px;overflow:auto;white-space:pre-wrap;font-size:11px;background:var(--raw-bg,#f1f5f9);padding:10px;border-radius:5px}.mon-actions{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.mon-actions button{padding:7px 12px;border-radius:7px;border:1px solid var(--border,#cbd5e1);color:var(--accent,#2563eb);background:var(--panel-bg,#fff);cursor:pointer}.mon-progress{width:100%;accent-color:#2563eb}@media(max-width:600px){.mon-metric{min-width:90px}.mon-report details{padding:8px}.mon-actions button{flex:1}}`;
  const badge = (value) => '<span class="mon-badge mon-' + (Object.hasOwn(statusLabels, value) ? value : "unknown") + '">' + label(value) + '</span>';

  function renderMonitorReport(taskId, report, { controls = true } = {}) {
    const coverage = report.coverage || {};
    const grouped = new Map();
    for (const check of report.checks || []) {
      if (!grouped.has(check.category)) grouped.set(check.category, []);
      grouped.get(check.category).push(check);
    }
    const severityRank = { critical: 0, warning: 1, unknown: 2, info: 3, ok: 4 };
    let html = '<section class="mon-report"><h3>深度健康巡检 ' + badge(report.executionStatus) + '</h3>' +
      '<div class="mon-meta">只读采集 · 确定性规则判定 · ' + esc(report.firewall) + ' · ' + esc(report.finishedAt || report.startedAt) + '</div>' +
      '<div class="mon-metrics"><div class="mon-metric">健康结论<strong>' + badge(report.overallSeverity) + '</strong></div>' +
      '<div class="mon-metric">检查覆盖率<strong>' + esc(coverage.percent ?? 0) + '%</strong></div>' +
      '<div class="mon-metric">有效检查<strong>' + esc(coverage.valid ?? 0) + ' / ' + esc(coverage.total ?? 0) + '</strong></div>' +
      '<div class="mon-metric">不适用<strong>' + esc(coverage.not_applicable ?? 0) + '</strong></div></div>' +
      '<div class="mon-meta">部分 ' + esc(coverage.partial ?? 0) + ' · 失败 ' + esc(coverage.error ?? 0) + ' · 不支持 ' + esc(coverage.unsupported ?? 0) + ' · 未知 ' + esc(coverage.unknown ?? 0) + ' · 未执行 ' + esc(coverage.not_run ?? 0) + '</div>';
    if (report.executionStatus !== "completed" || report.overallSeverity === "unknown") html += '<div class="mon-note">本次证据不完整，不代表全部正常。请查看未覆盖检查的具体原因；采集失败与健康告警分别统计。</div>';
    html += '<div class="mon-meta">覆盖率 =（有效检查 + 明确不适用）/ 所选检查；日志窗口 ' + esc(report.minutes) + ' 分钟，具体采样范围以该项证据为准。证据为脱敏限量预览，不是完整配置备份。</div>';
    if (controls && Number.isSafeInteger(Number(taskId))) html += '<div class="mon-actions"><button onclick="downloadMonitorReport(' + Number(taskId) + ',\'json\')">导出 JSON</button><button onclick="downloadMonitorReport(' + Number(taskId) + ',\'html\')">下载中文报告</button><button onclick="pushMonitorReport(' + Number(taskId) + ')">推送此报告到飞书</button></div>';
    for (const [category, checks] of grouped) {
      const important = checks.some((check) => ["warning", "critical"].includes(check.severity));
      html += '<details data-monitor-key="' + esc(taskId + ':' + category) + '"' + (important ? " open" : "") + '><summary>' + esc(checks[0].categoryLabel || category) + ' · ' + checks.length + ' 项</summary>';
      for (const check of [...checks].sort((a, b) => (severityRank[a.severity] ?? 2) - (severityRank[b.severity] ?? 2))) {
        html += '<details data-monitor-key="' + esc(taskId + ':' + check.id) + '"><summary>' + esc(check.label) + ' ' + (check.collection === "ok" ? '<span class="mon-badge">采集完整</span>' : badge(check.collection)) + badge(check.severity) + '</summary><div class="mon-findings">';
        for (const finding of check.findings || []) {
          const value = finding.value !== undefined && finding.value !== null ? esc(finding.value) + " " + esc(finding.unit || "") : "—";
          html += '<div class="mon-finding"><strong>' + esc(finding.metric) + '</strong> ' + badge(finding.severity) + '<p>' + value + '</p><p>' + esc(finding.message || "") + '</p>' +
            (finding.recommendation ? '<p class="mon-meta">建议：' + esc(finding.recommendation) + '</p>' : "") +
            (finding.plane || finding.window ? '<div class="mon-meta">' + esc(finding.plane || "") + ' · ' + esc(typeof finding.window === "object" ? JSON.stringify(finding.window) : finding.window || "") + '</div>' : "") + '</div>';
        }
        html += '</div><div class="mon-meta">采集时间 ' + esc(check.observedAt) + ' · 耗时 ' + esc(check.durationMs ?? 0) + ' ms</div><details data-monitor-key="' + esc(taskId + ':' + check.id + ':evidence') + '"><summary>查看采集来源与证据</summary><pre>' + esc(JSON.stringify({ sources: check.sources, evidence: check.evidence }, null, 2)) + '</pre></details></details>';
      }
      html += '</details>';
    }
    return html + '<div class="mon-meta" style="margin-top:12px">规则来源 panos-monitor · ' + esc(String(report.skillRevision || "").slice(0, 7)) + ' · 原生适配报告 v' + esc(report.schemaVersion) + '</div></section>';
  }

  const reportLayout = '.monitor-message .msg-bubble{flex:1;max-width:calc(100% - 44px);min-width:0}@media(max-width:600px){.monitor-message .msg-avatar{display:none}.monitor-message .msg-bubble{max-width:100%;padding:10px;box-sizing:border-box}}';
  const api = { renderMonitorReport, styles: styles + reportLayout };
  if (typeof module === "object" && module.exports) module.exports = api;
  else {
    root.MonitorUI = api;
    const style = document.createElement("style"); style.textContent = api.styles; document.head.appendChild(style);
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
