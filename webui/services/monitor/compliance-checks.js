'use strict';
const { scalar, toNumber, fields, finding, unknown } = require('./helpers');
const { text, name, define } = require('./device-checks');
const { deviceLogWindow } = require('./sources');

function members(value) {
  const raw = value?.member;
  const values = (Array.isArray(raw) ? raw : [raw]).map(scalar);
  return values.length && values.every(item => typeof item === 'string' && item.trim()) ? values.map(item => item.trim()) : null;
}

function policyHygiene(data) {
  const source = data.security_rules;
  const raw = source?.rules?.entry ?? source?.entry;
  const rules = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];
  if (!rules.length) return [unknown('policy vsys1 candidate rules')];
  return rules.map(rule => {
    const metric = `policy vsys1 ${name(rule)}`, disabled = text(rule?.disabled).toLowerCase();
    if (['yes', 'true'].includes(disabled)) return finding(metric, 'disabled', '', 'info', 'vsys1 候选配置：规则已明确停用，不评估其放行范围');
    if (!['no', 'false'].includes(disabled)) return unknown(metric);
    const action = text(rule?.action).toLowerCase();
    if (['deny', 'drop', 'reset-client', 'reset-server', 'reset-both'].includes(action)) return finding(metric, action, '', 'info', 'vsys1 候选配置：规则为拒绝动作，不属于 allow-any-any 检查对象');
    if (action !== 'allow') return unknown(metric);
    const sourceMembers = members(rule?.source), destinationMembers = members(rule?.destination);
    if (!sourceMembers || !destinationMembers) return unknown(metric);
    const broad = sourceMembers.includes('any') && destinationMembers.includes('any');
    return finding(metric, broad ? 'allow-any-any' : 'scoped', '', broad ? 'warning' : 'ok', broad
      ? 'vsys1 候选配置：启用的 allow 规则源与目的均为 any；需结合区域、应用、服务和业务用途评估范围'
      : 'vsys1 候选配置：该规则的源与目的并非同时为 any；此项不证明完整最小权限或已提交配置合规',
    broad ? '核对业务所需的源、目的、区域、应用和服务，评估收敛范围' : '');
  });
}

function wildfire(data) {
  const source = data.wildfire;
  const entries = fields(source, 'entry').flatMap(value => Array.isArray(value) ? value : [value]).filter(entry => !fields(entry, 'entry').length);
  const globalDisabled = ['no', 'false', 'disabled'].includes(text(source?.enabled).toLowerCase());
  const scopes = entries.length && !globalDisabled ? entries : [source];
  return scopes.flatMap(scope => {
    const metric = `WildFire connection${scope === source ? '' : ` ${name(scope)}`}`;
    const enabled = fields(scope, 'enabled').map(value => text(value).toLowerCase());
    const raw = typeof scope === 'string' ? scope : scope?.raw;
    if (enabled.some(value => ['no', 'false', 'disabled'].includes(value)) || typeof raw === 'string' && /^\s*Disabled due to configuration\s*$/im.test(raw)) {
      return [finding(metric, 'disabled', '', 'warning', '设备明确报告此 WildFire 范围已关闭', '核对威胁防护设计与 WildFire 配置')];
    }
    const statuses = typeof raw === 'string'
      ? [...raw.matchAll(/^[ \t]*(?:WildFire[ \t]+)?Connection status:[ \t]*([^\r\n]+)$/gim)].map(match => match[1].trim().toLowerCase())
      : fields(scope, ['connection-status', 'connection', 'status']).map(value => text(value).toLowerCase());
    return statuses.length ? statuses.map(status => ['connected', 'disconnected', 'disabled'].includes(status)
      ? finding(metric, status, '', status === 'connected' ? 'ok' : 'warning', `WildFire 云连接采样状态：${status}；连接状态不证明策略已绑定或文件已送检`, status === 'connected' ? '' : '核对 WildFire 云连接、许可和配置')
      : unknown(metric)) : [unknown(metric)];
  });
}

function contentVersions(data) {
  const result = [];
  for (const key of ['version', 'app-version', 'av-version', 'threat-version', 'wildfire-version']) {
    for (const raw of fields(data.content_versions, key)) {
      const value = scalar(raw);
      result.push(typeof value === 'string' && /^\d+(?:[.-]\d+)*$/.test(value.trim())
        ? finding(`content ${key}`, value.trim(), '', 'info', '仅记录设备返回的内容版本；可用版本列表不等于已安装或最新版本')
        : unknown(`content ${key}`));
    }
  }
  if (!result.length) result.push(unknown('content versions'));
  result.push(finding('content freshness', null, '', 'unknown', '未验证已安装版本、最新版本与发布时间的完整基准，无法判断内容库是否最新', '核对设备已安装版本、最新可用版本与发布时间'));
  return result;
}

function logObservation(id, source) {
  const window = source?.window, count = toNumber(source?.count);
  let expected;
  try { expected = deviceLogWindow(window?.end, window?.minutes); } catch { return [unknown(`${id} events`)]; }
  if (window.clock !== 'device' || window.start !== expected.start || window.end !== expected.end || window.limit !== 1000 || typeof window.complete !== 'boolean' || count === null || !Number.isInteger(count) || count < 0 || count > 1000) return [unknown(`${id} events`)];
  const complete = window.complete && count < window.limit;
  const metadata = { window: { ...window, complete } };
  const result = [finding(`${id} events`, count, 'events', count ? 'info' : 'unknown', count
    ? `${window.start} 至 ${window.end}（设备时间，${window.minutes} 分钟），${complete ? '观察到' : '至少观察到'} ${count} 条${id === 'traffic_logs' ? '流量' : '威胁'}日志；读取上限 1000`
    : `${window.start} 至 ${window.end}（设备时间）未观察到日志；无法区分无匹配事件、未开启记录与日志链路异常`, count ? '' : '结合流量、日志配置与采集权限核对', metadata)];
  if (!complete) result.push(finding(`${id} coverage`, null, '', 'unknown', '日志窗口覆盖不完整，计数仅为已观察下限', '缩小时间窗口并核对日志查询', metadata));
  return result;
}

function loggingHealth(data) {
  return [...logObservation('traffic_logs', data.traffic_logs), ...logObservation('threat_logs', data.threat_logs),
    finding('logging continuity', null, '', 'unknown', '单次窗口查询不能证明日志端到端持续完整或无中断', '结合连续采样、日志生成与转发状态验证完整性')];
}

const complianceChecks = define([
  ['policy_hygiene', 'security_policy', '策略最小权限（vsys1）', ['security_rules'], policyHygiene],
  ['wildfire', 'security_policy', 'WildFire 连接状态', ['wildfire'], wildfire],
  ['content_versions', 'license_subscription', '内容库版本', ['content_versions'], contentVersions],
  ['logging_health', 'device_health', '日志链路观察', ['traffic_logs', 'threat_logs'], loggingHealth],
]);

module.exports = { complianceChecks };
