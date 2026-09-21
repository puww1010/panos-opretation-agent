'use strict';
const { scalar, toNumber, fields, field, entries, finding, unknown } = require('./helpers');
const text = value => String(scalar(value) ?? '').trim();
const get = (value, keys) => text(field(value, keys)).toLowerCase();
const name = value => text(value?.['@_name']) || text(field(value, ['name','interface','application','peer','neighbor','id'])) || '未命名';
const number = (value, keys) => toNumber(field(value, keys));
const threshold = (value, warn, crit) => value >= crit ? 'critical' : value >= warn ? 'warning' : 'ok';
const empty = source => fields(source, 'entry').some(value => Array.isArray(value) && value.length === 0 || value === '');
const rows = (source, keys) => entries(source).filter(value => {
 const identity=['name','@_name'];
 const knownMetric=keys.some(key=>!identity.includes(key)&&Object.hasOwn(value,key));
 return knownMetric || identity.some(key=>Object.hasOwn(value,key)) && fields(value,'entry').length===0;
});
function state(metric, raw, good = ['up','active','ok','running','connected'], bad = ['down','failed','fail','error','stopped','not running','not-connected'], severity = 'critical') {
 const value = text(raw).toLowerCase();
 if (!good.includes(value) && !bad.includes(value)) return unknown(metric);
 return finding(metric,value,'',good.includes(value)?'ok':severity,`${metric}：${value}`,good.includes(value)?'':'核对组件状态及相关事件');
}
function listResult(id, source, result) {
 return result.length ? result : empty(source) ? [finding(id,0,'entries','info','本次查询未返回条目；不据此推断功能关闭或异常')] : [unknown(id)];
}
function disabled(id, source) {
 return ['no','false','disabled'].includes(get(source,['enabled'])) ? [finding(id,false,'','info','设备明确报告此功能关闭','',{applicability:'not_applicable'})] : null;
}
function define(definitions) {
 return definitions.map(([id,category,label,sources,evaluate])=>({id,category,label,sources,evaluate(data={},context={}) {
  const result=evaluate(data,context);
  if(result.length<=100)return result;
  const rank={critical:0,warning:1,unknown:2,info:3,ok:4};
  return [...result.sort((a,b)=>rank[a.severity]-rank[b.severity]).slice(0,99),finding('finding-limit',result.length,'findings','unknown','结果条目超过 100，已优先保留风险；展示不完整')];
 }}));
}
function storage(id, data) {
 const source=data[id];
 if(id==='logdb_quota'&&typeof source==='string'&&/^Quotas:\s*$/m.test(source)){
  const result=[];let inQuotas=false;
  for(const line of source.split('\n')){
   if(/^Quotas:\s*$/.test(line)){inQuotas=true;continue;}
   if(!inQuotas)continue;
   const match=line.match(/^\s+([\w-]+):\s+(\d+(?:\.\d+)?)%,\s+\d+(?:\.\d+)?\s+(?:KB|MB|GB|TB)\s+Expiration-period:/);
   if(match&&Number(match[2])<=100)result.push(finding(`logdb allocation ${match[1]}`,Number(match[2]),'%','info',`${match[1]} 日志配额分配比例 ${match[2]}%；此值不是已用空间比例`,'',{plane:'MP'}));
   else if(line.trim())inQuotas=false;
  }
  return [...result,unknown('logdb actual utilization',{plane:'MP'})];
 }
 let partitions=rows(source,['percent','usage','used','quota','total']);
 if(id==='disk_space'&&typeof source==='string') partitions=source.split('\n').flatMap(line=>{const match=line.match(/^\S+\s+\S+\s+\S+\s+\S+\s+(\d+(?:\.\d+)?)%\s+(.+)$/);return match?[{name:match[2],percent:match[1]}]:[];});
 return listResult(id,source,partitions.map(entry=>{
  const metric=`${id} ${name(entry)}`;
  let pct=toNumber(text(field(entry,['percent','usage'])).replace(/%$/,''));
  if(pct===null){const used=number(entry,['used']),total=number(entry,id==='logdb_quota'?['quota','total']:['total','size']);if(used!==null&&used>=0&&total>0)pct=used/total*100;}
  if(pct===null||pct<0||pct>100)return unknown(metric);
  return finding(metric,pct,'%',threshold(pct,80,id==='disk_space'?95:90),`${metric} 已使用 ${pct}%`,pct>=80?'核对日志保留、配额与磁盘容量':'',{plane:'MP'});
 }));
}
function software(data){
 const source=data.software_status;
 let processes=rows(source,['status','state']);
 if(typeof source==='string') processes=source.split('\n').flatMap(line=>{const match=line.match(/^\s*Process\s+(\S+)\s+(not running|running|stopped|failed|starting)(?:\s|$)/i);return match?[{name:match[1],status:match[2]}]:[];});
 return listResult('software_status',source,processes.map(entry=>state(`process ${name(entry)}`,field(entry,['status','state']))));
}
function counters(data){return listResult('global_counters',data.global_counters,rows(data.global_counters,['value','count']).map(entry=>{
 const value=number(entry,['value','count']),metric=`counter ${name(entry)}`;
 return value===null||value<0?unknown(metric):finding(metric,value,'packets','info','累计丢包计数；delta=no，缺少时间基线，不能判断当前丢包速率','结合后续采样与流量背景评估',{plane:'DP',window:'cumulative'});
}));}
function apps(data){return listResult('app_stats',data.app_stats,rows(data.app_stats,['sessions','count','bytes','byt','packets']).flatMap(entry=>{
 const result=[['sessions',['sessions','count']],['bytes',['bytes','byt']],['packets',['packets']]].filter(([,keys])=>field(entry,keys)!==undefined).map(([unit,keys])=>{const value=number(entry,keys),metric=`app ${name(entry)} ${unit}`;return value===null||value<0?unknown(metric):finding(metric,value,unit,'info','应用统计采样；无历史基线，不推断异常流量');});
 return result.length?result:[unknown(`app ${name(entry)}`)];
}));}
function discard(data){
 const source=data.discard_sessions;
 let count=number(source,['count','total-count']);
 if(count===null && (empty(source)||rows(source,['id','state','application']).length))count=rows(source,['id','state','application']).length;
 return [count===null||count<0||!Number.isInteger(count)?unknown('discard-sessions'):finding('discard-sessions',count,'sessions',threshold(count,10,100),`本次查询观察到 ${count} 个丢弃状态会话；列表可能受设备返回上限限制`,count>=10?'核对拒绝策略和业务流量':'')];
}
const deviceChecks=define([
 ['disk_space','device_health','磁盘空间',['disk_space'],data=>storage('disk_space',data)],
 ['logdb_quota','device_health','日志数据库配额',['logdb_quota'],data=>storage('logdb_quota',data)],
 ['software_status','device_health','软件进程状态',['software_status'],software],
 ['global_counters','resource_performance','全局丢包累计计数',['global_counters'],counters],
 ['app_stats','resource_performance','应用统计',['app_stats'],apps],
 ['discard_sessions','resource_performance','丢弃会话',['discard_sessions'],discard]
]);
module.exports={deviceChecks, text,get,name,number,threshold,empty,rows,state,listResult,disabled,define};
