'use strict';
const {scalar,toNumber,fields,field,entries,finding,unknown}=require('./helpers');
const {text,get,name,number,threshold,rows,state,listResult,disabled,define}=require('./device-checks');
function ruleHits(data){return listResult('rule_hits (vsys1)',data.rule_hits,rows(data.rule_hits,['hit-count','count']).map(entry=>{
 const metric=`rule vsys1 ${name(entry)}`,count=number(entry,['hit-count','count']);
 if(count===null||count<0)return unknown(metric);
 const high=count>10000&&/deny|default/i.test(name(entry));
 return finding(metric,count,'hits',high?'warning':'info',`仅 vsys1 安全规则；累计命中 ${count} 次。${high?'名称疑似默认拒绝规则，需核对策略用途；不能推断当前攻击。':count===0?'零命中需结合统计周期核对，不能直接认定可删除。':'无基线，不推断命中变化。'}`,high?'核对规则条件、用途与命中日志':'',{window:'cumulative'});
}));}
function zones(data){
 const source=data.zone_protection;
 const protocols=['tcp-syn','udp','icmp','icmpv6','other-ip'];
 const actual=entries(source).filter(entry=>Object.hasOwn(entry,'zone'));
 if(actual.length)return actual.flatMap(entry=>{
  const result=[],prefix=`zone ${text(entry.vsys)} ${text(entry.zone)}`;
  for(const protocol of protocols){
   if(!Object.hasOwn(entry,protocol))continue;
   const sample=entry[protocol],current=number(sample,['current']),alarm=number(sample,['alarm']),maximum=number(sample,['maximum']);
   const metric=`${prefix} ${protocol} current`;
   result.push(current===null||current<0||alarm===null||alarm<0||maximum===null||maximum<=0||alarm>maximum?unknown(metric):finding(metric,current,'packets/s',threshold(current,alarm,maximum),`设备防护阈值：alarm ${alarm}，maximum ${maximum}；当前值 ${current}`,current>=alarm?'核对流量与防护阈值；阈值触发本身不证明攻击':''));
   if(field(sample,['stats'])!==undefined){const count=number(sample,['stats']);result.push(count===null||count<0?unknown(`${prefix} ${protocol} stats`):finding(`${prefix} ${protocol} stats`,count,'count','info','协议防护累计统计；不推断当前事件','',{window:'cumulative'}));}
  }
  for(const [key,raw] of Object.entries(entry))if(/(?:_pkt_drop|-drops)$/.test(key)){
   const count=toNumber(raw),metric=`${prefix} ${key}`;
   result.push(count===null||count<0?unknown(metric):finding(metric,count,'drops','info','防护累计丢包计数；不能据此判断正在遭受攻击','',{window:'cumulative'}));
  }
  return result.length?result:[unknown(prefix)];
 });
 return listResult('zone_protection',source,rows(source,['dp','dp-drops','pb','pb-drops']).filter(entry=>!/^dp\d+$/.test(text(entry.dp))).flatMap(entry=>{
 return [['DDoS',['dp','dp-drops']],['packet-buffer',['pb','pb-drops']]].map(([label,keys])=>{const value=number(entry,keys),metric=`zone ${name(entry)} ${label}`;return value===null||value<0?unknown(metric):finding(metric,value,'drops','info',value>0?'观察到防护丢包累计值；需核对发生时间和预期策略，不能据此判断正在遭受攻击':'采样防护丢包计数为零',value>0?'核对防护日志、策略阈值及后续计数变化':'',{window:'cumulative'});});
}));}
function decryption(data){return listResult('decryption',data.decryption,rows(data.decryption,['hit-count','count','status','certificate-status']).flatMap(entry=>{
 const result=[],metric=`decryption ${name(entry)}`;
 if(field(entry,['hit-count','count'])!==undefined){const count=number(entry,['hit-count','count']);result.push(count===null||count<0?unknown(metric):finding(`${metric} hits`,count,'hits',count===0?'warning':'info',count===0?'解密规则累计零命中；需结合用途与统计周期核对':'观察到解密规则累计命中',count===0?'核对解密规则匹配条件':'',{window:'cumulative'}));}
 if(field(entry,['status','certificate-status'])!==undefined)result.push(state(`${metric} certificate`,field(entry,['certificate-status','status']),['ok','valid','active'],['invalid','expired','broken','failed','chain-error'],'warning'));
 return result.length?result:[unknown(metric)];
}));}
function threats(data){
 const source=data.threat_logs,window=source?.window;
 const count=toNumber(source?.count);
 if(!window||window.clock!=='device'||!window.start||!window.end||!Number.isInteger(window.minutes)||window.minutes<1||window.minutes>60||window.limit!==1000||typeof window.complete!=='boolean'||count===null||!Number.isInteger(count)||count<0||count>1000)return [unknown('threat-events')];
 const complete=window.complete&&count<window.limit;
 const result=[finding('threat-events',count,'events',threshold(count,50,200),`${window.start} 至 ${window.end}（设备时间，${window.minutes} 分钟），${complete?'观察到':'至少观察到'} ${count} 条威胁日志；读取上限 ${window.limit}`,count>=50?'核对威胁类型、受影响对象和处置结果':'',{window:{...window,complete}})];
 if(!complete)result.push(finding('threat-window-coverage',null,'','unknown','威胁时间窗口覆盖不完整；计数仅为已观察下限，不能声称完整窗口无其他事件','缩小窗口或在日志查询中进一步核对',{window:{...window,complete:false}}));
 return result;
}
function haDiagnostics(data){
 const off=disabled('ha_diagnostics',data.ha_all);if(off)return off;
 const result=[];
 const enabled=get(data.ha_all,['enabled']);
 if(!['yes','true','enabled'].includes(enabled))result.push(unknown('HA enabled'));
 else result.push(finding('HA enabled',true,'','info','HA 已开启'));
 const syncState=field(data.ha_all,['running-sync','config-sync','synchronization']);
 result.push(state('HA config sync',syncState,['synchronized','complete','yes'],['not synchronized','out-of-sync','no'],'warning'));
 for(const id of ['ha_link','ha_path']){
  result.push(...(disabled(id,data[id])||listResult(id,data[id],rows(data[id],['state','status']).map(entry=>state(`${id} ${name(entry)}`,field(entry,['state','status']),['up','ok','success','normal'],['down','failed','failure','error'])))));
 }
 const sent=number(data.ha_sync,['sent']),received=number(data.ha_sync,['received','recv']);
 result.push(sent===null||sent<0||received===null||received<0?unknown('HA state sync'):finding('HA state sync',`${sent}/${received}`,'sent/received',sent===0&&received===0?'warning':'info',sent===0&&received===0?'状态同步累计收发均为零；需结合设备角色、业务与运行时间核对':'观察到状态同步累计计数；单次采样不能证明同步持续正常','结合 HA2 链路和后续采样核对',{window:'cumulative'}));
 const flaps=number(data.ha_flaps,['flaps','count']);
 result.push(flaps===null||flaps<0?unknown('HA flaps'):finding('HA flaps',flaps,'flaps',flaps>5?'warning':'ok','HA 状态切换累计次数',flaps>5?'核对计划维护与 HA 链路稳定性':'',{window:'cumulative'}));
 return result;
}
function jobs(data){
 const source=data.jobs&&Object.hasOwn(data.jobs,'job')?{entry:data.jobs.job}:data.jobs;
 return listResult('jobs',source,rows(source,['status','result']).map(entry=>{
 const status=get(entry,['status']),result=get(entry,['result']),metric=`job ${name(entry)}`;
 if(['fail','failed','error'].includes(result)||['fail','failed','error'].includes(status))return finding(metric,`${status}/${result}`,'','warning','任务执行失败；FIN 仅表示已结束，不代表成功','检查任务详细结果与配置验证错误');
 if(status==='fin'&&result==='ok')return finding(metric,'FIN/OK','','ok','任务已完成且结果成功');
 if(['act','active','pend','pending','running'].includes(status))return finding(metric,status,'','info','任务正在执行或等待；单次采样无法判断积压时间');
 return unknown(metric);
}));}
function edl(data,context){return listResult('edl (IP)',data.edl,rows(data.edl,['count','entries','status','last-refresh','last-update']).flatMap(entry=>{
 const metric=`EDL IP ${name(entry)}`,count=number(entry,['count','entries']);
 const result=[count===null||count<0?unknown(metric):finding(metric,count,'entries',count===0?'warning':'ok',`仅 IP 类型动态列表；当前条目 ${count}`,count===0?'核对列表获取状态及内容':'')];
 const status=field(entry,['status']);if(status!==undefined)result.push(state(`${metric} refresh`,status,['success','ok','valid'],['failed','error','invalid'],'warning'));
 const refresh=text(field(entry,['last-refresh','last-update','refresh-time']));
 if(refresh){
  // A timestamp without a zone cannot be compared safely with the host clock.
  const timestamp=/T.*(?:Z|[+-]\d\d:\d\d)$/.test(refresh)?Date.parse(refresh):NaN;
  const now=new Date(context.now??Date.now()).getTime();
  if(!Number.isFinite(timestamp)||!Number.isFinite(now)||timestamp>now)result.push(unknown(`${metric} refresh age`));
  else {const hours=(now-timestamp)/3600000;result.push(finding(`${metric} refresh age`,Math.floor(hours),'hours',hours>24?'warning':'ok','距离最近一次刷新时间',hours>24?'核对刷新周期及列表服务器状态':''));}
 }
 return result;
}));}
function fqdn(data){
 let source=data.fqdn;
 if(typeof source==='string'){
  const blocks=[];let block;
  for(const line of source.split('\n')){
   if(/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]*\.?$/.test(line)){
    block={name:line};blocks.push(block);
   }else if(block&&/^\s+\S/.test(line)){
    (block.ip??=[]).push(line.trim());
   }else if(line.trim())block=undefined;
  }
  source={entry:blocks};
  if(!blocks.length)return [unknown('fqdn')];
 }
 return listResult('fqdn',source,rows(source,['fqdn','name','@_name','ip','resolved-ip','status']).map(entry=>{
 const metric=`FQDN ${name(entry)}`;
 const raw=fields(entry,['ip','resolved-ip']);
 if(!raw.length){const status=get(entry,['status']);return ['unresolved','failed'].includes(status)?finding(metric,'unresolved','','warning','域名对象解析失败','核对 DNS 服务器和域名状态'):unknown(metric);}
 const values=raw.flatMap(value=>Array.isArray(value)?value:[value]);
 if(values.some(value=>typeof scalar(value)!=='string'))return unknown(metric);
 const ips=values.map(text).filter(Boolean);
 if(!ips.length)return finding(metric,0,'addresses','warning','已返回解析字段，但没有解析地址','核对 DNS 服务器和域名状态');
 const {isIP}=require('node:net');
 if(ips.some(ip=>!isIP(ip)))return unknown(metric);
 return finding(metric,ips.length,'addresses','ok','域名对象具有有效解析地址');
}));}
const securityChecks=define([
 ['rule_hits','security_policy','安全规则命中（vsys1）',['rule_hits'],ruleHits],
 ['zone_protection','security_policy','区域防护',['zone_protection'],zones],
 ['decryption','security_policy','SSL 解密',['decryption'],decryption],
 ['threat_logs','security_policy','威胁日志窗口',['threat_logs'],threats],
 ['ha_diagnostics','high_availability','HA 深度诊断',['ha_all','ha_link','ha_path','ha_sync','ha_flaps'],haDiagnostics],
 ['jobs','high_availability','提交与后台任务',['jobs'],jobs],
 ['edl','license_subscription','外部动态 IP 列表',['edl'],edl],
 ['fqdn','license_subscription','FQDN 对象解析',['fqdn'],fqdn]
]);
module.exports={securityChecks};
