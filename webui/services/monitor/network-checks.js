'use strict';
const { toNumber,fields,field,finding,unknown }=require('./helpers');
const {text,get,name,number,threshold,empty,rows,state,listResult,disabled,define}=require('./device-checks');
function transceivers(data){return listResult('transceivers',data.transceivers,rows(data.transceivers,['vendor','vendor-name','status','alarm']).flatMap(entry=>{
 const metric=`transceiver ${name(entry)}`,result=[];
 const vendor=text(field(entry,['vendor','vendor-name']));
 if(vendor)result.push(finding(`${metric} vendor`,vendor,'',/unknown/i.test(vendor)?'warning':'info',/unknown/i.test(vendor)?'模块厂商无法识别，请核对兼容性':'已识别模块厂商；光功率和温度需结合设备阈值判断'));
 if(field(entry,['status'])!==undefined)result.push(state(metric,field(entry,['status']),['ok','normal','up'],['failed','fault','down']));
 const alarm=get(entry,['alarm']);
 if(['true','yes','1'].includes(alarm))result.push(finding(`${metric} alarm`,true,'','critical','光模块报告告警','检查模块温度、光功率和链路'));
 else if(['false','no','0'].includes(alarm))result.push(finding(`${metric} alarm`,false,'','ok','光模块未报告告警'));
 return result.length?result:[unknown(metric)];
}));}
function routing(data){
 const result=listResult('routes',data.routing,rows(data.routing,['destination','destination-prefix','flags']).length?[finding('routes',rows(data.routing,['destination','destination-prefix','flags']).length,'routes','info','本次查询返回的路由条目数；不推断路由可达性')]:[]);
 for(const protocol of ['bgp','ospf']){
  const source=data[protocol],off=disabled(protocol,source);
  result.push(...(off||listResult(protocol,source,rows(source,['state','status']).map(entry=>{
   let value=get(entry,['state','status']);
   if(protocol==='ospf'&&/^full(?:\/.*)?$/.test(value))value='full';
   return state(`${protocol} ${name(entry)}`,value,protocol==='bgp'?['established']:['full','2-way'],protocol==='bgp'?['idle','active','connect','opensent','openconfirm']:['down','attempt','init','loading','exchange','exstart'],protocol==='bgp'?'critical':'warning');
  }))));
 }
 return result;
}
function saCount(source){const count=number(source,['count','total','ntun']);if(count!==null&&Number.isInteger(count)&&count>=0)return count;const list=rows(source,['state','status','peer','gateway','name','@_name','spi','remote']);return list.length||empty(source)?list.length:null;}
function vpn(data){
 const off=disabled('vpn',data.vpn);if(off)return off;
 const result=[];const counts={};
 for(const id of ['vpn','ike']){
  counts[id]=saCount(data[id]);
  result.push(counts[id]===null?unknown(`${id} SA`):finding(`${id} SA`,counts[id],'SAs','info','本次查询的安全关联数量；零条目不能证明 VPN 未配置'));
  for(const entry of rows(data[id],['state','status']))result.push(state(`${id} ${name(entry)}`,field(entry,['state','status']),['active','up','established','mature'],['down','failed','error','inactive']));
 }
 if(counts.ike>0&&counts.vpn===0)result.push(finding('vpn-phase2',0,'SAs','warning','存在 IKE SA，但未观察到 IPSec SA；需核对二阶段协商与按需建链','核对 VPN 协商日志与业务流量'));
 return result;
}
function globalprotect(data){
 const source=data.globalprotect,off=disabled('globalprotect',source);if(off)return off;
 const users=rows(source,['username','user','domain','virtual-ip']);
 const result=users.length?[finding('globalprotect-users',users.length,'users','info','本次查询的在线用户数；不推断网关整体健康')]:[];
 for(const entry of rows(source,['state','status']))result.push(state(`globalprotect ${name(entry)}`,field(entry,['state','status'])));
 return listResult('globalprotect',source,result);
}
function dns(data){
 const source=data.dns_proxy,result=[];
 const hits=number(source,['cache-hit','hits']),misses=number(source,['cache-miss','misses']),queries=number(source,['queries','total']);
 if(hits!==null&&hits>=0&&misses!==null&&misses>=0){
  const sum=hits+misses;
  if(sum===0)result.push(finding('DNS cache',0,'queries','info','尚无缓存查询，命中率不可计算'));
  else {const pct=Math.round(hits/sum*1000)/10;result.push(finding('DNS cache hit rate',pct,'%',pct<50?'warning':'ok',`缓存命中率 ${pct}%`,pct<50?'核对缓存有效期与上游查询量':''));}
 }else result.push(unknown('DNS cache hit rate'));
 if(queries!==null&&queries>=0)result.push(finding('DNS queries',queries,'queries','info','累计 DNS 查询数；不推断瞬时查询增长'));
 return result;
}
function userId(data){
 const mappings=rows(data.user_id,['ip','user','username']);
 const result=listResult('user-id-mappings',data.user_id,mappings.length?[finding('user-id-mappings',mappings.length,'mappings','info','本次查询的用户地址映射数')]:[]);
 result.push(...listResult('user-groups',data.user_groups,rows(data.user_groups,['state','status']).map(entry=>state(`LDAP ${name(entry)}`,field(entry,['state','status'])))));
 return result;
}
function sdwan(data){
 const off=disabled('sdwan',data.sdwan);if(off)return off;
 const result=listResult('sdwan',data.sdwan,rows(data.sdwan,['latency','delay','jitter','loss','packet-loss','state','status']).flatMap(entry=>{
  const found=[];
  for(const [metric,keys,unit,warn,crit] of [['latency',['latency','delay'],'ms',150,300],['jitter',['jitter'],'ms',30,50],['loss',['loss','packet-loss'],'%',3,10]]){
   const raw=field(entry,keys);
   const value=toNumber(text(raw).replace(unit==='ms'?/\s*ms$/:/%$/,''));
   const label=`sdwan ${name(entry)} ${metric}`;
   found.push(value===null||value<0||(unit==='%'&&value>100)?unknown(label):finding(label,value,unit,threshold(value,warn,crit),`${metric}：${value}${unit}`,value>=warn?'核对线路质量与 SLA':''));
  }
  if(field(entry,['state','status'])!==undefined)found.push(state(`sdwan ${name(entry)} state`,field(entry,['state','status'])));
  return found.length?found:[unknown(`sdwan ${name(entry)}`)];
 }));
 const violations=fields(data.path_monitor,['violation']).flatMap(v=>Array.isArray(v)?v:[v]);
 if(violations.length){for(const value of violations){const flag=text(value).toLowerCase();result.push(['true','yes','1'].includes(flag)?finding('SLA violation',true,'','critical','设备报告 SLA 违反','核对线路和路径切换'):['false','no','0'].includes(flag)?finding('SLA violation',false,'','ok','设备未报告 SLA 违反'):unknown('SLA violation'));}}
 else result.push(...listResult('path-monitor',data.path_monitor,rows(data.path_monitor,['state','status']).map(entry=>state(`path-monitor ${name(entry)}`,field(entry,['state','status'])))));
 return result;
}
const networkChecks=define([
 ['transceivers','network_connectivity','光模块',['transceivers'],transceivers],
 ['routing','network_connectivity','路由及邻居',['routing','bgp','ospf'],routing],
 ['vpn','remote_access_vpn','VPN 安全关联',['vpn','ike'],vpn],
 ['globalprotect','remote_access_vpn','GlobalProtect 在线用户',['globalprotect'],globalprotect],
 ['dns_proxy','remote_access_vpn','DNS 代理',['dns_proxy'],dns],
 ['user_id','remote_access_vpn','用户映射',['user_id','user_groups'],userId],
 ['sdwan','sdwan','SD-WAN 链路质量',['sdwan','path_monitor'],sdwan]
]);
module.exports={networkChecks};
