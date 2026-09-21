'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { deviceChecks } = require('../services/monitor/device-checks');
const { networkChecks } = require('../services/monitor/network-checks');
const { securityChecks } = require('../services/monitor/security-checks');
const all = [...deviceChecks, ...networkChecks, ...securityChecks];
const e = value => ({ entry: value });
const window = {start:'2026/09/21 10:00:00',end:'2026/09/21 10:15:00',clock:'device',minutes:15,limit:1000,complete:true};
const fixtures = {
 disk_space:[e({percent:20}),e({percent:96})], logdb_quota:[e({percent:20}),e({percent:91})],
 software_status:[e({status:'running'}),e({status:'stopped'})],
 global_counters:[e({value:0}),e({value:999999})], app_stats:[e({sessions:1}),e({sessions:999999})],
 discard_sessions:[{count:0},{count:101}], transceivers:[e({vendor:'Palo Alto Networks'}),e({vendor:'unknown'})],
 routing:[{routing:e({destination:'0.0.0.0/0'}),bgp:e({state:'Established'}),ospf:e({state:'Full'})},{routing:e({destination:'0.0.0.0/0'}),bgp:e({state:'Active'}),ospf:e({state:'Init'})}],
 vpn:[{vpn:e({state:'active'}),ike:e({state:'active'})},{vpn:e([]),ike:e({state:'active'})}],
 globalprotect:[e({username:'example'}),e({state:'down'})], dns_proxy:[{'cache-hit':90,'cache-miss':10},{'cache-hit':10,'cache-miss':90}],
 user_id:[{user_id:e({ip:'192.0.2.1',user:'example'}),user_groups:e({state:'connected'})},{user_id:e([]),user_groups:e({state:'failed'})}],
 sdwan:[{sdwan:e({latency:10,jitter:1,loss:0,state:'up'}),path_monitor:{violation:false}},{sdwan:e({latency:200,jitter:1,loss:0,state:'up'}),path_monitor:{violation:false}}],
 rule_hits:[e({'@_name':'allow','hit-count':1}),e({'@_name':'default-deny','hit-count':10001})],
 zone_protection:[e({dp:0,pb:0}),e({dp:100,pb:0})], decryption:[e({'hit-count':10}),e({'hit-count':0})],
 threat_logs:[{entry:[],count:0,window},{entry:[],count:201,window}],
 ha_diagnostics:[{ha_all:{enabled:true,'config-sync':'synchronized'},ha_link:e({state:'up'}),ha_path:e({state:'up'}),ha_sync:{sent:10,received:10},ha_flaps:{flaps:0}},{ha_all:{enabled:true},ha_link:e({state:'down'}),ha_path:e({state:'up'}),ha_sync:{sent:0,received:0},ha_flaps:{flaps:6}}],
 jobs:[e({status:'FIN',result:'OK'}),e({status:'FIN',result:'FAIL'})], edl:[e({count:10}),e({count:0})],fqdn:[e({ip:'192.0.2.1'}),e({ip:''})]
};
test('21 unique extended definitions',()=>assert.equal(new Set(all.map(c=>c.id)).size,21));
for (const check of all) {
 const wrap = value => check.sources.length > 1 ? value : {[check.id]:value};
 test(`${check.id}: positive evidence`,()=>{const result=check.evaluate(wrap(fixtures[check.id][0]),{});assert(result.length);assert(!result.some(f=>['critical','warning','unknown'].includes(f.severity)));});
 test(`${check.id}: risk or elevated observed evidence`,()=>{const result=check.evaluate(wrap(fixtures[check.id][1]),{});assert(result.some(f=>['global_counters','app_stats','zone_protection'].includes(check.id)?f.severity==='info': ['warning','critical'].includes(f.severity)));});
 test(`${check.id}: missing and unsupported stay unknown`,()=>{for(const value of [undefined,{}, {error:'unsupported'}]){const result=check.evaluate(Object.fromEntries(check.sources.map(s=>[s,value])),{});assert(result.some(f=>f.severity==='unknown'));assert(!result.some(f=>f.severity==='ok'));}});
}
test('SDWAN warning does not escalate; loss and jitter critical do',()=>{const check=all.find(c=>c.id==='sdwan');assert(!check.evaluate(fixtures.sdwan[1]).some(f=>f.severity==='critical'));for(const sample of [{loss:11},{jitter:51}])assert(check.evaluate({sdwan:e(sample),path_monitor:{violation:false}}).some(f=>f.severity==='critical'));});
test('threat limit is visible and counts are lower bounds',()=>{const result=all.find(c=>c.id==='threat_logs').evaluate({threat_logs:{entry:[],count:1000,window:{...window,complete:false}}});assert(result.some(f=>f.severity==='unknown'));assert(result.some(f=>f.severity==='critical'&&f.value===1000));});
test('text disk and process output',()=>{assert(deviceChecks.find(c=>c.id==='disk_space').evaluate({disk_space:'Filesystem Size Used Avail Use% Mounted on\n/dev/root 10G 9.6G 0.4G 96% /'}).some(f=>f.severity==='critical'));assert(deviceChecks.find(c=>c.id==='software_status').evaluate({software_status:'Process mgmtsrvr running (pid: 123)\nProcess logrcvr stopped'}).some(f=>f.severity==='critical'));});
test('HA disabled requires explicit evidence',()=>{const check=all.find(c=>c.id==='ha_diagnostics');assert.equal(check.evaluate({ha_all:{enabled:false}})[0].applicability,'not_applicable');assert.equal(check.evaluate({})[0].severity,'unknown');});
test('false violation is not failure and counters never infer rates',()=>{assert(!all.find(c=>c.id==='sdwan').evaluate(fixtures.sdwan[0]).some(f=>f.severity==='critical'));assert(deviceChecks.find(c=>c.id==='global_counters').evaluate({global_counters:e({value:100000,delta:100000})}).every(f=>f.severity==='info'));});
test('all 29 definitions have fixed valid source IDs and categories',()=>{
 const {basicChecks}=require('../services/monitor/basic-checks');
 const {SOURCES}=require('../services/monitor/sources');
 const {CATEGORIES}=require('../services/monitor/service');
 const definitions=[...basicChecks,...all];assert.equal(new Set(definitions.map(c=>c.id)).size,29);
 for(const c of definitions){assert(Object.hasOwn(CATEGORIES,c.category));for(const source of c.sources)assert(Object.hasOwn(SOURCES,source));}
});
test('explicit empty optional feature lists do not fabricate incidents or disabled state',()=>{
 for(const id of ['vpn','globalprotect','user_id','edl','fqdn','transceivers','routing','sdwan','jobs','decryption']){
  const check=all.find(c=>c.id===id);const result=check.evaluate(Object.fromEntries(check.sources.map(s=>[s,e([])])));
  assert(!result.some(f=>['warning','critical'].includes(f.severity)),id);assert(!result.some(f=>f.applicability==='not_applicable'),id);
 }
});
test('strict numbers: booleans, empty strings and negative values never become healthy',()=>{
 for(const id of ['disk_space','logdb_quota'])for(const percent of [true,false,'',-1,101])assert.equal(all.find(c=>c.id===id).evaluate({[id]:e({percent})})[0].severity,'unknown');
 for(const count of [true,false,'',-1])assert.equal(all.find(c=>c.id==='edl').evaluate({edl:e({count})})[0].severity,'unknown');
});
test('nested XML entries do not count rule containers as rules',()=>{
 const data={rule_hits:{vsys:{entry:{'@_name':'vsys1','rule-base':{entry:{'@_name':'security',rules:e([{'@_name':'allow','hit-count':20},{'@_name':'default-deny','hit-count':12000}])}}}}}};
 const result=all.find(c=>c.id==='rule_hits').evaluate(data);assert.equal(result.length,2);assert(result.every(f=>f.metric.includes('vsys1')));assert(result.some(f=>f.severity==='warning'));
});
test('findings are bounded and retain a risk beyond first hundred rows',()=>{
 const data=e([...Array.from({length:150},(_,i)=>({name:`p${i}`,status:'running'})),{name:'failed-last',status:'stopped'}]);
 const result=all.find(c=>c.id==='software_status').evaluate({software_status:data});assert.equal(result.length,100);assert(result.some(f=>f.severity==='critical'));assert(result.some(f=>f.severity==='unknown'));
});
test('missing EDL counts, FQDN addresses and job outcomes remain unknown',()=>{
 for(const [id,source] of [['edl',e({name:'list',status:'success'})],['fqdn',e({name:'host'})],['jobs',e({status:'FIN'})]])assert(all.find(c=>c.id===id).evaluate({[id]:source}).some(f=>f.severity==='unknown'));
});
test('named incomplete entries remain visible beside recognized entries',()=>{
 for(const id of ['disk_space','logdb_quota','software_status','global_counters','app_stats','transceivers','rule_hits','decryption','jobs','edl','fqdn']){
  const positive=fixtures[id][0].entry;
  const result=all.find(c=>c.id===id).evaluate({[id]:e([positive,{name:'missing-fields'}])});
  assert(result.some(f=>f.severity==='unknown'),id);
 }
});
test('SDWAN partial rows expose each missing quality metric',()=>{
 const result=all.find(c=>c.id==='sdwan').evaluate({sdwan:e({name:'sample',state:'up',latency:10}),path_monitor:{violation:false}});
 for(const metric of ['jitter','loss'])assert(result.some(f=>f.metric.endsWith(metric)&&f.severity==='unknown'));
});
test('HA diagnostics expose missing configuration synchronization evidence',()=>{
 const result=all.find(c=>c.id==='ha_diagnostics').evaluate({...fixtures.ha_diagnostics[0],ha_all:{enabled:true}});
 assert(result.some(f=>f.metric==='HA config sync'&&f.severity==='unknown'));
});
test('FQDN unknown IP objects remain unknown while explicit empty fields warn',()=>{
 const check=all.find(c=>c.id==='fqdn');
 for(const ip of [{unrecognized:'format'},true,{'#text':{unexpected:'nested'}}])assert.equal(check.evaluate({fqdn:e({name:'host',ip})})[0].severity,'unknown');
 for(const ip of ['',[],{'#text':''}])assert.equal(check.evaluate({fqdn:e({name:'host',ip})})[0].severity,'warning');
 for(const ip of ['192.0.2.1',{'#text':'192.0.2.1'},['192.0.2.1','2001:db8::1']])assert.equal(check.evaluate({fqdn:e({name:'host',ip})})[0].severity,'ok');
});
test('XML text numeric values and explicit unit suffixes remain supported',()=>{
 assert.equal(all.find(c=>c.id==='disk_space').evaluate({disk_space:e({percent:{'#text':'20%'}})})[0].severity,'ok');
 const result=all.find(c=>c.id==='sdwan').evaluate({sdwan:e({latency:{'#text':'20 ms'},jitter:'2ms',loss:{'#text':'1%'},state:'up'}),path_monitor:{violation:false}});
 assert(!result.some(f=>['unknown','warning','critical'].includes(f.severity)));
});
test('PAN-OS job arrays preserve FIN outcomes and bounded risk findings',()=>{
 const check=all.find(c=>c.id==='jobs');
 assert.equal(check.evaluate({jobs:{job:[{id:1,status:'FIN',result:'OK'}]}})[0].severity,'ok');
 const result=check.evaluate({jobs:{job:[...Array.from({length:110},(_,id)=>({id,status:'FIN',result:'OK'})),{id:111,status:'FIN',result:'FAIL'}]}});
 assert.equal(result.length,100);assert(result.some(f=>f.severity==='warning'));assert(result.some(f=>f.severity==='unknown'));
 assert.equal(check.evaluate({jobs:{job:{id:1,status:'FIN',result:'FAIL'}}})[0].severity,'warning');
});
test('PAN-OS explicit zero tunnel count is informational with IKE absence visible',()=>{
 const result=all.find(c=>c.id==='vpn').evaluate({vpn:{entries:'',ntun:0},ike:''});
 assert(result.some(f=>f.metric==='vpn SA'&&f.value===0&&f.severity==='info'));
 assert(result.some(f=>f.metric==='ike SA'&&f.severity==='unknown'));
 assert(!result.some(f=>f.applicability==='not_applicable'||['critical','warning'].includes(f.severity)));
});
test('log database allocation percentages never become utilization alarms',()=>{
 const result=all.find(c=>c.id==='logdb_quota').evaluate({logdb_quota:'Quotas:\n system: 4.00%, 0.752 GB Expiration-period: 0 days\n traffic: 96.00%, 18.00 GB Expiration-period: 0 days\n'});
 assert.equal(result.filter(f=>f.severity==='info').length,2);
 assert(result.some(f=>f.severity==='unknown'));
 assert(!result.some(f=>['critical','warning','ok'].includes(f.severity)));
 assert(result.every(f=>!f.message.includes('已使用')));
});
test('zone processor identifiers are not counters; protocol thresholds come from device',()=>{
 const check=all.find(c=>c.id==='zone_protection');
 const source=current=>({entry:{dp:'dp0',entries:e({zone:'Untrust',vsys:'vsys1',profile:'example','tcp-syn':{alarm:500,assured:1000,maximum:2000,current,stats:10},'discard-ip-spoof_pkt_drop':100})}});
 const healthy=check.evaluate({zone_protection:source(1)});
 assert(!healthy.some(f=>['critical','warning','unknown'].includes(f.severity)));
 assert(healthy.some(f=>f.metric.includes('tcp-syn')&&f.value===1));
 assert(healthy.some(f=>f.metric.includes('discard-ip-spoof_pkt_drop')&&f.severity==='info'));
 assert(check.evaluate({zone_protection:source(500)}).some(f=>f.severity==='warning'));
 assert(check.evaluate({zone_protection:source(2000)}).some(f=>f.severity==='critical'));
 assert(check.evaluate({zone_protection:source('bad')}).some(f=>f.severity==='unknown'));
});
test('FQDN table text recognizes only domain blocks and keeps unknown addresses visible',()=>{
 const check=all.find(c=>c.id==='fqdn');
 const prefix='FQDN Table : Request time 2026-09-21 07:09:33\n-----\n\tIP Address\n-----\n\nVSYS : (using mgmt-obj dnsproxy object)\n\tShared\n\tvsys1\n\n';
 const result=check.evaluate({fqdn:prefix+'sinkhole.paloaltonetworks.com\n\t198.135.184.22\n\t::  unknown'});
 assert(result.some(f=>f.severity==='unknown'));
 assert(result.every(f=>f.metric.includes('sinkhole.paloaltonetworks.com')));
 const positive=check.evaluate({fqdn:prefix+'example.com\n\t192.0.2.1\n\t2001:db8::1'});
 assert.equal(positive.length,1);assert.equal(positive[0].severity,'ok');assert.equal(positive[0].value,2);
 assert.equal(check.evaluate({fqdn:prefix})[0].severity,'unknown');
});
