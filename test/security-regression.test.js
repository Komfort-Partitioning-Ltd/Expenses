const {test}=require('node:test'),assert=require('node:assert/strict');
const vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
const {createRequire}=require('node:module');
const express=require('express'),jwt=require('jsonwebtoken');
const {receiptValid}=require('../security');
async function fixture(t){
 const app=express(),rows=new Map();
 const get=(s,k)=>structuredClone(rows.get(s+'/'+k));
 const put=(s,k,v)=>rows.set(s+'/'+k,structuredClone(v));
 const store={get,put,getAll:s=>[...rows].filter(([k])=>k.startsWith(s+'/')).map(([,v])=>structuredClone(v)),
   del:(s,k)=>rows.delete(s+'/'+k),nextCounter:()=>100,initDb:()=>new Promise(()=>{})};
 for(const [id,roles]of [['employee',['employee','credit_card']],['manager',['manager']],['finance',['finance']],['victim',['employee']]])
  put('users',id,{id,username:id,roles,active:1,microsoft_oid:'11111111-1111-1111-1111-'+String(['employee','manager','finance','victim'].indexOf(id)+1).padStart(12,'0'),approver1_id:id==='employee'?'manager':null});
 put('reports','victim-report',{id:'victim-report',user_id:'victim',type:'expense',status:'unsubmitted'});
 put('lines','victim-line',{id:'victim-line',report_id:'victim-report',line_type:'expense',line_date:'2026-11-17',amount:100});
 const source=path.join(__dirname,'../server.js'),realRequire=createRequire(source);
 vm.runInNewContext(fs.readFileSync(source,'utf8'),{require:name=>name==='express'?Object.assign(()=>app,express):
   name==='./database'?store:name==='./mailer'?{sendMail(){}}:realRequire(name),
   process:{env:{JWT_SECRET:'regression-test-secret-strong-synthetic-secret-2026'}},__dirname:path.dirname(source),console});
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 t.after(()=>new Promise(r=>server.close(r)));
 const request=async(method,url,who,body)=>{
  const token=jwt.sign({id:who,auth_method:'microsoft',session_fingerprint:require('../hardening').fingerprint(store.get('users',who))},'regression-test-secret-strong-synthetic-secret-2026');
  const res=await fetch(`http://127.0.0.1:${server.address().port}`+url,{method,headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:body&&JSON.stringify(body)});
  return {status:res.status,body:await res.json(),headers:res.headers};
 };
 return {store,request};
}
test('normal expense workflow works; owners cannot approve, change stages or edit locked claims',async t=>{
 const f=await fixture(t),{store,request}=f;
 const save=(s,u,v)=>request('PUT','/api/store/'+s,u,v);
 assert.equal((await save('reports','employee',{id:'draft',type:'expense',title:'Travel',notes:'',status:'unsubmitted'})).status,200);
 const line={id:'line',report_id:'draft',line_type:'expense',line_date:'2026-11-17',amount:120,receipts:[{mime:'image/png',data:'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aZV8AAAAASUVORK5CYII='}]};
 assert.equal((await save('lines','employee',line)).status,200);
 assert.equal((await save('reports','employee',{...store.get('reports','draft'),status:'reimbursed'})).status,403);
 assert.equal((await save('reports','employee',{...store.get('reports','draft'),finance_approved_by:'employee'})).status,403);
 assert.equal((await save('reports','employee',{...store.get('reports','draft'),status:'awaiting_finance'})).status,403);
 assert.equal((await save('reports','employee',{...store.get('reports','draft'),status:'awaiting_manager',submitted_at:'2000-01-01'})).status,200);
 assert.notEqual(store.get('reports','draft').submitted_at,'2000-01-01');
 assert.equal((await save('lines','employee',{...line,amount:999})).status,403);
 assert.equal((await save('reports','employee',{...store.get('reports','draft'),status:'awaiting_finance'})).status,403);
 assert.equal((await save('reports','victim',{...store.get('reports','draft'),status:'awaiting_finance'})).status,403);
 assert.equal((await save('reports','manager',{...store.get('reports','draft'),status:'awaiting_finance',manager_approved_by:'forged'})).status,200);
 assert.equal(store.get('reports','draft').manager_approved_by,'manager');
 assert.equal((await save('reports','manager',{...store.get('reports','draft'),status:'awaiting_reimbursement'})).status,403);
 assert.equal((await save('lines','finance',{...line,amount:126})).status,403);
 assert.equal((await save('reports','finance',{...store.get('reports','draft'),status:'awaiting_reimbursement',finance_approved_by:'forged'})).status,200);
 assert.equal(store.get('reports','draft').finance_approved_by,'finance');
 assert.equal((await save('reports','employee',{...store.get('reports','draft'),status:'reimbursed'})).status,403);
 assert.equal((await save('payment_runs','finance',{id:'payment',report_ids:['draft'],total:120})).status,200);
 assert.equal((await save('reports','finance',{...store.get('reports','draft'),status:'reimbursed',payment_run_id:'payment'})).status,200);
 assert.equal((await save('lines','finance',{...line,amount:200})).status,403);
 assert.equal((await request('DELETE','/api/store/lines/line','finance')).status,403);
 assert.equal((await request('DELETE','/api/store/reports/draft','finance')).status,403);
 const audit=store.getAll('audit_log');assert.ok(audit.length>=7);
 assert.ok(audit.every(a=>a.actor_id&&a.timestamp));
});
test('returns, resubmissions, separate approvers and credit-card reconciliation remain supported',async t=>{
 const {store,request}=await fixture(t),save=(s,u,v)=>request('PUT','/api/store/'+s,u,v);
 await save('reports','employee',{id:'card',type:'creditcard',title:'Card',status:'unsubmitted'});
 const line={id:'card-line',report_id:'card',line_type:'expense',line_date:'2026-11-17',amount:20,receipts:[]};
 await save('lines','employee',line);
 await save('reports','employee',{...store.get('reports','card'),status:'awaiting_manager'});
 assert.equal((await save('reports','manager',{...store.get('reports','card'),status:'rejected',rejection_note:'Add details'})).status,200);
 assert.equal((await save('lines','employee',{...line,description:'Updated'})).status,200);
 assert.equal((await save('reports','employee',{...store.get('reports','card'),status:'awaiting_manager'})).status,200);
 assert.equal(store.get('reports','card').rejection_note,null);
 assert.equal((await save('reports','employee',{...store.get('reports','card'),reconciliation:{completed:true,txs:[]}})).status,200);
 assert.equal((await save('reports','finance',{...store.get('reports','card'),status:'awaiting_finance'})).status,200);
 assert.equal((await save('reports','finance',{...store.get('reports','card'),status:'approved'})).status,403);
 const second={...store.get('users','finance'),id:'finance-two',username:'finance-two'};store.put('users',second.id,second);
 assert.equal((await save('reports','finance-two',{...store.get('reports','card'),status:'approved'})).status,200);
 assert.equal((await save('lines','finance',line)).status,403);
});
test('ownership, receipts, audit entries, internal stores and identifiers are protected',async t=>{
 const {store,request}=await fixture(t);
 const save=(s,v)=>request('PUT','/api/store/'+s,'employee',v);
 await save('reports',{id:'own',type:'expense',status:'unsubmitted'});
 assert.equal((await save('lines',{id:'victim-line',report_id:'own',line_type:'expense',line_date:'2026-11-17',amount:0})).status,403);
 assert.equal(store.get('lines','victim-line').report_id,'victim-report');
 assert.equal((await save('lines',{id:'receipt',report_id:'own',line_type:'expense',line_date:'2026-11-17',amount:1,receipts:[{mime:'image/png',data:'x" onerror="alert(1)'}]})).status,400);
 assert.equal((await save('audit_log',{id:'fake',user:'finance',action:'approved'})).status,403);
 const audit=store.getAll('audit_log')[0];
 assert.equal((await request('DELETE','/api/store/audit_log/'+audit.id,'employee')).status,403);
 assert.equal((await request('GET','/api/store/%72eset_tokens','employee')).status,404);
 assert.equal((await save('unknown',{id:'fake'})).status,404);
 assert.equal((await save('reports',{id:"bad');alert(1);//",type:'expense',status:'unsubmitted'})).status,400);
 const own=store.get('users','employee');
 assert.equal((await save('users',{...own,approver1_id:'employee'})).status,200);
 assert.equal(store.get('users','employee').approver1_id,'manager');
});
test('valid receipt formats remain accepted; quotes, external URLs and MIME mismatches are rejected',()=>{
 assert.equal(receiptValid({mime:'application/pdf',data:'data:application/pdf;base64,JVBERi0xLjc='}),true);
 for(const mime of ['image/svg+xml','text/html','application/octet-stream']) assert.equal(receiptValid({mime,data:`data:${mime};base64,aGVsbG8=`}),false);
 for(const data of ['https://example.invalid/image.png','javascript:alert(1)','data:image/png;base64,x" onerror="alert(1)'])
  assert.equal(receiptValid({mime:'image/png',data}),false);
 assert.equal(receiptValid({mime:'image/png',data:'data:text/html;base64,aGVsbG8='}),false);
});
test('server refuses to start with an absent or known fallback signing secret',()=>{
 const source=path.join(__dirname,'../server.js'),realRequire=createRequire(source);
 for(const env of [{},{JWT_SECRET:'x'},{JWT_SECRET:'expenses-dev-secret-change-me'}]) assert.throws(()=>
  vm.runInNewContext(fs.readFileSync(source,'utf8'),{require:name=>name==='./database'?{}:name==='./mailer'?{}:realRequire(name),process:{env},__dirname:path.dirname(source),console}),/Configure JWT_SECRET/);
});
