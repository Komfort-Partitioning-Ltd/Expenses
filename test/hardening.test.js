const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {createRequire}=require('node:module');
const express=require('express'),jwt=require('jsonwebtoken');
const {rateLimit,receiptBytes}=require('../hardening');
async function fixture(t){
 const app=express(),rows=new Map();
 const store={get:(s,k)=>structuredClone(rows.get(s+'/'+k)),put:(s,k,v)=>rows.set(s+'/'+k,structuredClone(v)),getAll:s=>[...rows].filter(([k])=>k.startsWith(s+'/')).map(([,v])=>structuredClone(v)),del:(s,k)=>rows.delete(s+'/'+k),nextCounter:()=>1,initDb:()=>new Promise(()=>{})};
 for(const [id,roles]of [['employee',['employee']],['manager',['manager']],['finance',['finance']],['victim',['employee']]]) store.put('users',id,{id,username:id,full_name:id,roles,active:1,microsoft_oid:id+'-oid',password_hash:'never-return-this',account_number:'E8-private',email:id+'@example.invalid',approver1_id:id==='employee'?'manager':null});
 store.put('reports','own',{id:'own',user_id:'employee',type:'expense',status:'unsubmitted',title:'Travel'});
 store.put('suppliers','shared',{id:'shared',name:'Shared'});
 const source=path.join(__dirname,'../server.js'),realRequire=createRequire(source),context={require:n=>n==='express'?Object.assign(()=>app,express):n==='./database'?store:n==='./mailer'?{sendMail(){}}:realRequire(n),process:{env:{JWT_SECRET:'synthetic-hardening-test-secret-with-entropy'}},__dirname:path.dirname(source),console};
 vm.runInNewContext(fs.readFileSync(source,'utf8')+'\nglobalThis.issueToken=signToken;',context);
 const issue=id=>context.issueToken(store.get('users',id));
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));t.after(()=>new Promise(r=>server.close(r)));
 const call=async(method,url,who='employee',body,token)=>{const r=await fetch(`http://127.0.0.1:${server.address().port}`+url,{method,headers:{Authorization:'Bearer '+(token||issue(who)),'Content-Type':'application/json'},body:body&&JSON.stringify(body)});return {status:r.status,body:await r.json(),headers:r.headers};};
 const line={id:'line',report_id:'own',line_type:'expense',line_date:'2026-11-17',amount:100,vat_amount:20};
 return {store,issue,call,line};
}
test('rejects stored markup, invalid dates, numeric coercion, bad VAT and unknown references',async t=>{
 const {store,call,line}=await fixture(t);
 for(const patch of [{distance_miles:'<img src=x onerror=alert(1)>'},{line_date:'<img src=x>'},{line_date:'2026-02-30'},{line_date:undefined},{amount:'100'},{amount:null},{vat_amount:101},{vat_amount:-1},{distance_miles:-1},{distance_miles:100001},{amount:1000001},{supplier_id:'missing'},{extra_field:1}]) {
   assert.equal((await call('PUT','/api/store/lines','employee',{...line,...patch})).status,400,JSON.stringify(patch));
 }
 assert.equal(store.get('lines','line'),undefined);
 assert.equal((await call('PUT','/api/store/lines','employee',line)).status,200);
 assert.equal((await call('PUT','/api/store/lines','employee',{...line,amount:-100,vat_amount:-20})).status,200);
});
test('employee supplier creation is stamped; update, delete and referenced deletion are protected',async t=>{
 const {store,call,line}=await fixture(t);
 assert.equal((await call('PUT','/api/store/suppliers','employee',{id:'new',name:'New supplier',created_by:'finance'})).status,200);
 assert.equal(store.get('suppliers','new').created_by,'employee');
 assert.equal((await call('PUT','/api/store/suppliers','employee',{id:'shared',name:'Overwrite'})).status,403);
 assert.equal((await call('DELETE','/api/store/suppliers/shared')).status,403);
 await call('PUT','/api/store/lines','employee',{...line,supplier_id:'shared'});
 assert.equal((await call('DELETE','/api/store/suppliers/shared','finance')).status,409);
});
test('directory minimizes colleagues while preserving own profile and assigned manager routing',async t=>{
 const {call}=await fixture(t);
 const colleague=await call('GET','/api/store/users/victim');
 assert.deepEqual(Object.keys(colleague.body).sort(),['active','full_name','id']);
 assert.equal(colleague.headers.get('cache-control'),'no-store');
 const own=await call('GET','/api/me');assert.equal(own.body.account_number,'E8-private');assert.equal(own.body.password_hash,undefined);assert.equal(own.body.session_version,undefined);
 assert.equal((await call('GET','/api/store/users/employee','manager')).body.approver1_id,'manager');
 assert.equal((await call('GET','/api/store/users/victim','finance')).body.account_number,'E8-private');
});
test('actual issued sessions expire in one hour and are revoked on logout, relink and role changes',async t=>{
 const {store,issue,call}=await fixture(t);
 let token=issue('employee');const decoded=jwt.decode(token);assert.equal(decoded.exp-decoded.iat,3600);
 assert.equal((await call('POST','/api/logout','employee',{},token)).status,200);
 assert.equal((await call('GET','/api/me','employee',null,token)).status,401);
 token=issue('employee');store.put('users','employee',{...store.get('users','employee'),microsoft_oid:'new-oid'});
 assert.equal((await call('GET','/api/me','employee',null,token)).status,401);
 token=issue('employee');store.put('users','employee',{...store.get('users','employee'),roles:['manager']});
 assert.equal((await call('GET','/api/me','employee',null,token)).status,401);
 const old=jwt.sign({id:'employee',auth_method:'microsoft'},'synthetic-hardening-test-secret-with-entropy');
 assert.equal((await call('GET','/api/me','employee',null,old)).status,401);
});
test('approved financial content requires return, correction and renewed approval; audit includes deltas',async t=>{
 const {store,call,line}=await fixture(t);
 await call('PUT','/api/store/lines','employee',line);
 await call('PUT','/api/store/reports','employee',{...store.get('reports','own'),status:'awaiting_manager'});
 await call('PUT','/api/store/reports','manager',{...store.get('reports','own'),status:'awaiting_finance'});
 assert.equal((await call('PUT','/api/store/lines','finance',{...line,amount:200})).status,403);
 await call('PUT','/api/store/reports','finance',{...store.get('reports','own'),status:'awaiting_reimbursement'});
 assert.equal((await call('PUT','/api/store/lines','finance',{...line,amount:200})).status,403);
 assert.equal((await call('PUT','/api/store/reports','finance',{...store.get('reports','own'),status:'rejected',rejection_note:'Correct amount'})).status,200);
 assert.equal((await call('PUT','/api/store/lines','finance',{...line,amount:200})).status,200);
 assert.equal((await call('PUT','/api/store/reports','employee',{...store.get('reports','own'),status:'awaiting_manager'})).status,200);
 assert.equal(store.get('reports','own').manager_approved_by,null);assert.equal(store.get('reports','own').finance_approved_by,null);
 assert.equal((await call('PUT','/api/store/reports','finance',{...store.get('reports','own'),status:'reimbursed'})).status,403);
 const changed=store.getAll('audit_log').find(a=>a.changes?.amount?.after===200);assert.equal(changed.changes.amount.before,100);
});
test('receipt validation verifies decoded signatures and rejects active document types',()=>{
 assert.ok(receiptBytes({mime:'application/pdf',data:'data:application/pdf;base64,JVBERi0xLjc='})>0);
 for(const r of [{mime:'image/png',data:'data:image/png;base64,aGVsbG8='},{mime:'text/html',data:'data:text/html;base64,PGgxPg=='},{mime:'image/svg+xml',data:'data:image/svg+xml;base64,PHN2Zz4='},{mime:'application/pdf',data:'data:application/pdf;base64,JVBERi0xLjc=!!!'}])assert.equal(receiptBytes(r),-1);
});
test('rate limiter returns 429 and a retry interval when the client exceeds its allowance',()=>{
 const limit=rateLimit({limit:2,windowMs:60000}),headers={};let next=0,status;
 const res={set:(k,v)=>{headers[k]=v;},status:n=>{status=n;return res;},json:()=>{}};
 for(let i=0;i<3;i++)limit({ip:'synthetic-client'},res,()=>next++);
 assert.equal(next,2);assert.equal(status,429);assert.ok(Number(headers['Retry-After'])>0);
});
test('nested statement identifiers and transaction types are validated',async t=>{
 const {store,call}=await fixture(t);
 store.put('reports','card',{id:'card',user_id:'employee',type:'creditcard',status:'unsubmitted'});
 const tx={id:'tx',date:'2026-11-17',description:'Receipt',amount:10};
 for(const patch of [{id:"x');alert(1);//"},{date:'2026-02-30'},{amount:'10'}])assert.equal((await call('PUT','/api/store/reports','employee',{...store.get('reports','card'),reconciliation:{txs:[{...tx,...patch}]}})).status>=400,true);
 assert.equal((await call('PUT','/api/store/reports','employee',{...store.get('reports','card'),reconciliation:{txs:[tx],tickedLineIds:[]}})).status,200);
});
