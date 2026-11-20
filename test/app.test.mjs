import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../server.mjs';
import { createAI } from '../ai.mjs';

const password = 'a2#Bc3';
test('Browser bootstrap is opt-in, secret protected, origin checked and creates exactly one administrator',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'mc-setup-'));
  const secret='test-only-setup-token-at-least-32-characters';
  const app=createApp({dataDir:dir,origin:'http://localhost:3000',bootstrapToken:secret,ai:{enabled:false}});
  await assert.rejects(()=>app.addAdmin('short@example.test','Ab1#x'),/от 6 до 200/);
  await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
  const base='http://127.0.0.1:'+app.server.address().port;
  const send=async(token,origin='http://localhost:3000')=>fetch(base+'/api/setup',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify({token,name:'Администратор',email:'first@example.test',password})});
  try{
    assert.equal((await send(secret,'https://wrong.example')).status,403);
    assert.equal((await send('wrong')).status,403);
    const results=await Promise.all([send(secret),send(secret)]);
    assert.equal(results.filter(r=>r.status===201).length,1);
    assert.ok(results.every(r=>[201,403,409].includes(r.status)));
    assert.equal(app.db.prepare('SELECT COUNT(*) n FROM users').get().n,1);
    assert.equal((await send(secret)).status,403);
  }finally{await app.close();await rm(dir,{recursive:true,force:true});}
  const disabledDir=await mkdtemp(join(tmpdir(),'mc-disabled-'));
  const disabled=createApp({dataDir:disabledDir,origin:'http://localhost:3000',bootstrapToken:'',ai:{enabled:false}});
  await new Promise(resolve=>disabled.server.listen(0,'127.0.0.1',resolve));
  try{
    const r=await fetch('http://127.0.0.1:'+disabled.server.address().port+'/api/setup',{method:'POST',headers:{Origin:'http://localhost:3000','Content-Type':'application/json'},body:JSON.stringify({token:secret,name:'Test',email:'first@example.test',password})});
    assert.equal(r.status,403);assert.equal(disabled.db.prepare('SELECT COUNT(*) n FROM users').get().n,0);
  }finally{await disabled.close();await rm(disabledDir,{recursive:true,force:true});}
});
async function fixture(ai) {
  const dataDir = await mkdtemp(join(tmpdir(),'medconsilium-'));
  const app = createApp({dataDir,origin:'http://localhost:3000',secure:false,ai});
  const adminId = await app.addAdmin('admin@example.test',password,'Администратор');
  await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
  const base='http://127.0.0.1:'+app.server.address().port;
  async function req(path,method='GET',body,session={},headers={}) {
    const res=await fetch(base+path,{method,headers:{Origin:'http://localhost:3000',...(body?{'Content-Type':'application/json'}:{}),...(session.cookie?{Cookie:session.cookie}:{}),...(session.csrf?{'X-CSRF-Token':session.csrf}:{}),...headers},body:body?JSON.stringify(body):undefined});
    const value=res.headers.get('content-type')?.includes('application/json')?await res.json():await res.text();
    return {status:res.status,value,cookie:res.headers.get('set-cookie')?.split(';')[0],headers:res.headers};
  }
  const login=async(email)=>{const r=await req('/api/login','POST',{email,password});assert.equal(r.status,200);return {cookie:r.cookie,csrf:r.value.csrf};};
  const admin=await login('admin@example.test');
  async function member(email='member@example.test',name='Участник'){
    const invite=await req('/api/admin/invitations','POST',{email},admin);assert.equal(invite.status,201);
    const token=new URLSearchParams(new URL(invite.value.url).hash.slice(1)).get('invite');
    const r=await req('/api/accept-invite','POST',{email,password,name,birthdate:'1990-01-01',token,adminAccessAcknowledged:true});assert.equal(r.status,201);
    const session=await login(email), m=await req('/api/me','GET',undefined,session);
    return {session,id:m.value.user.id,token,email};
  }
  return {app,req,login,admin,adminId,member,dataDir,async close(){await app.close();await rm(dataDir,{recursive:true,force:true});}};
}

test('Invitation-only accounts, email binding, acknowledgement and one-time use',async()=>{
  const f=await fixture({enabled:false});try{
    const r=await f.req('/api/admin/invitations','POST',{email:'new@example.test'},f.admin);
    const token=new URLSearchParams(new URL(r.value.url).hash.slice(1)).get('invite');
    const b={token,email:'other@example.test',name:'Семья',password,birthdate:'1991-05-10',adminAccessAcknowledged:true};
    assert.equal((await f.req('/api/accept-invite','POST',b)).status,400);
    b.email='new@example.test';b.adminAccessAcknowledged=false;
    assert.equal((await f.req('/api/accept-invite','POST',b)).status,400);
    b.adminAccessAcknowledged=true;
    assert.equal((await f.req('/api/accept-invite','POST',b)).status,201);
    assert.equal((await f.req('/api/accept-invite','POST',b)).status,400);
    assert.equal((await f.req('/api/register','POST',b)).status,401);
    await assert.rejects(()=>f.app.addAdmin('extra@example.test',password),/уже создан/);
  }finally{await f.close();}
});

test('Session cookies, CSRF, Origin and member admin restrictions',async()=>{
  const f=await fixture({enabled:false});try{
    const m=await f.member();
    assert.equal((await f.req('/api/me')).status,401);
    const profiles=await f.req('/api/profiles','GET',undefined,m.session);
    assert.deepEqual(profiles.value.map(p=>p.id),[m.id]);
    assert.equal((await f.req('/api/admin/users','GET',undefined,m.session)).status,403);
    assert.equal((await f.req('/api/profiles/'+m.id+'/consultations','POST',{question:'Вопрос'}, {cookie:m.session.cookie})).status,403);
    assert.equal((await f.req('/api/profiles/'+m.id+'/consultations','POST',{question:'Вопрос'},m.session,{Origin:'https://evil.example'})).status,403);
    const login=await f.req('/api/login','POST',{email:m.email,password});
    assert.match(login.headers.get('set-cookie'),/HttpOnly; SameSite=Strict/);
    assert.equal((await f.req('/api/logout','POST',{},m.session)).status,200);
    assert.equal((await f.req('/api/me','GET',undefined,m.session)).status,401);
  }finally{await f.close();}
});

test('Family isolation covers direct conversations, attachments and text writes; admin views audited',async()=>{
  const f=await fixture({enabled:false});try{
    const a=await f.member(),b=await f.member('second@example.test','Второй');
    const c=await f.req(`/api/profiles/${a.id}/consultations`,'POST',{question:'Личная информация'},a.session);
    const base=`/api/profiles/${a.id}/consultations/${c.value.id}`;
    const upload=await f.req(base+'/documents','POST',{name:'analysis.pdf',base64:Buffer.from('%PDF-1.7\nprivate test').toString('base64')},a.session);
    assert.equal(upload.status,201); const did=upload.value.documents[0].id;
    for(const url of [base,`/api/profiles/${a.id}/documents`, `/api/profiles/${a.id}/documents/${did}/file`,`/api/profiles/${b.id}/consultations/${c.value.id}`])assert.equal((await f.req(url,'GET',undefined,b.session)).status,404);
    assert.equal((await f.req(`/api/profiles/${b.id}/documents/${did}`,'PATCH',{text:'Чужой текст',confirmed:true},b.session)).status,404);
    assert.equal((await f.req(base,'GET',undefined,f.admin)).status,200);
    const log=await f.req('/api/admin/audit','GET',undefined,f.admin);
    assert.ok(log.value.some(a=>a.profile_id===c.value.profile_id&&a.action==='view'));
  }finally{await f.close();}
});

test('Questions work without documents, files require verification and retain original revisions',async()=>{
  let seen;
  const f=await fixture({enabled:true,async consult(context){seen=context;return {status:'completed',summary:'Тестовый итог',coordinator:'Тест',opinions:[],failures:[]};}});try{
    const c=await f.req(`/api/profiles/${f.adminId}/consultations`,'POST',{question:'Тестовый вопрос'},f.admin);
    const url=`/api/profiles/${f.adminId}/consultations/${c.value.id}`;
    const file={name:'анализ.pdf',base64:Buffer.from('%PDF-1.7\ntest').toString('base64')};
    const upload=await f.req(url+'/documents','POST',file,f.admin);assert.equal(upload.status,201);
    assert.equal((await f.req(url+'/documents','POST',file,f.admin)).status,409);
    assert.equal((await f.req(url+'/documents','POST',{name:'evil.html',base64:Buffer.from('<html>evil</html>').toString('base64')},f.admin)).status,415);
    assert.equal((await f.req(url+'/run','POST',{specialists:['cardiology']},f.admin)).status,409);
    const did=upload.value.documents[0].id;
    const docUrl=`/api/profiles/${f.adminId}/documents/${did}`;
    assert.equal((await f.req(docUrl,'PATCH',{text:'Показатель: 10; единицы: тест',confirmed:true},f.admin)).status,200);
    assert.equal((await f.req(docUrl,'PATCH',{text:'Исправление: 12; единицы: тест',confirmed:true},f.admin)).status,200);
    assert.equal(f.app.db.prepare('SELECT COUNT(*) n FROM document_revisions WHERE document_id=?').get(did).n,2);
    const download=await f.req(docUrl+'/file','GET',undefined,f.admin);assert.match(download.value,/test/);
    assert.equal((await f.req(url+'/run','POST',{specialists:['cardiology']},f.admin)).status,202);
    for(let i=0;i<30;i++){const r=await f.req(url,'GET',undefined,f.admin);if(r.value.runs[0].status!=='running')break;await new Promise(r=>setTimeout(r,10));}
    assert.equal(seen.documents[0].text,'Исправление: 12; единицы: тест');
    const result=await f.req(url,'GET',undefined,f.admin);assert.equal(result.value.runs[0].status,'completed');assert.equal(result.value.messages.at(-1).role,'assistant');
    assert.equal(JSON.parse(f.app.db.prepare('SELECT snapshot FROM runs').get().snapshot).profile.name,'Администратор');
  }finally{await f.close();}
});

test('Unconfigured AI saves question and never fabricates an answer',async()=>{
  const f=await fixture({enabled:false});try{
    const c=await f.req(`/api/profiles/${f.adminId}/consultations`,'POST',{question:'Сначала вопрос'},f.admin);
    assert.equal(c.status,201);const url=`/api/profiles/${f.adminId}/consultations/${c.value.id}`;
    assert.equal((await f.req(url+'/run','POST',{specialists:['cardiology']},f.admin)).status,503);
    assert.equal((await f.req(url,'GET',undefined,f.admin)).value.messages.length,1);
  }finally{await f.close();}
});

test('Blocking revokes all member sessions immediately',async()=>{
  const f=await fixture({enabled:false});try{
    const m=await f.member();
    assert.equal((await f.req('/api/admin/users/'+m.id,'PATCH',{active:false},f.admin)).status,200);
    assert.equal((await f.req('/api/me','GET',undefined,m.session)).status,401);
    assert.equal((await f.req('/api/login','POST',{email:m.email,password})).status,401);
    assert.equal((await f.req('/api/admin/users/'+f.adminId,'PATCH',{active:false},f.admin)).status,400);
  }finally{await f.close();}
});

test('Persistent data survives restart and running consultations become interrupted',async()=>{
  const f=await fixture({enabled:false});
  const c=await f.req(`/api/profiles/${f.adminId}/consultations`,'POST',{question:'Сохранись'},f.admin);
  f.app.db.prepare('INSERT INTO runs VALUES(?,?,?,?,?,?,?)').run('test-run',c.value.id,'running','{}',null,null,new Date().toISOString());
  await f.app.close();
  const restored=createApp({dataDir:f.dataDir,ai:{enabled:false}});
  try{assert.equal(restored.db.prepare('SELECT title FROM consultations').get().title,'Сохранись');assert.equal(restored.db.prepare('SELECT status FROM runs').get().status,'interrupted');}
  finally{await restored.close();await rm(f.dataDir,{recursive:true,force:true});}
});

test('Real AI adapter uses separate opinions, cross-review, synthesis, and does not store provider responses',async()=>{
  const calls=[];
  const ai=createAI({apiKey:'test-key',model:'test-model',async fetchImpl(url,options){calls.push({url,...JSON.parse(options.body)});return {ok:true,async json(){return {status:'completed',output:[{type:'message',content:[{type:'output_text',text:'Проверочный ответ '+calls.length}]}]};}};}});
  const result=await ai.consult({messages:[{text:'Test'}],documents:[]},['cardiology','neurology']);
  assert.equal(result.status,'completed');assert.equal(calls.length,6);assert.equal(result.opinions.length,2);assert.ok(calls.every(c=>c.store===false));assert.match(calls[3].instructions,/Рассмотри предварительные мнения/);assert.match(calls.at(-1).instructions,/Собери итог/);
});

test('AI specialist failure returns partial result without a fabricated consensus',async()=>{
  const ai=createAI({apiKey:'test',model:'test',async fetchImpl(url,options){const p=JSON.parse(options.body);if(p.instructions.includes('Твоя роль: Кардиолог'))return {ok:false};return {ok:true,async json(){return {status:'completed',output:[{content:[{type:'output_text',text:'Тест'}]}]};}};}});
  const r=await ai.consult({},['cardiology','neurology']);assert.equal(r.status,'partial');assert.deepEqual(r.failures,['cardiology']);assert.match(r.summary,/не завершён/);
});

test('AI upstream failure and concurrent runs are visible without losing user messages',async()=>{
  let release;
  const gate=new Promise(r=>release=r);
  const f=await fixture({enabled:true,async consult(){await gate;throw new Error('private provider diagnostic');}});try{
    const c=await f.req(`/api/profiles/${f.adminId}/consultations`,'POST',{question:'Вопрос'},f.admin);
    const url=`/api/profiles/${f.adminId}/consultations/${c.value.id}`;
    assert.equal((await f.req(url+'/run','POST',{specialists:['cardiology']},f.admin)).status,202);
    assert.equal((await f.req(url+'/run','POST',{specialists:['cardiology']},f.admin)).status,409);
    release();
    for(let i=0;i<30;i++){const r=await f.req(url,'GET',undefined,f.admin);if(r.value.runs[0].status==='failed')break;await new Promise(r=>setTimeout(r,10));}
    const r=await f.req(url,'GET',undefined,f.admin);assert.equal(r.value.runs[0].status,'failed');assert.equal(r.value.messages.length,1);assert.ok(!r.value.runs[0].error.includes('private'));
  }finally{release();await f.close();}
});
