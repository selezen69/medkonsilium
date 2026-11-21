import {createAI,SPECIALISTS} from '../../ai.mjs';
const uid=()=>crypto.randomUUID(), now=()=>new Date().toISOString();
const fail=(status,message)=>{throw Object.assign(new Error(message),{status});};
const text=(v,max=8000)=>typeof v==='string'&&v.trim()&&v.trim().length<=max?v.trim():fail(400,'Проверьте заполненные поля.');
const hash=async b=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',b))).map(x=>x.toString(16).padStart(2,'0')).join('');
export async function api(req,env,ctx){
 const url=new URL(req.url),path=url.pathname,method=req.method;
 const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'};
 const json=(v,status=200)=>new Response(JSON.stringify(v),{status,headers:{...headers,'Content-Type':'application/json; charset=utf-8'}});
 try{
  if(!['GET','POST','PATCH'].includes(method))fail(405,'Метод не поддерживается.');
  if(method!=='GET'&&req.headers.get('origin')!==url.origin)fail(403,'Недопустимый источник запроса.');
  const identity=req.headers.get('oai-authenticated-user-id'),email=req.headers.get('oai-authenticated-user-email')?.toLowerCase();
  if(!identity||!email)fail(401,'Войдите через ChatGPT.');
  const one=(sql,...p)=>env.DB.prepare(sql).bind(...p).first();
  const all=async(sql,...p)=>(await env.DB.prepare(sql).bind(...p).all()).results;
  const run=(sql,...p)=>env.DB.prepare(sql).bind(...p).run();
  const audit=(pid,action)=>run('INSERT INTO audit(actor_id,profile_id,action,created) VALUES(?,?,?,?)',identity,pid,action,now());
  let actor=await one('SELECT * FROM users WHERE id=?',identity);
  // Only the configured owner can initialize an account. Site sharing alone never grants profile access.
  if(!actor&&env.OWNER_EMAIL&&email===env.OWNER_EMAIL.toLowerCase()){
   await run("INSERT OR IGNORE INTO users(id,email,name,role,csrf) VALUES(?,?,?,'admin',?)",identity,email,'Игорь',uid()+uid());
   actor=await one('SELECT * FROM users WHERE id=?',identity);
  }
  if(!actor||!actor.active)fail(403,'Доступ к прототипу не предоставлен.');
  if(method!=='GET'&&req.headers.get('x-csrf-token')!==actor.csrf)fail(403,'Обновите страницу и повторите действие.');
  async function body(){if(!req.headers.get('content-type')?.startsWith('application/json'))fail(415,'Ожидается JSON.');let size=0;const chunks=[];for await(const b of req.body){size+=b.byteLength;if(size>12*1024*1024)fail(413,'Файл слишком большой.');chunks.push(b);}const b=new Uint8Array(size);let i=0;for(const c of chunks){b.set(c,i);i+=c.length;}try{const v=JSON.parse(new TextDecoder().decode(b));if(!v||Array.isArray(v)||typeof v!=='object')throw Error();return v;}catch{fail(400,'Неверный JSON.');}}
  const safe=u=>({id:u.id,email:u.email,name:u.name,birthdate:u.birthdate,role:u.role,active:!!u.active});
  const ai=createAI({apiKey:env.OPENAI_API_KEY,model:env.OPENAI_MODEL});
  if(path==='/api/me'&&method==='GET')return json({user:safe(actor),csrf:actor.csrf,aiEnabled:ai.enabled,specialists:SPECIALISTS,hosted:true});
  if(path==='/api/profiles'&&method==='GET')return json(actor.role==='admin'?await all('SELECT id,name,birthdate FROM users ORDER BY rowid'):[{id:actor.id,name:actor.name,birthdate:actor.birthdate}]);
  if(path.startsWith('/api/admin/')){
   if(actor.role!=='admin')fail(403,'Требуется доступ администратора.');
   if(path==='/api/admin/users'&&method==='GET')return json((await all('SELECT * FROM users ORDER BY rowid')).map(safe));
   if(path==='/api/admin/audit'&&method==='GET')return json(await all('SELECT a.*,u.name actor,p.name profile FROM audit a LEFT JOIN users u ON u.id=a.actor_id LEFT JOIN users p ON p.id=a.profile_id ORDER BY a.id DESC LIMIT 100'));
   fail(409,'Семейные приглашения подключим на следующем этапе. Сейчас прототип доступен только владельцу.');
  }
  const m=path.match(/^\/api\/profiles\/([^/]+)(.*)$/);if(!m)fail(404,'Действие не найдено.');
  const [,pid,rest]=m;
  const p=await one('SELECT id,name,birthdate FROM users WHERE id=?',pid);
  if(!p||(actor.role!=='admin'&&pid!==identity))fail(404,'Профиль не найден.');
  if(pid!==identity)await audit(pid,method==='GET'?'view':'change');
  async function conversation(cid){
   const c=await one('SELECT * FROM consultations WHERE id=? AND profile_id=?',cid,pid);if(!c)fail(404,'Разговор не найден.');
   await run("UPDATE runs SET status='interrupted',error='Обсуждение прервано. Повторите запуск.' WHERE consultation_id=? AND status='running' AND expires<?",cid,Date.now());
   return {...c,messages:await all('SELECT id,role,text,created FROM messages WHERE consultation_id=? ORDER BY rowid',cid),documents:await all('SELECT id,name,mime,extracted,confirmed,created FROM documents WHERE consultation_id=? AND profile_id=? ORDER BY rowid',cid,pid),runs:(await all('SELECT id,status,result,error,created FROM runs WHERE consultation_id=? ORDER BY rowid DESC',cid)).map(r=>({...r,result:r.result?JSON.parse(r.result):null}))};
  }
  if(rest==='/consultations'&&method==='GET')return json(await all('SELECT * FROM consultations WHERE profile_id=? ORDER BY created DESC',pid));
  if(rest==='/consultations'&&method==='POST'){
   const b=await body(),question=text(b.question),id=uid(),created=now();
   await env.DB.batch([env.DB.prepare('INSERT INTO consultations VALUES(?,?,?,?)').bind(id,pid,question.slice(0,100),created),env.DB.prepare('INSERT INTO messages VALUES(?,?,?,?,?,?)').bind(uid(),id,identity,'user',question,created)]);
   return json(await conversation(id),201);
  }
  if(rest==='/documents'&&method==='GET')return json(await all('SELECT id,name,mime,confirmed,created,consultation_id FROM documents WHERE profile_id=? ORDER BY created DESC',pid));
  const dm=rest.match(/^\/documents\/([^/]+)(\/file)?$/);
  if(dm){
   const d=await one('SELECT * FROM documents WHERE id=? AND profile_id=?',dm[1],pid);if(!d)fail(404,'Документ не найден.');
   if(dm[2]&&method==='GET'){const obj=await env.BUCKET.get(d.object_key);if(!obj)fail(404,'Оригинал не найден.');return new Response(obj.body,{headers:{...headers,'Content-Type':d.mime,'Content-Disposition':`attachment; filename*=UTF-8''${encodeURIComponent(d.name)}`}});}
   if(!dm[2]&&method==='PATCH'){const b=await body(),extracted=text(b.text,30000);if(b.confirmed!==true)fail(400,'Подтвердите проверенный текст.');await env.DB.batch([env.DB.prepare('UPDATE documents SET extracted=?,confirmed=1 WHERE id=?').bind(extracted,d.id),env.DB.prepare('INSERT INTO document_revisions VALUES(?,?,?,?,?)').bind(uid(),d.id,identity,extracted,now())]);return json({ok:true});}
  }
  const cm=rest.match(/^\/consultations\/([^/]+)(.*)$/);if(!cm)fail(404,'Действие не найдено.');
  const [,cid,action]=cm;const c=await conversation(cid);
  if(!action&&method==='GET')return json(c);
  if(action==='/messages'&&method==='POST'){const b=await body();await run('INSERT INTO messages VALUES(?,?,?,?,?,?)',uid(),cid,identity,'user',text(b.text),now());return json(await conversation(cid),201);}
  if(action==='/documents'&&method==='POST'){
   const b=await body(),name=text(b.name,160);if(typeof b.base64!=='string'||!/^[A-Za-z0-9+/]*={0,2}$/.test(b.base64))fail(400,'Повреждённый файл.');
   let bytes;try{bytes=Uint8Array.from(atob(b.base64),x=>x.charCodeAt(0));}catch{fail(400,'Повреждённый файл.');}
   if(!bytes.length||bytes.length>8*1024*1024)fail(413,'Допустимый размер файла: до 8 МБ.');
   const starts=(a)=>a.every((v,i)=>bytes[i]===v);
   const mime=starts([37,80,68,70,45])?'application/pdf':starts([137,80,78,71,13,10,26,10])?'image/png':starts([255,216,255])?'image/jpeg':null;
   if(!mime)fail(415,'Поддерживаются PDF, PNG и JPEG.');
   const digest=await hash(bytes);if(await one('SELECT id FROM documents WHERE profile_id=? AND digest=?',pid,digest))fail(409,'Такой документ уже загружен в этот профиль.');
   const id=uid(),key=`${pid}/${id}`;await env.BUCKET.put(key,bytes,{httpMetadata:{contentType:mime}});
   try{await run('INSERT INTO documents(id,profile_id,consultation_id,name,mime,object_key,digest,created) VALUES(?,?,?,?,?,?,?,?)',id,pid,cid,name,mime,key,digest,now());}catch(e){await env.BUCKET.delete(key);throw e;}
   return json(await conversation(cid),201);
  }
  if(action==='/run'&&method==='POST'){
   if(!ai.enabled)fail(503,'ИИ ещё не подключён. Вопрос и документы сохранены.');
   const b=await body();if(!Array.isArray(b.specialists)||b.specialists.length<1||b.specialists.length>4||new Set(b.specialists).size!==b.specialists.length||b.specialists.some(x=>!Object.hasOwn(SPECIALISTS,x)))fail(400,'Выберите от одного до четырёх специалистов.');
   if(c.documents.some(d=>!d.confirmed))fail(409,'Сначала проверьте текст документов.');
   if(await one("SELECT id FROM runs WHERE consultation_id=? AND status='running'",cid))fail(409,'Обсуждение уже идёт.');
   if((await one('SELECT count(*) n FROM runs r JOIN consultations c ON c.id=r.consultation_id WHERE c.profile_id=? AND r.created>?',pid,new Date(Date.now()-3600000).toISOString())).n>=10)fail(429,'Не более 10 обсуждений в час.');
   const context={profile:p,messages:c.messages.map(({role,text})=>({role,text})),documents:c.documents.map(({id,name,extracted})=>({id,name,text:extracted}))};
   if(JSON.stringify(context).length>60000)fail(413,'В разговоре слишком много данных. Начните новый.');
   const id=uid();await run('INSERT INTO runs VALUES(?,?,?,?,?,?,?)',id,cid,'running',null,null,now(),Date.now()+10*60*1000);
   // Complete the run within the request; no background lifetime assumption.
   await (async()=>{try{const result=await ai.consult(context,b.specialists);const ops=[env.DB.prepare('UPDATE runs SET status=?,result=? WHERE id=?').bind(result.status,JSON.stringify(result),id)];if(result.status==='completed')ops.push(env.DB.prepare('INSERT INTO messages VALUES(?,?,?,?,?,?)').bind(uid(),cid,identity,'assistant',result.summary,now()));await env.DB.batch(ops);}catch{await run("UPDATE runs SET status='failed',error=? WHERE id=?",'Не удалось завершить консилиум. Повторите позже.',id);}})();
   return json({id,status:'running'},202);
  }
  fail(404,'Действие не найдено.');
 }catch(e){return json({error:e.status?e.message:'Не удалось выполнить действие. Повторите позже.'},e.status||500);}
}
