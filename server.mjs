import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, createHash, scrypt as rawScrypt, timingSafeEqual } from 'node:crypto';
import { promisify, parseArgs } from 'node:util';
import { mkdirSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAI, SPECIALISTS } from './ai.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const scrypt = promisify(rawScrypt);
const token = () => randomBytes(32).toString('base64url');
const hash = value => createHash('sha256').update(value).digest('hex');
const iso = () => new Date().toISOString();
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const text = (v, max = 8000) => typeof v === 'string' && v.trim() && v.trim().length <= max ? v.trim() : fail(400, 'Проверьте заполненные поля.');
const emailOf = v => { const e = text(v, 254).toLowerCase(); return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? e : fail(400, 'Укажите корректный email.'); };
async function passwordHash(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 200) fail(400, 'Пароль: от 12 до 200 символов.');
  const salt = randomBytes(16).toString('hex');
  return `${salt}:${(await scrypt(password, salt, 64)).toString('hex')}`;
}
async function passwordMatches(password, stored) {
  const [salt, expected] = stored.split(':');
  const actual = await scrypt(typeof password === 'string' && password.length <= 200 ? password : '', salt, 64);
  return timingSafeEqual(actual, Buffer.from(expected, 'hex'));
}

export function createApp(options = {}) {
  const dataDir = resolve(options.dataDir || process.env.DATA_DIR || './data');
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(resolve(dataDir, 'medkonsilium.sqlite'));
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,birthdate TEXT NOT NULL DEFAULT '',password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'member',active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,user_id TEXT REFERENCES users(id),csrf TEXT NOT NULL,expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS invitations(hash TEXT PRIMARY KEY,email TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS consultations(id TEXT PRIMARY KEY,profile_id TEXT REFERENCES users(id),title TEXT NOT NULL,created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,consultation_id TEXT REFERENCES consultations(id),author_id TEXT REFERENCES users(id),role TEXT NOT NULL,text TEXT NOT NULL,created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY,profile_id TEXT REFERENCES users(id),consultation_id TEXT REFERENCES consultations(id),name TEXT NOT NULL,mime TEXT NOT NULL,bytes BLOB NOT NULL,digest TEXT NOT NULL,extracted TEXT NOT NULL DEFAULT '',confirmed INTEGER NOT NULL DEFAULT 0,created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS document_revisions(id TEXT PRIMARY KEY,document_id TEXT REFERENCES documents(id),author_id TEXT REFERENCES users(id),text TEXT NOT NULL,created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,consultation_id TEXT REFERENCES consultations(id),status TEXT NOT NULL,snapshot TEXT NOT NULL,result TEXT,error TEXT,created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor_id TEXT,profile_id TEXT,action TEXT,created TEXT);
  `);
  db.prepare("UPDATE runs SET status='interrupted',error='Сервер был перезапущен. Повторите обсуждение.' WHERE status='running'").run();
  const ai = options.ai || createAI({ apiKey: process.env.OPENAI_API_KEY, model: process.env.OPENAI_MODEL });
  const origin = options.origin || process.env.APP_ORIGIN || 'http://localhost:3000';
  const secure = options.secure ?? process.env.COOKIE_SECURE === 'true';
  if (!origin.startsWith('http://localhost:') && !origin.startsWith('http://127.0.0.1:') && (!origin.startsWith('https://') || !secure)) throw new Error('Для внешнего адреса требуются HTTPS и COOKIE_SECURE=true.');
  const rate = new Map();
  const activeJobs = new Set();
  const one = (sql, ...p) => db.prepare(sql).get(...p);
  const all = (sql, ...p) => db.prepare(sql).all(...p);
  const run = (sql, ...p) => db.prepare(sql).run(...p);
  const audit = (actor, profile, action) => run('INSERT INTO audit(actor_id,profile_id,action,created) VALUES(?,?,?,?)', actor.id, profile, action, iso());
  const transaction = fn => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
  // A dummy hash makes unknown-address logins perform the same password work.
  const dummyPassword = passwordHash(token());

  async function addAdmin(email, password, name = 'Игорь') {
    if (one('SELECT id FROM users LIMIT 1')) fail(409, 'Первый аккаунт уже создан.');
    const encrypted = await passwordHash(password);
    const id = randomUUID();
    transaction(() => {
      if (one('SELECT id FROM users LIMIT 1')) fail(409, 'Первый аккаунт уже создан.');
      run("INSERT INTO users(id,email,name,password,role) VALUES(?,?,?,?,'admin')", id, emailOf(email), text(name, 80), encrypted);
    });
    return id;
  }
  const safeUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, active: Boolean(u.active), birthdate: u.birthdate });
  const profile = (actor, id, action = 'view') => {
    const p = one('SELECT id,name,birthdate FROM users WHERE id=?', id);
    if (!p || (actor.role !== 'admin' && actor.id !== id)) fail(404, 'Профиль не найден.');
    if (actor.id !== id) audit(actor, id, action);
    return p;
  };
  const consultation = (id, pid) => one('SELECT * FROM consultations WHERE id=? AND profile_id=?', id, pid) || fail(404, 'Разговор не найден.');
  const readConsultation = (id, pid) => {
    const c = consultation(id, pid);
    return { ...c, messages: all('SELECT id,role,text,created FROM messages WHERE consultation_id=? ORDER BY rowid', id),
      documents: all('SELECT id,name,mime,extracted,confirmed,created FROM documents WHERE consultation_id=? AND profile_id=? ORDER BY rowid', id, pid),
      runs: all('SELECT id,status,result,error,created FROM runs WHERE consultation_id=? ORDER BY rowid DESC', id).map(r => ({ ...r, result: r.result ? JSON.parse(r.result) : null })) };
  };
  function limit(key, max, period) {
    if (rate.size > 10000) for (const [k, v] of rate) if (v.until < Date.now()) rate.delete(k);
    let r = rate.get(key); if (!r || r.until < Date.now()) rate.set(key, r = { n: 0, until: Date.now() + period });
    if (++r.n > max) fail(429, 'Слишком много попыток. Повторите позже.');
  }
  async function body(req) {
    if (!req.headers['content-type']?.startsWith('application/json')) fail(415, 'Ожидается JSON.');
    let size = 0; const chunks = [];
    for await (const chunk of req) { size += chunk.length; if (size > 12 * 1024 * 1024) fail(413, 'Файл слишком большой. Максимум 8 МБ.'); chunks.push(chunk); }
    try { const v = JSON.parse(Buffer.concat(chunks).toString()); if (!v || Array.isArray(v) || typeof v !== 'object') fail(400, 'Неверный запрос.'); return v; } catch { fail(400, 'Неверный JSON.'); }
  }
  async function handle(req, res) {
    const send = (status, value, headers = {}) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers }); res.end(JSON.stringify(value)); };
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('Permissions-Policy', 'camera=(), microphone=()');
    try {
      const url = new URL(req.url, origin), path = url.pathname, method = req.method;
      if (!['GET','POST','PATCH'].includes(method)) fail(405, 'Метод не поддерживается.');
      if (method !== 'GET' && req.headers.origin !== origin) fail(403, 'Недопустимый источник запроса.');
      if (!path.startsWith('/api/')) {
        if (method !== 'GET') fail(405, 'Метод не поддерживается.');
        const assets = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'] };
        const a = assets[path]; if (!a) fail(404, 'Страница не найдена.');
        res.writeHead(200, { 'Content-Type': `${a[1]}; charset=utf-8` }); return res.end(readFileSync(resolve(root, 'public', a[0])));
      }
      if (path === '/api/login' && method === 'POST') {
        limit(`login:${req.socket.remoteAddress}`, 12, 15*60_000);
        const b = await body(req); const u = one('SELECT * FROM users WHERE email=?', emailOf(b.email));
        const valid = await passwordMatches(b.password, u?.password || await dummyPassword);
        if (!valid || !u?.active) fail(401, 'Неверный email или пароль.');
        const session = token(), csrf = token();
        run('DELETE FROM sessions WHERE expires<?', Date.now());
        run('INSERT INTO sessions VALUES(?,?,?,?)', hash(session), u.id, csrf, Date.now()+7*86400_000);
        return send(200, { user: safeUser(u), csrf }, { 'Set-Cookie': `mc_session=${session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${secure ? '; Secure' : ''}` });
      }
      if (path === '/api/accept-invite' && method === 'POST') {
        limit(`invite:${req.socket.remoteAddress}`, 10, 15*60_000);
        const b = await body(req); const ih = hash(text(b.token, 100));
        const e = emailOf(b.email); const name = text(b.name, 80);
        if (typeof b.birthdate !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(b.birthdate) || !Number.isFinite(Date.parse(b.birthdate)) || new Date(b.birthdate).toISOString().slice(0,10) !== b.birthdate || b.birthdate > iso().slice(0,10)) fail(400, 'Проверьте дату рождения.');
        if (b.adminAccessAcknowledged !== true) fail(400, 'Подтвердите, что администратор имеет доступ к вашему профилю.');
        const encrypted = await passwordHash(b.password);
        transaction(() => {
          const inv = one('SELECT * FROM invitations WHERE hash=? AND used=0 AND expires>?', ih, Date.now());
          if (!inv || inv.email !== e) fail(400, 'Приглашение недействительно или email не совпадает.');
          if (one('SELECT id FROM users WHERE email=?', e)) fail(409, 'Аккаунт с таким email уже существует.');
          run('INSERT INTO users(id,email,name,birthdate,password) VALUES(?,?,?,?,?)', randomUUID(), e, name, b.birthdate, encrypted);
          run('UPDATE invitations SET used=1 WHERE hash=?', ih);
        });
        return send(201, { ok: true });
      }
      const cookie = req.headers.cookie?.split(';').map(s => s.trim()).find(s => s.startsWith('mc_session='))?.slice(11);
      const session = cookie && one('SELECT * FROM sessions WHERE hash=? AND expires>?', hash(cookie), Date.now());
      const actor = session && one('SELECT * FROM users WHERE id=? AND active=1', session.user_id);
      if (!actor) fail(401, 'Войдите в аккаунт.');
      if (method !== 'GET' && req.headers['x-csrf-token'] !== session.csrf) fail(403, 'Обновите страницу и повторите действие.');
      if (path === '/api/me' && method === 'GET') return send(200, { user: safeUser(actor), csrf: session.csrf, aiEnabled: ai.enabled, specialists: SPECIALISTS });
      if (path === '/api/logout' && method === 'POST') { run('DELETE FROM sessions WHERE hash=?', session.hash); return send(200, { ok: true }, { 'Set-Cookie': `mc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? '; Secure' : ''}` }); }
      if (path === '/api/profiles' && method === 'GET') return send(200, actor.role === 'admin' ? all('SELECT id,name,birthdate FROM users ORDER BY rowid') : [{ id: actor.id, name: actor.name, birthdate: actor.birthdate }]);
      if (path.startsWith('/api/admin/')) {
        if (actor.role !== 'admin') fail(403, 'Требуется доступ администратора.');
        if (path === '/api/admin/users' && method === 'GET') return send(200, all('SELECT * FROM users ORDER BY rowid').map(safeUser));
        if (path === '/api/admin/audit' && method === 'GET') return send(200, all('SELECT a.*,u.name actor,p.name profile FROM audit a LEFT JOIN users u ON u.id=a.actor_id LEFT JOIN users p ON p.id=a.profile_id ORDER BY a.id DESC LIMIT 100'));
        if (path === '/api/admin/invitations' && method === 'POST') {
          const b = await body(req); const email = emailOf(b.email), secret = token();
          if (one('SELECT id FROM users WHERE email=?', email)) fail(409, 'Такой аккаунт уже есть.');
          transaction(() => { run('DELETE FROM invitations WHERE email=?', email); run('INSERT INTO invitations VALUES(?,?,?,0)', hash(secret), email, Date.now()+7*86400_000); });
          audit(actor, actor.id, 'invite'); return send(201, { url: `${origin}/#invite=${secret}`, email });
        }
        const m = path.match(/^\/api\/admin\/users\/([^/]+)$/);
        if (m && method === 'PATCH') {
          if (m[1] === actor.id) fail(400, 'Нельзя заблокировать собственный аккаунт.');
          const b = await body(req); if (typeof b.active !== 'boolean') fail(400, 'Укажите состояние аккаунта.');
          if (!one('SELECT id FROM users WHERE id=?', m[1])) fail(404, 'Аккаунт не найден.');
          transaction(() => { run('UPDATE users SET active=? WHERE id=?', Number(b.active), m[1]); run('DELETE FROM sessions WHERE user_id=?', m[1]); });
          audit(actor, m[1], b.active ? 'unblock' : 'block'); return send(200, { ok: true });
        }
        fail(404, 'Действие не найдено.');
      }
      const match = path.match(/^\/api\/profiles\/([^/]+)(.*)$/); if (!match) fail(404, 'Действие не найдено.');
      const [, pid, rest] = match; const p = profile(actor, pid, method === 'GET' ? 'view' : 'change');
      if (rest === '/consultations' && method === 'GET') return send(200, all('SELECT * FROM consultations WHERE profile_id=? ORDER BY created DESC', pid));
      if (rest === '/consultations' && method === 'POST') {
        const b = await body(req), question = text(b.question), id = randomUUID();
        transaction(() => { run('INSERT INTO consultations VALUES(?,?,?,?)', id, pid, question.slice(0,100), iso()); run('INSERT INTO messages VALUES(?,?,?,?,?,?)', randomUUID(), id, actor.id, 'user', question, iso()); });
        return send(201, readConsultation(id, pid));
      }
      if (rest === '/documents' && method === 'GET') return send(200, all('SELECT id,name,mime,confirmed,created,consultation_id FROM documents WHERE profile_id=? ORDER BY created DESC', pid));
      const docMatch = rest.match(/^\/documents\/([^/]+)(\/file)?$/);
      if (docMatch) {
        const d = one('SELECT * FROM documents WHERE id=? AND profile_id=?', docMatch[1], pid) || fail(404, 'Документ не найден.');
        if (docMatch[2] && method === 'GET') { res.writeHead(200, { 'Content-Type': d.mime, 'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(d.name)}` }); return res.end(d.bytes); }
        if (!docMatch[2] && method === 'PATCH') {
          const b = await body(req); const extracted = text(b.text, 30000);
          if (b.confirmed !== true) fail(400, 'Подтвердите проверенный текст.');
          transaction(() => { run('UPDATE documents SET extracted=?,confirmed=1 WHERE id=?', extracted, d.id); run('INSERT INTO document_revisions VALUES(?,?,?,?,?)', randomUUID(), d.id, actor.id, extracted, iso()); });
          return send(200, { ok: true });
        }
      }
      const cm = rest.match(/^\/consultations\/([^/]+)(.*)$/); if (!cm) fail(404, 'Действие не найдено.');
      const [, cid, action] = cm; consultation(cid, pid);
      if (action === '' && method === 'GET') return send(200, readConsultation(cid, pid));
      if (action === '/messages' && method === 'POST') { const b = await body(req); run('INSERT INTO messages VALUES(?,?,?,?,?,?)', randomUUID(), cid, actor.id, 'user', text(b.text), iso()); return send(201, readConsultation(cid, pid)); }
      if (action === '/documents' && method === 'POST') {
        const b = await body(req), name = text(b.name, 160);
        if (typeof b.base64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(b.base64)) fail(400, 'Повреждённый файл.');
        const bytes = Buffer.from(b.base64, 'base64');
        if (!bytes.length || bytes.length > 8*1024*1024) fail(413, 'Допустимый размер файла: до 8 МБ.');
        const mime = bytes.subarray(0,5).toString() === '%PDF-' ? 'application/pdf' : bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])) ? 'image/png' : bytes.subarray(0,3).equals(Buffer.from([255,216,255])) ? 'image/jpeg' : null;
        if (!mime) fail(415, 'Поддерживаются PDF, PNG и JPEG.');
        const digest = hash(bytes);
        if (one('SELECT id FROM documents WHERE profile_id=? AND digest=?', pid, digest)) fail(409, 'Такой документ уже загружен в этот профиль.');
        const id = randomUUID(); run('INSERT INTO documents(id,profile_id,consultation_id,name,mime,bytes,digest,created) VALUES(?,?,?,?,?,?,?,?)', id, pid, cid, name, mime, bytes, digest, iso());
        return send(201, readConsultation(cid, pid));
      }
      if (action === '/run' && method === 'POST') {
        if (!ai.enabled) fail(503, 'ИИ ещё не подключён. Вопрос и документы сохранены.');
        const b = await body(req);
        if (!Array.isArray(b.specialists) || b.specialists.length < 1 || b.specialists.length > 4 || new Set(b.specialists).size !== b.specialists.length || b.specialists.some(x => !Object.hasOwn(SPECIALISTS, x))) fail(400, 'Выберите от одного до четырёх специалистов.');
        limit(`ai:${actor.id}`, 10, 60*60_000);
        if (one("SELECT id FROM runs WHERE consultation_id=? AND status='running'", cid)) fail(409, 'Обсуждение уже идёт.');
        if (activeJobs.size >= 2) fail(429, 'Сейчас идут два обсуждения. Повторите немного позже.');
        const c = readConsultation(cid, pid);
        if (c.documents.some(d => !d.confirmed)) fail(409, 'Сначала проверьте текст загруженных документов.');
        const context = { profile: { name: p.name, birthdate: p.birthdate }, messages: c.messages.map(m => ({ role: m.role, text: m.text })), documents: c.documents.map(d => ({ id: d.id, name: d.name, text: d.extracted })) };
        const snapshot = JSON.stringify(context);
        if (snapshot.length > 60000) fail(413, 'В разговоре слишком много данных. Начните отдельную консультацию.');
        const rid = randomUUID(); run('INSERT INTO runs VALUES(?,?,?,?,?,?,?)', rid, cid, 'running', snapshot, null, null, iso());
        const job = (async () => {
          try { const result = await ai.consult(context, b.specialists); transaction(() => { run('UPDATE runs SET status=?,result=? WHERE id=?', result.status, JSON.stringify(result), rid); if (result.status === 'completed') run('INSERT INTO messages VALUES(?,?,?,?,?,?)', randomUUID(), cid, actor.id, 'assistant', result.summary, iso()); }); }
          catch { run("UPDATE runs SET status='failed',error=? WHERE id=?", 'Не удалось завершить консилиум. Проверьте подключение ИИ и повторите.', rid); }
        })();
        activeJobs.add(job); void job.finally(() => activeJobs.delete(job));
        return send(202, { id: rid, status: 'running' });
      }
      fail(404, 'Действие не найдено.');
    } catch (error) { if (!res.headersSent) send(error.status || 500, { error: error.status ? error.message : 'Внутренняя ошибка. Повторите позже.' }); else res.end(); }
  }
  const server = http.createServer((req, res) => { void handle(req, res); });
  server.requestTimeout = 30_000; server.headersTimeout = 15_000;
  return { server, addAdmin, db, async close() { await new Promise(resolve => server.close(resolve)); await Promise.allSettled([...activeJobs]); db.close(); } };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const app = createApp();
  const { values } = parseArgs({ options: { port: { type: 'string' }, host: { type: 'string' }, strictPort: { type: 'boolean' } } });
  const port = Number(values.port || process.env.PORT || 3000), host = values.host || process.env.HOST || '127.0.0.1';
  app.server.listen(port, host, () => console.log(`МедКонсилиум: http://${host}:${port}`));
}
