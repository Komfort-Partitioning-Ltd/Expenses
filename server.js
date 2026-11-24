// Komfort Expenses System — shared multi-user API server.
// Serves the front-end and exposes a small REST API that mirrors the app's
// data helpers, backed by one shared SQLite database (see database.js), with
// real login (JWT + bcrypt) and role-based permissions.
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID: uuidv4 } = require('crypto');
const crypto = require('crypto');
const store = require('./database');
const mailer = require('./mailer');
const { installMicrosoftAuth, UUID } = require('./microsoft-auth');
const { KNOWN_STORES, canEdit, reportUpdate, receiptValid, safeId } = require('./security');

const { validateLine, structuralError, directoryUser, fingerprint, rateLimit, auditChanges, receiptBytes, MAX_USER_RECEIPT_BYTES } = require('./hardening');
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32 || JWT_SECRET === 'expenses-dev-secret-change-me')
  throw new Error('Configure JWT_SECRET before starting Expenses.');

// Behind a Cloudflare Tunnel every request arrives from cloudflared on loopback.
// Trusting loopback makes req.ip the real visitor (from X-Forwarded-For), so the
// per-IP rate limits apply per person rather than to the whole company at once.
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');

// The web app and Android WebView use same-origin requests; no wildcard CORS.
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' https://api.postcodes.io; worker-src 'self' blob:; frame-src 'self' data: blob:; font-src 'self'; object-src 'none'; form-action 'self'; frame-ancestors 'self'; base-uri 'self'",
    'Content-Security-Policy-Report-Only': "script-src 'self'; object-src 'none'; base-uri 'self'" });
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  next();
});
app.use('/api/auth/microsoft/start', rateLimit({limit:20,windowMs:60000}));
app.use('/api', rateLimit({limit:600,windowMs:60000}));
app.param('store', (req, res, next, name) => {
  if (!KNOWN_STORES.has(name)) return res.status(404).json({ error: 'Not found' });
  next();
});
app.use('/api/auth', express.json({limit:'16kb'}));
app.use(express.json({ limit: '25mb' }));
for(const [url,dir] of Object.entries({
 '/vendor/pdfjs':'pdfjs-dist/legacy/build','/vendor/pdfjs-cmaps':'pdfjs-dist/cmaps',
 '/vendor/pdfjs-fonts':'pdfjs-dist/standard_fonts','/vendor/pdfjs-wasm':'pdfjs-dist/wasm',
 '/vendor/tesseract':'tesseract.js/dist','/vendor/tesseract-core':'tesseract.js-core',
 '/vendor/ocr-eng':'@tesseract.js-data/eng/4.0.0_best_int'
})) app.use(url,express.static(path.join(__dirname,'node_modules',dir),{dotfiles:'deny',index:false}));
app.use(express.static(path.join(__dirname, 'public')));

// ── Helpers ──
const REF_STORES = ['categories', 'departments', 'locations', 'vehicle_types',
  'mileage_rates', 'advisory_rates', 'mileage_adjustments', 'suppliers', 'vat_rates'];
const FINANCE_ONLY_READ = ['audit_log', 'payment_runs'];

function keyField(s) { return s === 'settings' ? 'key' : 'id'; }
function role(user, r) { return Array.isArray(user.roles) && user.roles.includes(r); }
function strip(u) { return directoryUser({id:u?.id},u); }
function sessionUser(u, method) {
  const user = strip(u);
  if (method === 'microsoft' || method === 'local-admin') user.must_change_password = false;
  return user;
}

// ── Break-glass admin sign-in (initial set-up / recovery only) ──
// Off unless ADMIN_LOGIN_ENABLED=true, limited to one username, and only usable from
// the server machine itself: anything arriving through the Cloudflare Tunnel carries
// forwarding headers and is refused, so the page is not reachable from the internet.
const ADMIN_LOGIN_ENABLED = process.env.ADMIN_LOGIN_ENABLED === 'true';
const ADMIN_LOGIN_USERNAME = String(process.env.ADMIN_LOGIN_USERNAME || 'admin').toLowerCase();
function isDirectLocalRequest(req) {
  const addr = req.socket.remoteAddress || '';
  return ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(addr) &&
    !req.headers['x-forwarded-for'] && !req.headers['cf-connecting-ip'] && !req.headers['cf-ray'];
}
function adminLoginAllowed(req) { return ADMIN_LOGIN_ENABLED && isDirectLocalRequest(req); }
function signToken(u, method = 'microsoft') {
  return jwt.sign({ id: u.id, username: u.username, roles: u.roles, full_name: u.full_name, auth_method: method, session_fingerprint: fingerprint(u) },
    JWT_SECRET, { expiresIn: '1h', algorithm: 'HS256' });
}
function auth(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    const user = store.get('users', req.user.id);
    if (req.user.auth_method === 'local-admin') {
      // Break-glass sessions stop working as soon as the flag is turned off, and never work remotely.
      if (!adminLoginAllowed(req) || !user?.active || String(user.username).toLowerCase() !== ADMIN_LOGIN_USERNAME)
        return res.status(401).json({ error: 'Please sign in with Microsoft.' });
    } else {
      if (req.user.auth_method !== 'microsoft')
        return res.status(401).json({ error: 'Please sign in with Microsoft.' });
      if (!user?.active || !user.microsoft_oid)
        return res.status(401).json({ error: 'Account not available for Microsoft sign-in.' });
    }
    if (req.user.session_fingerprint !== fingerprint(user))
      return res.status(401).json({error:'Session revoked. Please sign in again.'});
    req.user.roles = user.roles;
    req.user.username = user.username;
    if (!Array.isArray(user.roles) || !user.roles.some(r => ['employee', 'manager', 'finance', 'credit_card'].includes(r))) {
      if (!['/api/me','/api/logout'].includes(req.path))
        return res.status(403).json({ error: 'Ask an admin to assign you permissions.' });
    }
    next();
  }
  catch (e) { return res.status(401).json({ error: 'Invalid or expired session' }); }
}

// Report visibility: finance sees all; owners see their own; a manager/finance
// approver sees reports of people who report to them.
function reportApprovers(report) {
  const owner = store.get('users', report.user_id);
  return owner ? [owner.approver1_id, owner.approver2_id] : [];
}
function canReadReport(user, report) {
  if (role(user, 'finance')) return true;
  if (report.user_id === user.id) return true;
  return reportApprovers(report).includes(user.id);
}
function recordAudit(user, action, details = {}) {
  const id = uuidv4();
  store.put('audit_log', id, { id, timestamp: new Date().toISOString(), user: user.username || user.id,
    actor_id: user.id, action, ...details });
}

// Stores that must never be exposed through the generic /api/store API.
const INTERNAL_STORES = ['reset_tokens'];

// ── Expense email notifications ──
const escapeHtml = value => String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtDate = d => d ? new Date(d).toLocaleDateString('en-GB') : '—';
function reportTotal(reportId) {
  return store.getAll('lines')
    .filter(l => l.report_id === reportId)
    .reduce((sum, l) => sum + Number(l.amount || 0), 0);
}
function notifyReport(report, stage) {
  try {
    const owner = store.get('users', report.user_id);
    if (!owner) return;
    const isCC = report.type === 'creditcard';
    const label = isCC ? 'Credit card report' : 'Expense claim';
    const subj = isCC ? 'Credit card report' : 'Expense';
    const approver1 = owner.approver1_id ? store.get('users', owner.approver1_id) : null;
    const approver2 = owner.approver2_id ? store.get('users', owner.approver2_id) : null;
    const money = '£' + reportTotal(report.id).toFixed(2);
    const ref = report.reference || report.title || report.id;
    const rows = [
      ['Employee', owner.full_name],
      ['Reference', ref],
      ['Amount', money],
      ['Submitted', fmtDate(report.submitted_at)],
      ['Manager approved', fmtDate(report.manager_approved_at)],
      ['Finance approved', fmtDate(report.finance_approved_at)],
    ];
    if (!isCC) rows.push(['Reimbursed', fmtDate(report.reimbursed_at)]);
    const table = '<table style="border-collapse:collapse;margin:8px 0">' +
      rows.map(([k, v]) => `<tr><td style="padding:3px 14px 3px 0;color:#666">${k}</td><td style="padding:3px 0"><strong>${escapeHtml(v)}</strong></td></tr>`).join('') +
      '</table>';
    let subject, intro, extra = null;
    if (stage === 'submitted') { subject = `${subj} ${escapeHtml(ref)} submitted — ${escapeHtml(owner.full_name)}`; intro = `${escapeHtml(owner.full_name)} has submitted ${label.toLowerCase()} <strong>${escapeHtml(ref)}</strong> for <strong>${money}</strong>, awaiting approval.`; extra = (approver1 || approver2 || {}).email; }
    else if (stage === 'manager_approved') { subject = `${subj} ${escapeHtml(ref)} approved by manager`; intro = `${label} <strong>${escapeHtml(ref)}</strong> (${money}) has been approved by the manager and is awaiting finance approval.`; extra = (approver2 || {}).email; }
    else if (stage === 'finance_approved') { subject = `${subj} ${escapeHtml(ref)} approved by finance`; intro = isCC ? `${label} <strong>${escapeHtml(ref)}</strong> (${money}) has been fully approved.` : `Expense claim <strong>${escapeHtml(ref)}</strong> (${money}) has been approved by finance and is due for reimbursement.`; extra = (approver2 || {}).email; }
    else if (stage === 'reimbursed') { subject = `Expense ${escapeHtml(ref)} reimbursed`; intro = `Expense claim <strong>${escapeHtml(ref)}</strong> (${money}) has been reimbursed.`; }
    else if (stage === 'rejected') { subject = `${subj} ${escapeHtml(ref)} returned for changes`; intro = `Your ${label.toLowerCase()} <strong>${escapeHtml(ref)}</strong> (${money}) has been <strong>returned for changes</strong>.` + (report.rejection_note ? ` Reason: <em>${String(report.rejection_note).replace(/</g, '&lt;')}</em>` : ' Please amend it and resubmit.'); }
    else return;
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222">
      <p>${intro}</p>${table}
      <p style="margin-top:16px"><a href="${mailer.APP_URL}" style="background:#565A5C;color:#fff;padding:9px 18px;border-radius:6px;text-decoration:none">Open the Expenses System</a></p>
      <p style="color:#999;font-size:12px">Komfort Partitioning Ltd — Expenses System</p></div>`;
    // Submitted expense claims also go to the purchase invoices mailbox (set SUBMISSION_NOTIFY_EMAIL= to turn off).
    const purchaseInvoices = stage === 'submitted' && !isCC ? SUBMISSION_NOTIFY_EMAIL : null;
    mailer.sendMail([owner.email, extra, purchaseInvoices], subject, html);
  } catch (e) { console.warn('notifyReport failed:', e.message); }
}
const SUBMISSION_NOTIFY_EMAIL = (process.env.SUBMISSION_NOTIFY_EMAIL ?? 'purchaseinvoices@komfort.co.uk').trim() || null;

// ── Claim / receipt messages ──
// Reviewers (manager or finance) raise amendments, rejections and questions on a line or the
// whole claim; the employee replies. Messages are server-managed and append-only, and the
// sender chooses whether the other side is emailed.
const MESSAGE_KINDS = { amendment: 'Amendment required', rejection: 'Receipt rejected', question: 'Question', reply: 'Reply' };
const REVIEWER_KINDS = ['amendment', 'rejection', 'question', 'reply'];
function lineSummary(line) {
  if (!line) return null;
  const what = line.line_type === 'mileage'
    ? `Mileage ${line.postcode_from || ''} → ${line.postcode_to || ''}`
    : (store.get('suppliers', line.supplier_id)?.name || line.description || 'Expense');
  return `${fmtDate(line.line_date)} · ${what} · £${(Number(line.amount) || 0).toFixed(2)}`;
}
function reportMessages(reportId) {
  return store.getAll('messages').filter(m => m.report_id === reportId)
    .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
}
app.get('/api/reports/:id/messages', auth, (req, res) => {
  const report = store.get('reports', req.params.id);
  if (!report || !canReadReport(req.user, report)) return res.status(404).json({ error: 'Report not found' });
  res.json(reportMessages(report.id));
});
app.post('/api/reports/:id/messages', auth, rateLimit({ limit: 30, windowMs: 60000 }), (req, res) => {
  const report = store.get('reports', req.params.id);
  if (!report || !canReadReport(req.user, report)) return res.status(404).json({ error: 'Report not found' });
  const { line_id, kind, body, notify } = req.body || {};
  const text = typeof body === 'string' ? body.trim() : '';
  if (!text || text.length > 4000) return res.status(400).json({ error: 'Enter a message of up to 4000 characters.' });
  const isOwner = report.user_id === req.user.id;
  if (!MESSAGE_KINDS[kind] || (isOwner ? kind !== 'reply' : !REVIEWER_KINDS.includes(kind)))
    return res.status(400).json({ error: 'Invalid message type.' });
  let line = null;
  if (line_id != null && line_id !== '') {
    if (!safeId(String(line_id))) return res.status(400).json({ error: 'Invalid line.' });
    line = store.get('lines', String(line_id));
    if (!line || line.report_id !== report.id) return res.status(400).json({ error: 'That line is not on this claim.' });
  }
  const owner = store.get('users', report.user_id);
  const author = store.get('users', req.user.id);
  // Who "the other side" is: the employee for reviewer messages; for employee replies, the
  // reviewers who have messaged on this claim, falling back to the assigned approvers.
  let recipients = [];
  if (notify) {
    if (!isOwner) recipients = [owner];
    else {
      const ids = [...new Set(reportMessages(report.id).map(m => m.author_id).filter(id => id !== report.user_id))];
      if (!ids.length) ids.push(...[owner?.approver1_id, owner?.approver2_id].filter(Boolean));
      recipients = ids.map(id => store.get('users', id));
    }
    recipients = recipients.filter(u => u && u.active && u.email && u.id !== req.user.id);
  }
  const id = uuidv4();
  const msg = { id, report_id: report.id, line_id: line?.id || null, line_summary: lineSummary(line), kind, body: text,
    author_id: req.user.id, author_name: author?.full_name || req.user.username, created_at: new Date().toISOString(),
    notify: !!notify, notified: recipients.map(u => u.full_name || u.email) };
  store.put('messages', id, msg);
  recordAudit(req.user, 'message_sent', { report_id: report.id, line_id: msg.line_id, kind, notified: msg.notified });
  if (recipients.length) {
    const ref = report.reference || report.title || report.id;
    const subject = `${MESSAGE_KINDS[kind]} — ${report.type === 'creditcard' ? 'Credit card report' : 'Expense claim'} ${ref}`;
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222">
      <p><strong>${escapeHtml(msg.author_name)}</strong> sent a message about ${escapeHtml(owner?.full_name || 'an')}'s claim <strong>${escapeHtml(ref)}</strong>:</p>
      ${msg.line_summary ? `<p style="color:#666">Line: ${escapeHtml(msg.line_summary)}</p>` : ''}
      <p style="border-left:4px solid #565A5C;padding:6px 12px;background:#f6f6f6;white-space:pre-wrap"><strong>${escapeHtml(MESSAGE_KINDS[kind])}:</strong> ${escapeHtml(text)}</p>
      <p style="margin-top:16px"><a href="${mailer.APP_URL}" style="background:#565A5C;color:#fff;padding:9px 18px;border-radius:6px;text-decoration:none">Open the Expenses System</a></p>
      <p style="color:#999;font-size:12px">Komfort Partitioning Ltd — Expenses System</p></div>`;
    mailer.sendMail(recipients.map(u => u.email), subject, html);
  }
  res.json(msg);
});

// ── Auth endpoints ──
installMicrosoftAuth(app, { store, session: u => {
  recordAudit(u, 'login', { method: 'microsoft' });
  return { token: signToken(u, 'microsoft'), user: sessionUser(u, 'microsoft') };
} });
// Retired routes stay blocked for older website and Android clients.
const microsoftOnly = (req, res) => res.status(403).json({ error: 'Please sign in with Microsoft. Password sign-in is disabled.' });
for (const route of ['/api/login', '/api/change-password', '/api/forgot-password', '/api/reset-password']) {
  app.post(route, microsoftOnly);
}

// Break-glass page and endpoint: a plain 404 unless enabled and opened on the server itself.
app.get('/admin', (req, res) => {
  if (!adminLoginAllowed(req)) return res.status(404).send('Not found');
  res.sendFile(path.join(__dirname, 'admin-login.html'));
});
app.post('/api/auth/admin-login', rateLimit({ limit: 5, windowMs: 60000 }), (req, res) => {
  if (!adminLoginAllowed(req)) return res.status(404).json({ error: 'Not found' });
  const { username, password } = req.body || {};
  const u = store.getAll('users').find(x => String(x.username).toLowerCase() === ADMIN_LOGIN_USERNAME);
  const ok = u && u.active && String(username || '').toLowerCase() === ADMIN_LOGIN_USERNAME &&
    typeof password === 'string' && u.password_hash && bcrypt.compareSync(password, u.password_hash);
  if (!ok) {
    if (u) recordAudit(u, 'admin_login_failed', { method: 'local-admin' });
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  recordAudit(u, 'login', { method: 'local-admin' });
  console.warn(`Break-glass admin sign-in by ${u.username} at ${new Date().toISOString()}`);
  res.json({ token: signToken(u, 'local-admin'), user: sessionUser(u, 'local-admin') });
});

app.get('/api/me', auth, (req, res) => {
  const u = store.get('users', req.user.id);
  if (!u || !u.active) return res.status(401).json({ error: 'Account not available' });
  res.json(sessionUser(u, req.user.auth_method));
});

app.post('/api/logout', auth, (req,res) => {
  const user=store.get('users',req.user.id);
  store.put('users',user.id,{...user,session_version:(user.session_version||0)+1});
  store.save?.();
  recordAudit(req.user,'logout');
  res.json({ok:true});
});

// Download a fresh copy of the whole database (finance only) for off-site backup.
app.get('/api/backup', auth, (req, res) => {
  if (!role(req.user, 'finance')) return res.status(403).json({ error: 'Finance only' });
  recordAudit(req.user,'database_backup_downloaded');
  store.save();
  const name = 'komfort-expenses-backup-' + new Date().toISOString().slice(0, 10) + '.db';
  res.download(store.DB_PATH, name);
});

// Trigger an immediate on-disk snapshot (finance only).
app.post('/api/backup/run', auth, (req, res) => {
  if (!role(req.user, 'finance')) return res.status(403).json({ error: 'Finance only' });
  store.backupDb();
  res.json({ ok: true });
});

// Email diagnostic — sends a test email and returns the exact result (so we can
// see Graph/SMTP errors). Allowed for a logged-in finance user, or via a secret
// ?key=<MAIL_TEST_KEY> query (env-set) so it can be checked without logging in.
app.post('/api/test-email', auth, rateLimit({limit:3,windowMs:60000}), async (req,res) => {
  if(!role(req.user,'finance')) return res.status(403).json({error:'Finance only'});
  const to=mailer.mailStatus().sender;
  const result=await mailer.sendResult(to,'Komfort Expenses — test email','<p>Expenses email configuration test.</p>');
  recordAudit(req.user,'email_test');
  res.json({ok:!!result.ok});
});

// Never expose internal stores (e.g. reset tokens) through the generic API.
app.use('/api/store', (req, res, next) => {
  const s = req.path.split('/').filter(Boolean)[0];
  if (INTERNAL_STORES.includes(s)) return res.status(404).json({ error: 'Not found' });
  next();
});

// ── Read scoping ──
function scopedGetAll(user, s) {
  const all = store.getAll(s);
  if (s === 'users') return all.map(u=>directoryUser(user,u));
  if (s === 'reports') return all.filter(r => canReadReport(user, r));
  if (s === 'lines') return all.filter(l => {
    const rep = store.get('reports', l.report_id);
    return rep && canReadReport(user, rep);
  });
  if (FINANCE_ONLY_READ.includes(s)) return role(user, 'finance') ? all : [];
  return all; // reference data + settings: any authenticated user
}

// ── Generic store API (mirrors idbGetAll / idbGet / idbPut / idbDelete / idbByIndex) ──
app.get('/api/store/:store', auth, (req, res) => {
  res.json(scopedGetAll(req.user, req.params.store));
});

app.get('/api/store/:store/index/:field/:value', auth, (req, res) => {
  const { store: s, field, value } = req.params;
  const rows = scopedGetAll(req.user, s).filter(r => String(r[field]) === String(value));
  res.json(rows);
});

app.get('/api/store/:store/:key', auth, (req, res) => {
  const { store: s, key } = req.params;
  const rec = store.get(s, key);
  if (!rec) return res.json(null);
  if (s === 'users') return res.json(directoryUser(req.user,rec));
  if (s === 'reports' && !canReadReport(req.user, rec)) return res.status(403).json({ error: 'Forbidden' });
  if (s === 'lines') {
    const rep = store.get('reports', rec.report_id);
    if (!(rep && canReadReport(req.user, rep))) return res.status(403).json({ error: 'Forbidden' });
  }
  if (FINANCE_ONLY_READ.includes(s) && !role(req.user, 'finance')) return res.status(403).json({ error: 'Forbidden' });
  res.json(rec);
});

app.put('/api/store/:store', auth, (req, res) => {
  const s = req.params.store;
  let obj = req.body || {};
  const user = req.user;
  let prevReport = null;
  if (!obj || typeof obj !== 'object' || Array.isArray(obj))
    return res.status(400).json({ error: 'Invalid record.' });
  const shapeError=structuralError(obj);
  if(shapeError) return res.status(400).json({error:shapeError});
  const previousRecord=obj[keyField(s)] ? store.get(s,obj[keyField(s)]) : null;
  if (s === 'audit_log') return res.status(403).json({ error: 'Audit entries are managed by the server.' });
  for (const [field, value] of Object.entries(obj)) {
    if ((field === 'id' || field.endsWith('_id')) && value != null && value !== '' && !safeId(String(value)))
      return res.status(400).json({ error: 'Invalid record identifier.' });
  }

  // Reference data: any authenticated user may add a supplier; other reference
  // writes are finance-only.
  if (REF_STORES.includes(s) && s !== 'suppliers' && !role(user, 'finance'))
    return res.status(403).json({ error: 'Finance only' });
  if (s === 'settings' && !role(user, 'finance')) return res.status(403).json({ error: 'Finance only' });
  if (s === 'payment_runs' && !role(user, 'finance')) return res.status(403).json({ error: 'Finance only' });

  if (s === 'suppliers') {
    if(previousRecord && !role(user,'finance')) return res.status(403).json({error:'Only finance can change existing suppliers.'});
    if(typeof obj.name!=='string'||!obj.name.trim()||obj.name.length>200) return res.status(400).json({error:'Supplier name is required (up to 200 characters).'});
    obj={id:obj.id||uuidv4(),name:obj.name.trim(),active:role(user,'finance')?(obj.active===0?0:1):1,created_by:previousRecord?.created_by||user.id,created_at:previousRecord?.created_at||new Date().toISOString()};
  }
  if (s === 'users') {
    if(!role(user,'finance') && obj.id!==user.id) return res.status(403).json({error:'Forbidden'});
    if(obj.full_name!==undefined && (typeof obj.full_name!=='string'||!obj.full_name.trim()||obj.full_name.length>200)) return res.status(400).json({error:'A name of up to 200 characters is required.'});
    // Microsoft-only accounts never accept password material from client updates.
    delete obj.password;
    delete obj.password_hash;
    const existing = obj.id ? store.get('users', obj.id) : null;
    const isSelf = existing && existing.id === user.id;
    // Only finance administrators may link a directory identity to an expense user.
    const microsoftOid = String(obj.microsoft_oid ?? existing?.microsoft_oid ?? '').trim().toLowerCase();
    if (!role(user, 'finance') && microsoftOid !== (existing?.microsoft_oid || ''))
      return res.status(403).json({ error: 'Only finance can change Microsoft account links' });
    if (microsoftOid && !UUID.test(microsoftOid))
      return res.status(400).json({ error: 'Microsoft user object ID must be a valid UUID' });
    if (microsoftOid && store.getAll('users').some(u => u.id !== obj.id && u.microsoft_oid?.toLowerCase() === microsoftOid))
      return res.status(400).json({ error: 'This Microsoft account is already linked to another user' });
    obj.microsoft_oid = microsoftOid || null;
    if (!role(user, 'finance')) {
      if (!isSelf) return res.status(403).json({ error: 'Forbidden' });
      // Non-finance users cannot change their own roles or active flag (no privilege escalation)
      obj = { ...existing, full_name: obj.full_name ?? existing.full_name };
    }
    if (existing && !obj.password_hash) obj.password_hash = existing.password_hash; // keep current password on edits
    obj.session_version=existing?.session_version||0;
    if (!obj.id) obj.id = uuidv4();
    if (!obj.password_hash) obj.password_hash = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 10);
  }

  if (s === 'reports') {
    const existing = obj.id ? store.get('reports', obj.id) : null;
    prevReport = existing;
    const checked = reportUpdate(existing, obj, user, store);
    if (checked.error) return res.status(403).json({ error: checked.error });
    obj = checked.record;
    if (existing) {
      obj.user_id = existing.user_id;                        // ownership is fixed once set
      if (existing.created_at) obj.created_at = existing.created_at;
      if (existing.reference) obj.reference = existing.reference;   // keep the assigned reference
    } else {
      if (!role(user, 'finance')) obj.user_id = user.id;     // new reports are owned by their creator
      if (!obj.reference) {                                  // assign a sequential reference server-side
        const cc = obj.type === 'creditcard';
        const n = store.nextCounter(cc ? 'seq_creditcard' : 'seq_expense');
        obj.reference = `${cc ? 'KPLCC' : 'KPLEXP'}-${String(n).padStart(6, '0')}`;
      }
    }
    if (!existing && store.getAll('reports').filter(r=>r.user_id===obj.user_id).length>=1000) return res.status(413).json({error:'Account report quota reached.'});
    if (!obj.id) obj.id = uuidv4();
  }

  if (s === 'lines') {
    const existingLine = obj.id ? store.get('lines', obj.id) : null;
    if (existingLine && existingLine.report_id !== obj.report_id)
      return res.status(403).json({ error: 'An expense line cannot move to another report.' });
    const rep = store.get('reports', obj.report_id);
    if (!rep || !canEdit(user, rep)) return res.status(403).json({ error: 'This report is read-only.' });
    const lineError=validateLine(obj,store);
    if(lineError) return res.status(400).json({error:lineError});
    const ownedReports=new Set(store.getAll('reports').filter(r=>r.user_id===rep.user_id).map(r=>r.id));
    const otherLines=store.getAll('lines').filter(l=>ownedReports.has(l.report_id)&&l.id!==obj.id);
    if(otherLines.length>=5000) return res.status(413).json({error:'Account expense-line quota reached.'});
    const usedBytes=otherLines.reduce((n,l)=>n+(l.receipts||[]).reduce((m,r)=>m+(typeof r.data==='string'?r.data.length:0),0),0);
    const newBytes=(obj.receipts||[]).reduce((n,r)=>n+r.data.length,0);
    if(usedBytes+newBytes>MAX_USER_RECEIPT_BYTES) return res.status(413).json({error:'Account receipt-storage quota reached.'});
    if (!obj.id) obj.id = uuidv4();
  }

  const kf = keyField(s);
  if (obj[kf] === undefined || obj[kf] === null) obj[kf] = uuidv4();
  const key = obj[kf];
  store.put(s, key, obj);
  if(s==='users') store.save?.();
  recordAudit(user, s + '_saved', { store: s, record_id: String(key), changes:auditChanges(previousRecord,obj), ...(s === 'reports' ? { previous_status: prevReport?.status || null, status: obj.status } : {}) });
  if (s === 'reports') {
    const was = prevReport || {};
    const awaiting = st => st === 'awaiting_manager' || st === 'awaiting_finance';
    if (obj.status === 'rejected' && was.status !== 'rejected') notifyReport(obj, 'rejected');
    else if (awaiting(obj.status) && !awaiting(was.status)) notifyReport(obj, 'submitted'); // first submit or resubmit
    else if (!was.manager_approved_at && obj.manager_approved_at) notifyReport(obj, 'manager_approved');
    else if (!was.finance_approved_at && obj.finance_approved_at) notifyReport(obj, 'finance_approved');
    else if (!was.reimbursed_at && obj.reimbursed_at) notifyReport(obj, 'reimbursed');
  }
  res.json({ key, id: obj.id, [kf]: obj[kf] });
});

app.delete('/api/store/:store/:key', auth, (req, res) => {
  const { store: s, key } = req.params;
  const user = req.user;
  if (s === 'audit_log') return res.status(403).json({ error: 'Audit entries cannot be deleted.' });
  if(s==='suppliers'){
    if(!role(user,'finance'))return res.status(403).json({error:'Only finance can delete suppliers.'});
    if(store.getAll('lines').some(l=>l.supplier_id===key))return res.status(409).json({error:'This supplier is used by expense lines. Deactivate it instead.'});
  }
  if (s === 'users') {
    if (!role(user, 'finance')) return res.status(403).json({ error: 'Finance only' });
    if (key === user.id) return res.status(400).json({ error: 'You cannot delete your own account.' });
    if (!store.get('users', key)) return res.status(404).json({ error: 'User not found.' });
    if (store.getAll('reports').some(report => report.user_id === key))
      return res.status(409).json({ error: 'This user has expense reports. Disable their account instead to preserve expense history.' });
    if (store.getAll('users').some(u => u.id !== key && [u.approver1_id, u.approver2_id].includes(key)))
      return res.status(409).json({ error: 'This user is assigned as an approver. Reassign their approvals or disable their account first.' });
  }
  if (s === 'reports') {
    const rep = store.get('reports', key);
    if (rep && !canEdit(user, rep)) return res.status(403).json({ error: 'Forbidden' });
  }
  if (s === 'lines') {
    const l = store.get('lines', key);
    if (l) { const rep = store.get('reports', l.report_id); if (rep && !canEdit(user, rep)) return res.status(403).json({ error: 'Forbidden' }); }
  }
  if (REF_STORES.includes(s) && s !== 'suppliers' && !role(user, 'finance')) return res.status(403).json({ error: 'Finance only' });
  if ((s === 'payment_runs' || s === 'settings') && !role(user, 'finance')) return res.status(403).json({ error: 'Finance only' });
  store.del(s, key);
  recordAudit(user, s + '_deleted', { store: s, record_id: String(key) });
  res.json({ ok: true });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const status = error.type === 'entity.too.large' ? 413 : error instanceof SyntaxError ? 400 : 500;
  res.status(status).json({error:status===413?'Request is too large.':status===400?'Invalid request.':'Unable to complete this request.'});
});

store.initDb().then(() => {
  const HOST = process.env.HOST || '127.0.0.1'; // loopback only: the public route is the Cloudflare Tunnel
  app.listen(PORT, HOST, () => {
    console.log(`Komfort Expenses System running on http://${HOST}:${PORT}`);
    if (ADMIN_LOGIN_ENABLED) console.warn(`Break-glass admin sign-in is ON for "${ADMIN_LOGIN_USERNAME}" at http://localhost:${PORT}/admin (this machine only). Set ADMIN_LOGIN_ENABLED=false after set-up.`);
  });
}).catch(err => { console.error('Failed to start:', err); process.exit(1); });
