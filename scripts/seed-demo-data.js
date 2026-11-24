// Adds example staff, claims, lines, receipts and messages to a LOCAL test instance.
// It goes through the normal API, so every record passes the same checks as real use.
//
//   npm start                                   (server running locally, ADMIN_LOGIN_ENABLED=true)
//   node --env-file=.env scripts/seed-demo-data.js <admin-password>
//
// Demo staff use @example.com addresses and fake Microsoft IDs, so no real person is emailed
// and nobody can sign in as them. Never run this against the live database.
const path = require('path');
const crypto = require('crypto');
const jwt = require(path.join(__dirname, '..', 'node_modules', 'jsonwebtoken'));
const { fingerprint } = require(path.join(__dirname, '..', 'hardening'));

const BASE = `http://127.0.0.1:${process.env.PORT || 3000}`;
const password = process.argv[2];
if (!password) { console.error('Usage: node --env-file=.env scripts/seed-demo-data.js <admin-password>'); process.exit(1); }
if (!process.env.JWT_SECRET) { console.error('JWT_SECRET missing: run with --env-file=.env'); process.exit(1); }

async function call(token, method, url, body) {
  const r = await fetch(BASE + url, { method, headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) throw new Error(`${method} ${url} -> ${r.status} ${data?.error || ''}`);
  return data;
}
const put = (t, store, obj) => call(t, 'PUT', '/api/store/' + store, obj);
const get = (t, store, id) => call(t, 'GET', `/api/store/${store}/${encodeURIComponent(id)}`);
const all = (t, store) => call(t, 'GET', '/api/store/' + store);
const message = (t, reportId, msg) => call(t, 'POST', `/api/reports/${reportId}/messages`, msg);
async function move(t, reportId, status, extra = {}) {
  const current = await get(t, 'reports', reportId);
  return put(t, 'reports', { ...current, status, ...extra });
}

// A small one-page PDF "receipt" so the receipt viewer and messages have something to point at.
function receiptPdf(lines) {
  const esc = s => s.replace(/[\\()]/g, m => '\\' + m);
  const content = 'BT /F1 14 Tf 50 780 Td ' + lines.map((l, i) => `${i ? '0 -22 Td ' : ''}(${esc(l)}) Tj`).join(' ') + ' ET';
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let pdf = '%PDF-1.4\n'; const offsets = [];
  objs.forEach((o, i) => { offsets.push(Buffer.byteLength(pdf)); pdf += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offsets.map(o => String(o).padStart(10, '0') + ' 00000 n \n').join('');
  pdf += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return { name: 'receipt.pdf', mime: 'application/pdf', data: 'data:application/pdf;base64,' + Buffer.from(pdf).toString('base64') };
}

(async () => {
  const login = await (await fetch(BASE + '/api/auth/admin-login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password }) })).json();
  if (!login.token) throw new Error('Admin sign-in failed: ' + (login.error || 'is ADMIN_LOGIN_ENABLED=true and the server running?'));
  const A = login.token;

  const users = await all(A, 'users');
  if (users.some(u => u.id.startsWith('demo-'))) { console.log('Demo data is already present; nothing to do.'); return; }
  const finance = users.find(u => u.microsoft_oid && u.roles?.includes('finance')) || users.find(u => u.roles?.includes('finance'));
  if (!finance?.microsoft_oid) throw new Error('Link a finance user to Microsoft first (they act as the finance approver).');

  const byName = async (store, name) => (await all(A, store)).find(x => x.name === name)?.id
    || (() => { throw new Error(`No ${store} named "${name}"`); })();
  const dept = { sales: await byName('departments', 'Sales'), fitting: await byName('departments', 'Fitting Labour'), hr: await byName('departments', 'HR') };
  const loc = { leeds: await byName('locations', 'Leeds'), crawley: await byName('locations', 'Crawley'), central: await byName('locations', 'Central') };
  const sup = { inn: await byName('suppliers', 'Premier Inn'), shell: await byName('suppliers', 'Shell'), rail: await byName('suppliers', 'National Rail') };
  const cats = await all(A, 'categories');
  const cat = n => (cats.find(c => c.name === n) || cats.find(c => c.name === 'Travel') || cats[0]).id;
  const vats = await all(A, 'vat_rates');
  const VAT20 = vats.find(v => Number(v.percent) === 20).id, NOVAT = vats.find(v => v.name === 'No VAT')?.id || vats[0].id;
  const rates = await all(A, 'mileage_rates');
  const rate = rates.find(r => r.vehicle_type === 'Car - Diesel - up to 1600cc') || rates[0];

  // ── Staff ──
  const oid = () => crypto.randomUUID();
  const staff = {
    sarah: { id: 'demo-sarah', full_name: 'Sarah Mitchell', roles: ['employee', 'manager'], department_id: dept.sales, location_id: loc.leeds, approver1_id: null },
    tom:   { id: 'demo-tom', full_name: 'Tom Harris', roles: ['employee', 'manager'], department_id: dept.fitting, location_id: loc.crawley, approver1_id: null },
    priya: { id: 'demo-priya', full_name: 'Priya Shah', roles: ['employee'], department_id: dept.sales, location_id: loc.leeds, approver1_id: 'demo-sarah' },
    dan:   { id: 'demo-dan', full_name: 'Dan Cooper', roles: ['employee'], department_id: dept.sales, location_id: loc.leeds, approver1_id: 'demo-sarah' },
    liam:  { id: 'demo-liam', full_name: "Liam O'Brien", roles: ['employee'], department_id: dept.fitting, location_id: loc.crawley, approver1_id: 'demo-tom' },
    emma:  { id: 'demo-emma', full_name: 'Emma Clarke', roles: ['employee', 'credit_card'], department_id: dept.hr, location_id: loc.central, approver1_id: 'demo-tom' },
  };
  let n = 0;
  for (const s of Object.values(staff)) {
    const email = s.full_name.toLowerCase().replace(/[^a-z ]/g, '').replace(' ', '.') + '@example.com';
    await put(A, 'users', { ...s, username: email, email, microsoft_oid: oid(), approver2_id: finance.id, active: 1,
      account_number: 'E8' + String(100 + ++n), must_change_password: false });
  }
  // Sessions for each demo person (local only), built exactly like a Microsoft sign-in session.
  const tokenFor = async id => {
    const u = id === finance.id ? finance : await get(A, 'users', id);
    return jwt.sign({ id: u.id, username: u.username, roles: u.roles, full_name: u.full_name, auth_method: 'microsoft',
      session_fingerprint: fingerprint(u) }, process.env.JWT_SECRET, { expiresIn: '1h', algorithm: 'HS256' });
  };
  const T = {}; for (const k of Object.keys(staff)) T[k] = await tokenFor(staff[k].id);
  const F = await tokenFor(finance.id);

  // ── Helpers to build claims ──
  const vatOf = gross => Math.round(gross / 6 * 100) / 100; // 20% VAT inside a gross amount
  async function claim(t, id, type, title, lines) {
    await put(t, 'reports', { id, user_id: id.split('-rep')[0], type, title, status: 'unsubmitted', notes: '' });
    for (const [i, l] of lines.entries()) await put(t, 'lines', { id: `${id}-l${i + 1}`, report_id: id, ...l });
    return id;
  }
  const expense = (date, supplier, category, gross, desc, receipt, vat = true) => ({
    line_type: 'expense', line_date: date, description: desc, supplier_id: supplier, category_id: cat(category),
    vat_rate_id: vat ? VAT20 : NOVAT, amount: gross, vat_amount: vat ? vatOf(gross) : 0, receipts: receipt ? [receiptPdf(receipt)] : [] });
  const mileage = (date, from, to, miles, desc) => {
    const amount = Math.round(miles * rate.rate_pence) / 100;
    return { line_type: 'mileage', line_date: date, description: desc, supplier_id: '', category_id: '', vat_rate_id: '',
      amount, vat_amount: Math.round(miles * rate.afr_pence / 6) / 100, postcode_from: from, postcode_to: to, distance_miles: miles,
      vehicle_type: rate.vehicle_type, vehicle_reg: 'KP21 XYZ', mileage_rate_id: rate.id, company_car: false, return_journey: true,
      rate_up: Number(rate.rate_pence), rate_over: Number(rate.rate_over_pence), rate_adv: Number(rate.afr_pence),
      miles_under: miles, miles_over: 0, receipts: [] };
  };
  const make = (key, n2, type, title, lines) => claim(T[key], `demo-${key}-rep${n2}`, type, title, lines);
  const submit = (key, id) => move(T[key], id, staff[key].approver1_id ? 'awaiting_manager' : 'awaiting_finance');
  const mgr = key => T[staff[key].approver1_id.replace('demo-', '')];

  // 1. Priya: draft, not yet submitted
  await make('priya', 1, 'expense', 'November 2026 Expenses', [
    expense('2026-11-18', sup.rail, 'Travel', 64.20, 'Leeds to London, client meeting', ['National Rail', 'Off-peak return', 'Total GBP 64.20']),
    expense('2026-11-18', null, 'Subsistence', 12.85, 'Lunch', ['Pret A Manger', 'Total GBP 12.85']),
  ]);
  // 2. Priya: submitted, waiting for Sarah
  let id = await make('priya', 2, 'expense', 'Manchester site survey', [
    mileage('2026-11-12', 'LS1 4DY', 'M1 1AE', 88, 'Site survey, Piccadilly fit-out'),
    expense('2026-11-12', sup.shell, 'Fuel', 15.00, 'Top-up', ['Shell Leeds Road', 'Diesel 9.8L', 'Total GBP 15.00']),
  ]);
  await submit('priya', id);
  // 3. Dan: manager approved, waiting for finance; finance has queried a receipt and Dan has replied
  id = await make('dan', 1, 'expense', 'October 2026 Expenses', [
    expense('2026-10-21', sup.inn, 'Accommodation', 89.00, 'Overnight, Sheffield install', ['Premier Inn Sheffield', '1 night room only', 'Total GBP 89.00']),
    expense('2026-10-22', null, 'Subsistence', 46.30, 'Team dinner (3 people)', ['The Botanist', 'Total GBP 46.30']),
  ]);
  await submit('dan', id);
  await move(mgr('dan'), id, 'awaiting_finance');
  await message(F, id, { line_id: `${id}-l2`, kind: 'question', body: 'Who were the other two people at dinner? We need names for the subsistence policy.', notify: true });
  await message(T.dan, id, { line_id: `${id}-l2`, kind: 'reply', body: 'Me, Liam and Tom from the fitting team — we finished the Sheffield install late.', notify: true });
  await message(F, id, { line_id: `${id}-l1`, kind: 'amendment', body: 'The hotel receipt shows "room only" but the claim says breakfast was included — please confirm.', notify: false });
  // 4. Liam: returned by Tom for changes, with a rejected receipt
  id = await make('liam', 1, 'expense', 'Crawley install — week 45', [
    expense('2026-11-04', sup.shell, 'Fuel', 72.40, 'Van fuel', ['Shell Crawley', 'Total GBP 72.40']),
    expense('2026-11-05', null, 'Tools', 38.99, 'Replacement drill bits', null),
  ]);
  await submit('liam', id);
  await message(mgr('liam'), id, { line_id: `${id}-l2`, kind: 'rejection', body: 'No receipt attached for the drill bits. Please add it or remove the line.', notify: true });
  await message(mgr('liam'), id, { line_id: `${id}-l1`, kind: 'question', body: 'Was this for the company van or your own car?', notify: true });
  await move(mgr('liam'), id, 'rejected', { rejection_note: 'Missing receipt for the drill bits — see messages.' });
  // 5. Liam: fully approved, waiting for reimbursement
  id = await make('liam', 2, 'expense', 'Gatwick hotel stay', [
    expense('2026-10-28', sup.inn, 'Accommodation', 112.00, 'Overnight, Gatwick South install', ['Premier Inn Gatwick', 'Total GBP 112.00']),
  ]);
  await submit('liam', id); await move(mgr('liam'), id, 'awaiting_finance'); await move(F, id, 'awaiting_reimbursement');
  // 6. Emma: reimbursed through a payment run
  id = await make('emma', 1, 'expense', 'September 2026 Expenses', [
    mileage('2026-09-15', 'RH10 9AT', 'BN1 1AA', 46, 'Brighton client visit'),
    expense('2026-09-15', null, 'Subsistence', 9.60, 'Parking', ['NCP Brighton', 'Total GBP 9.60'], false),
  ]);
  await submit('emma', id); await move(mgr('emma'), id, 'awaiting_finance'); await move(F, id, 'awaiting_reimbursement');
  const runId = 'demo-run-1';
  await put(F, 'payment_runs', { id: runId, reference: 'PR-DEMO-001', run_date: '2026-10-01', created_by: finance.id, total: 30.30,
    status: 'completed', notes: 'Example payment run', report_ids: [id], created_at: new Date().toISOString() });
  await move(F, id, 'reimbursed', { payment_run_id: runId });
  // 7. Emma: credit card report, fully approved
  id = await make('emma', 2, 'creditcard', 'Credit Card October 2026', [
    expense('2026-10-03', null, 'IT Hardware', 249.99, 'Laptop dock for new starter', ['Currys Business', 'Total GBP 249.99']),
    expense('2026-10-09', sup.rail, 'Travel', 31.50, 'Interview candidate travel', ['National Rail', 'Total GBP 31.50']),
  ]);
  await submit('emma', id); await move(mgr('emma'), id, 'awaiting_finance'); await move(F, id, 'approved');
  // 8. Tom (manager, reports straight to finance): waiting for finance
  id = await make('tom', 1, 'expense', 'Supplier visit — Birmingham', [
    mileage('2026-11-20', 'RH10 9AT', 'B1 1BB', 154, 'Visit to partition supplier'),
  ]);
  await submit('tom', id);
  await message(F, id, { kind: 'question', body: 'Can you add the purpose of the supplier visit to the notes?', notify: true });

  console.log('Demo data added: 6 staff (Sarah & Tom are managers), 8 claims across every status, receipts and messages.');
})().catch(e => { console.error('Seeding stopped:', e.message); process.exit(1); });
