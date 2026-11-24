const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

function fixture({ android = false, enabled = true, stored, hash = '', respond } = {}) {
  const elements = new Map(), storage = new Map(stored ? [['komfort_microsoft_pending', JSON.stringify(stored)]] : []);
  const requests = [], navigations = [], messages = [], sessions = [], timers = new Map();
  const el = id => {
    if (!elements.has(id)) elements.set(id, { disabled: true, hidden: true, textContent: '', events: {}, addEventListener(name, fn) { this.events[name] = fn; } });
    return elements.get(id);
  };
  const context = {
    document: { getElementById: el, addEventListener() {} },
    sessionStorage: { getItem: k => storage.get(k) || null, setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) },
    location: { hash, pathname: '/', search: '', assign: url => navigations.push(url) },
    history: { replaceState() {} },
    navigator: { userAgent: android ? 'KomfortExpensesApp/1.0' : 'browser' },
    crypto: webcrypto, TextEncoder, Uint8Array, AbortSignal, btoa, console,
    setTimeout: fn => { const id = timers.size + 1; timers.set(id, fn); return id; },
    clearTimeout: id => timers.delete(id),
    fetch: async (url, options) => {
      const data = options.body && JSON.parse(options.body);
      requests.push({ url, data });
      const result = url.endsWith('/config') ? { enabled } : await respond(url, data);
      return { ok: true, json: async () => result };
    },
  };
  context.window = { addEventListener() {}, __komfortMicrosoftNative: android,
    KomfortAndroid: android ? { postMessage: message => messages.push(JSON.parse(message)) } : undefined };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../public/microsoft-signin.js'), 'utf8'), context);
  return { ui: context.window.KomfortMicrosoft, el, requests, navigations, messages, sessions, storage, timers,
    init: () => context.window.KomfortMicrosoft.init(s => sessions.push(s)) };
}

test('login button is disabled when the server has no Microsoft configuration', async () => {
  const f = fixture({ enabled: false });
  await f.init();
  assert.equal(f.el('microsoft-signin').disabled, true);
  assert.match(f.el('microsoft-status').textContent, /not configured/);
});

test('browser start stores private proof and navigates only to the backend authorization URL', async () => {
  const f = fixture({ respond: async () => ({ state: 's'.repeat(43), url: 'https://expenses.example/api/auth/microsoft/authorize?state=s' }) });
  await f.init();
  await f.el('microsoft-signin').events.click();
  const pending = JSON.parse(f.storage.get('komfort_microsoft_pending'));
  assert.equal(pending.verifier.length, 43);
  assert.equal(f.requests[1].data.mode, 'web');
  assert.notEqual(pending.verifier, f.requests[1].data.challenge);
  assert.equal(f.navigations.length, 1);
  assert.ok(!f.navigations[0].includes(pending.verifier));
});

test('Android uses native bridge and polls while the browser handles sign-in', async () => {
  const f = fixture({ android: true, respond: async url => url.endsWith('/start')
    ? { state: 's'.repeat(43), url: 'https://expenses.example/api/auth/microsoft/authorize?state=s' } : { pending: true } });
  await f.init();
  await f.el('microsoft-signin').events.click();
  assert.equal(f.messages[0].type, 'microsoftSignIn');
  assert.equal(f.requests[1].data.mode, 'android');
  assert.equal(f.navigations.length, 0);
  assert.equal(f.timers.size, 1);
  f.el('microsoft-cancel').events.click();
  assert.equal(f.storage.size, 0);
  assert.equal(f.timers.size, 0);
});

test('redirect completion signs in once and discards temporary proof', async () => {
  const state = 's'.repeat(43);
  const f = fixture({ stored: { state, verifier: 'v'.repeat(43), expires: Date.now() + 10000 }, hash: '#microsoft=' + state,
    respond: async () => ({ token: 'session', user: { id: 'u' } }) });
  assert.equal(await f.init(), true);
  assert.equal(f.sessions.length, 1);
  assert.equal(f.storage.size, 0);
});

test('a return in a different browser cannot finish sign-in', async () => {
  const f = fixture({ hash: '#microsoft=' + 's'.repeat(43) });
  await f.init();
  assert.equal(f.sessions.length, 0);
  assert.match(f.el('microsoft-status').textContent, /start Microsoft sign-in again/);
});

test('cancelling a start request prevents a late response from redirecting', async () => {
  let resolveStart;
  const f = fixture({ respond: () => new Promise(resolve => { resolveStart = resolve; }) });
  await f.init();
  const start = f.el('microsoft-signin').events.click();
  while (!resolveStart) await new Promise(resolve => setImmediate(resolve));
  f.el('microsoft-cancel').events.click();
  resolveStart({ state: 's'.repeat(43), url: 'https://expenses.example/auth' });
  await start;
  assert.equal(f.navigations.length, 0);
  assert.equal(f.storage.size, 0);
});
