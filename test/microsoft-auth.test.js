const { test } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const crypto = require('crypto');
const { generateKeyPair, SignJWT } = require('jose');
const { installMicrosoftAuth, configuration, provider, hash } = require('../microsoft-auth');
const tenant = '11111111-1111-1111-1111-111111111111';
const client = '22222222-2222-2222-2222-222222222222';
const oid = '33333333-3333-3333-3333-333333333333';
const config = { tenant, client, secret: 'test-only', origin: 'http://localhost:3000',
  redirect: 'http://localhost:3000/api/auth/microsoft/callback', secure: false };

async function fixture(t, options = {}) {
  let clock = 1000, claims = options.claims || {}, calls = 0;
  const users = options.users || [{ id: 'expense-user', active: 1, microsoft_oid: oid, roles: ['employee'] }];
  const app = express();
  app.use(express.json());
  installMicrosoftAuth(app, {
    config: options.disabled ? null : config, now: () => clock,
    store: { getAll: () => users, get: (_, id) => users.find(u => u.id === id), put: (_, id, user) => users.push(user) },
    session: u => ({ token: 'expense-session', user: u }),
    identityProvider: {
      authorize: tx => `https://login.microsoftonline.com/test?state=${tx.state}`,
      redeem: async (_, tx) => { calls++; return { tid: tenant, oid, nonce: tx.nonce, ...claims }; },
    },
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api/auth/microsoft`;
  const get = (path, cookie) => fetch(base + path, { redirect: 'manual', headers: cookie ? { Cookie: cookie } : {} });
  const post = (path, data) => fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  async function start(mode = 'web') {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const response = await post('/start', { challenge: hash(verifier), mode });
    const { state, url } = await response.json();
    const auth = await get('/authorize?state=' + state);
    assert.equal(auth.status, 302);
    const cookie = auth.headers.get('set-cookie').split(';')[0];
    return { state, verifier, cookie, url };
  }
  const callback = tx => get(`/callback?state=${tx.state}&code=fake-code`, tx.cookie);
  return { get, post, start, callback, users, calls: () => calls, advance: ms => { clock += ms; } };
}

test('configuration is disabled until supplied, rejects incomplete settings and unsafe redirects', () => {
  assert.equal(configuration({}), null);
  assert.throws(() => configuration({ MICROSOFT_TENANT_ID: 'common' }));
  const env = { MICROSOFT_TENANT_ID: tenant, MICROSOFT_CLIENT_ID: client, MICROSOFT_CLIENT_SECRET: 'secret' };
  for (const uri of ['http://example.com/api/auth/microsoft/callback', 'https://example.com/other', 'https://example.com/api/auth/microsoft/callback?next=bad']) {
    assert.throws(() => configuration({ ...env, MICROSOFT_REDIRECT_URI: uri }));
  }
  assert.equal(configuration({ ...env, MICROSOFT_REDIRECT_URI: config.redirect }).tenant, tenant);
});

test('disabled sign-in has no available start route', async t => {
  const f = await fixture(t, { disabled: true });
  assert.deepEqual(await (await f.get('/config')).json(), { enabled: false });
  assert.equal((await f.post('/start', {})).status, 503);
});

test('browser sign-in requires proof, is one-use, and preserves expense roles', async t => {
  const f = await fixture(t), tx = await f.start();
  assert.equal((await f.post('/complete', tx)).status, 202);
  const callback = await f.callback(tx);
  assert.equal(callback.headers.get('location'), `${config.origin}/#microsoft=${tx.state}`);
  assert.equal(callback.headers.get('cache-control'), 'no-store');
  assert.equal((await f.post('/complete', { ...tx, verifier: 'x'.repeat(43) })).status, 400);
  const result = await f.post('/complete', tx);
  assert.equal(result.status, 200);
  assert.deepEqual((await result.json()).user.roles, ['employee']);
  assert.equal((await f.post('/complete', tx)).status, 400);
  assert.equal((await f.callback(tx)).status, 400);
  assert.equal(f.calls(), 1);
});

test('Android return page contains no token and still needs original proof', async t => {
  const f = await fixture(t), tx = await f.start('android');
  const response = await f.callback(tx), html = await response.text();
  assert.match(html, /uk\.co\.komfort\.expenses:\/\/microsoft-signin/);
  assert.ok(!html.includes('expense-session'));
  assert.ok(!html.includes(tx.verifier));
  assert.equal((await f.post('/complete', tx)).status, 200);
});

test('callback rejects missing cookie, unknown state, and callback replay', async t => {
  const f = await fixture(t), tx = await f.start();
  assert.equal((await f.get(`/callback?state=${tx.state}&code=fake`)).status, 400);
  assert.equal((await f.get('/callback?state=unknown&code=fake', tx.cookie)).status, 400);
  assert.equal(f.calls(), 0);
  await f.callback(tx);
  assert.equal((await f.callback(tx)).status, 400);
  assert.equal(f.calls(), 1);
});

test('cancelled and expired requests cannot produce a session', async t => {
  const f = await fixture(t), tx = await f.start();
  await f.get(`/callback?state=${tx.state}&error=access_denied`, tx.cookie);
  assert.equal((await f.post('/complete', tx)).status, 403);
  assert.equal(f.calls(), 0);
  const next = await f.start();
  f.advance(300001);
  assert.equal((await f.callback(next)).status, 400);
  assert.equal((await f.post('/complete', next)).status, 400);
});

for (const [name, options] of [
  ['wrong tenant', { claims: { tid: client } }],
  ['wrong nonce', { claims: { nonce: 'wrong' } }],
  ['missing object ID', { claims: { oid: undefined } }],
  ['unlinked email match', { users: [{ id: 'u', active: 1, email: 'person@example.com' }], claims: { email: 'person@example.com' } }],
  ['disabled user', { users: [{ id: 'u', active: 0, microsoft_oid: oid }] }],
  ['duplicate identity', { users: [{ id: 'a', active: 1, microsoft_oid: oid }, { id: 'b', active: 1, microsoft_oid: oid }] }],
]) {
  test(`rejects ${name}`, async t => {
    const f = await fixture(t, options), tx = await f.start();
    await f.callback(tx);
    assert.equal((await f.post('/complete', tx)).status, 403);
  });
}

test('user disabled after Microsoft callback is denied at completion', async t => {
  const f = await fixture(t), tx = await f.start();
  await f.callback(tx);
  f.users[0].active = 0;
  assert.equal((await f.post('/complete', tx)).status, 403);
});

test('actual JWT verification rejects wrong signature, audience, issuer, missing expiry and expired tokens', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const other = await generateKeyPair('RS256');
  const tx = { nonce: 'nonce', state: 'state', verifier: 'proof' };
  const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`;
  const claims = { tid: tenant, oid, nonce: tx.nonce, sub: 'subject', iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+60, iss: issuer, aud: client };
  let token;
  const idp = provider(config, { keys: publicKey, fetch: async (url, init) => {
    assert.equal(new URL(url).hostname, 'login.microsoftonline.com');
    assert.equal(init.body.get('code_verifier'), tx.verifier);
    return { ok: true, json: async () => ({ id_token: token }) };
  } });
  const sign = (payload, key = privateKey) => new SignJWT(payload).setProtectedHeader({ alg: 'RS256' }).sign(key);
  token = await sign(claims);
  assert.equal((await idp.redeem('code', tx)).oid, oid);
  for (const change of [{ aud: 'other-client' }, { iss: 'https://attacker.example' }, { exp: 1 }, { exp: undefined }]) {
    token = await sign({ ...claims, ...change });
    await assert.rejects(idp.redeem('code', tx));
  }
  token = await sign(claims, other.privateKey);
  await assert.rejects(idp.redeem('code', tx));
  const url = new URL(idp.authorize(tx));
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('nonce'), tx.nonce);
  assert.equal(url.searchParams.get('scope'), 'openid profile');
});

test('new Komfort Microsoft users get one account with no permissions', async t => {
  const f = await fixture(t, { users: [], claims: { preferred_username: 'New.User@KOMFORT.CO.UK', name: 'New User' } });
  for (let i = 0; i < 2; i++) {
    const tx = await f.start(); await f.callback(tx);
    const response = await f.post('/complete', tx);
    assert.equal(response.status, 200);
    const { user } = await response.json();
    assert.deepEqual(user.roles, []);
    assert.equal(user.email, 'new.user@komfort.co.uk');
    assert.equal(user.microsoft_oid, oid);
  }
  assert.equal(f.users.length, 1);
});
for (const claims of [
  { preferred_username: 'user@other.co.uk' },
  { preferred_username: 'user@komfort.co.uk.evil.example' },
  { preferred_username: 'user@sub.komfort.co.uk' },
  { preferred_username: 'user@komfort.co.uk', acct: 1 },
  { preferred_username: 'user@komfort.co.uk', tid: client },
  {},
]) test('does not provision disallowed identity ' + JSON.stringify(claims), async t => {
  const f = await fixture(t, { users: [], claims });
  const tx = await f.start(); await f.callback(tx);
  assert.equal((await f.post('/complete', tx)).status, 403);
  assert.equal(f.users.length, 0);
});
test('existing email cannot silently link a new Microsoft identity', async t => {
  const f = await fixture(t, { users: [{ id: 'existing', email: 'user@komfort.co.uk', active: 1, roles: ['finance'] }],
    claims: { preferred_username: 'user@komfort.co.uk' } });
  const tx = await f.start(); await f.callback(tx);
  assert.equal((await f.post('/complete', tx)).status, 403);
  assert.equal(f.users.length, 1);
  assert.equal(f.users[0].microsoft_oid, undefined);
});
test('disabled Komfort account is not recreated by provisioning', async t => {
  const f = await fixture(t, { users: [{ id: 'disabled', microsoft_oid: oid, active: 0 }],
    claims: { preferred_username: 'user@komfort.co.uk' } });
  const tx = await f.start(); await f.callback(tx);
  assert.equal((await f.post('/complete', tx)).status, 403);
  assert.equal(f.users.length, 1);
});
