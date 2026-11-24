// Server-side Microsoft work-account sign-in. No Microsoft tokens reach the client.
const crypto = require('crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PROOF = /^[A-Za-z0-9_-]{43}$/;
const random = () => crypto.randomBytes(32).toString('base64url');
const hash = value => crypto.createHash('sha256').update(value).digest('base64url');
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' &&
  a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

function configuration(env = process.env) {
  const tenant = (env.MICROSOFT_TENANT_ID || '').toLowerCase();
  const client = env.MICROSOFT_CLIENT_ID || '';
  const secret = env.MICROSOFT_CLIENT_SECRET || '';
  const redirect = env.MICROSOFT_REDIRECT_URI || '';
  if (![tenant, client, secret, redirect].some(Boolean)) return null;
  if (!UUID.test(tenant) || !UUID.test(client) || !secret) throw new Error('Microsoft sign-in needs a tenant UUID, client UUID and client secret.');
  const uri = new URL(redirect);
  if ((uri.protocol !== 'https:' && !(uri.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(uri.hostname))) ||
      uri.pathname !== '/api/auth/microsoft/callback' || uri.search || uri.hash || uri.username || uri.password) {
    throw new Error('MICROSOFT_REDIRECT_URI must be HTTPS (or HTTP localhost), ending in /api/auth/microsoft/callback.');
  }
  return { tenant, client, secret, redirect, origin: uri.origin, secure: uri.protocol === 'https:' };
}

function provider(config, dependencies = {}) {
  const authority = `https://login.microsoftonline.com/${config.tenant}`;
  const keys = dependencies.keys || createRemoteJWKSet(new URL(`${authority}/discovery/v2.0/keys`));
  const request = dependencies.fetch || fetch;
  return {
    authorize(tx) {
      const query = new URLSearchParams({ client_id: config.client, response_type: 'code',
        redirect_uri: config.redirect, response_mode: 'query', scope: 'openid profile',
        state: tx.state, nonce: tx.nonce, code_challenge: hash(tx.verifier),
        code_challenge_method: 'S256', prompt: 'select_account' });
      return `${authority}/oauth2/v2.0/authorize?${query}`;
    },
    async redeem(code, tx) {
      const response = await request(`${authority}/oauth2/v2.0/token`, {
        method: 'POST', signal: AbortSignal.timeout(15000),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: config.client, client_secret: config.secret,
          grant_type: 'authorization_code', code, redirect_uri: config.redirect,
          code_verifier: tx.verifier, scope: 'openid profile' }),
      });
      if (!response.ok) throw new Error('Microsoft token exchange failed');
      const tokens = await response.json();
      const { payload } = await jwtVerify(tokens.id_token, keys, {
        issuer: `${authority}/v2.0`, audience: config.client, algorithms: ['RS256'],
        requiredClaims: ['exp', 'iat', 'sub', 'nonce', 'tid', 'oid'],
      });
      return payload;
    },
  };
}

function validateIdentity(claims, tx, config) {
  if (!equal(claims.nonce, tx.nonce) || claims.tid !== config.tenant || !UUID.test(claims.oid || '')) {
    throw new Error('Invalid Microsoft identity');
  }
  return claims.oid.toLowerCase();
}

function installMicrosoftAuth(app, { store, session, config = configuration(), identityProvider, now = Date.now }) {
  const pending = new Map();
  const ttl = 5 * 60 * 1000;
  const idp = config && (identityProvider || provider(config));
  const prefix = '/api/auth/microsoft';
  const clean = () => { for (const [key, tx] of pending) if (tx.expires <= now()) pending.delete(key); };
  app.use(prefix, (req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
    clean();
    next();
  });
  app.get(`${prefix}/config`, (req, res) => res.json({ enabled: !!config }));
  app.post(`${prefix}/start`, (req, res) => {
    if (!config) return res.status(503).json({ error: 'Microsoft sign-in is not configured yet.' });
    if (!PROOF.test(req.body?.challenge || '') || !['web', 'android'].includes(req.body?.mode)) {
      return res.status(400).json({ error: 'Invalid sign-in request.' });
    }
    if (pending.size >= 1000) return res.status(429).json({ error: 'Please try signing in again shortly.' });
    const state = random();
    pending.set(state, { state, challenge: req.body.challenge, mode: req.body.mode,
      nonce: random(), verifier: random(), expires: now() + ttl, status: 'pending' });
    res.json({ state, url: `${config.origin}${prefix}/authorize?state=${state}` });
  });
  app.get(`${prefix}/authorize`, (req, res) => {
    const tx = pending.get(req.query.state);
    if (!config || !tx || tx.begun) return res.status(400).send('This sign-in request has expired. Please start again.');
    tx.begun = true;
    tx.cookie = random();
    res.cookie('komfort_ms_state', tx.cookie, { httpOnly: true, secure: config.secure,
      sameSite: 'lax', path: `${prefix}/callback`, maxAge: ttl });
    res.redirect(idp.authorize(tx));
  });
  app.get(`${prefix}/callback`, async (req, res) => {
    const tx = pending.get(req.query.state);
    const cookie = (req.headers.cookie || '').split(';').map(v => v.trim())
      .find(v => v.startsWith('komfort_ms_state='))?.slice('komfort_ms_state='.length);
    if (!config || !tx || !tx.begun || tx.used || !equal(cookie, tx.cookie)) {
      return res.status(400).send('This sign-in request is invalid or expired. Return to Expenses and try again.');
    }
    tx.used = true; // consume before the network request, including on failure
    res.clearCookie('komfort_ms_state', { httpOnly: true, secure: config.secure, sameSite: 'lax', path: `${prefix}/callback` });
    try {
      if (req.query.error || typeof req.query.code !== 'string' || !req.query.code) throw new Error('Sign-in cancelled');
      const claims = await idp.redeem(req.query.code, tx);
      const oid = validateIdentity(claims, tx, config);
      const allUsers = store.getAll('users');
      let users = allUsers.filter(u => u.microsoft_oid?.toLowerCase() === oid);
      if (users.length === 0) {
        // The signed token has already passed issuer, tenant and nonce validation.
        // The address gates provisioning only; the immutable oid binds the account.
        const address = String(claims.preferred_username || claims.email || '').trim().toLowerCase();
        const allowed = /^[^@\s]+@komfort\.co\.uk$/.test(address) && claims.acct !== 1;
        const collision = allUsers.some(u => [u.username, u.email].some(value =>
          String(value || '').toLowerCase() === address));
        if (allowed && !collision) {
          const user = { id: crypto.randomUUID(), username: address, email: address,
            full_name: String(claims.name || address), microsoft_oid: oid,
            roles: [], active: 1, must_change_password: false,
            department_id: null, location_id: null, approver1_id: null, approver2_id: null,
            created_at: new Date(now()).toISOString() };
          store.put('users', user.id, user);
          users = [user];
        }
      }
      users = users.filter(u => u.active);
      if (users.length !== 1) {
        tx.error = 'Your Microsoft account is not linked to an active Expenses user. Please contact your finance administrator.';
      } else {
        tx.userId = users[0].id;
        tx.oid = oid;
        tx.status = 'ready';
      }
    } catch (_) {
      tx.error = 'Microsoft sign-in was cancelled or could not be verified. Please try again.';
    }
    if (tx.error) tx.status = 'error';
    if (tx.mode === 'web') return res.redirect(`${config.origin}/#microsoft=${tx.state}`);
    res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");
    res.type('html').send('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Komfort Expenses</title><body style="font-family:Arial,sans-serif;padding:32px;line-height:1.6"><h1>Return to Expenses</h1><p>Continue in the app to finish signing in.</p><a href="uk.co.komfort.expenses://microsoft-signin">Open Komfort Expenses</a><p>If the app does not open, switch back to it manually.</p></body></html>');
  });
  app.post(`${prefix}/complete`, (req, res) => {
    const { state, verifier } = req.body || {};
    const tx = pending.get(state);
    if (!tx || !PROOF.test(verifier || '') || !equal(hash(verifier), tx.challenge)) {
      return res.status(400).json({ error: 'This sign-in request has expired. Please try again.' });
    }
    if (tx.status === 'pending') return res.status(202).json({ pending: true });
    pending.delete(state); // one-time handoff, bound to the originating app/browser
    if (tx.error) return res.status(403).json({ error: tx.error });
    const user = store.get('users', tx.userId);
    if (!user?.active || user.microsoft_oid?.toLowerCase() !== tx.oid) {
      return res.status(403).json({ error: 'Your account is no longer available for Microsoft sign-in.' });
    }
    res.json(session(user));
  });
}

module.exports = { installMicrosoftAuth, configuration, validateIdentity, provider, UUID, hash };
