const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { createRequire } = require('node:module');

test('server permits finance linking, protects links from employees, and enforces Microsoft-only sessions', async t => {
  const app = express(), secret = 'test-session-secret-strong-synthetic-secret-2026';
  const oid = '33333333-3333-3333-3333-333333333333';
  const users = [
    { id: 'employee', username: 'employee', roles: ['employee'], active: 1, microsoft_oid: '44444444-4444-4444-4444-444444444444', must_change_password: true, password_hash: bcrypt.hashSync('test-password', 4) },
    { id: 'finance', username: 'finance', roles: ['finance'], microsoft_oid: '55555555-5555-5555-5555-555555555555', active: 1 },
  ];
  const sourcePath = path.join(__dirname, '..', 'server.js');
  const realRequire = createRequire(sourcePath);
  const store = {
    getAll: s => s === 'users' ? structuredClone(users) : [],
    get: (_, id) => structuredClone(users.find(u => u.id === id)),
    put: (s, id, u) => { if (s === 'users') users[users.findIndex(x => x.id === id)] = structuredClone(u); },
    // Do not open a database or listening socket during module initialization.
    initDb: () => new Promise(() => {}),
  };
  vm.runInNewContext(fs.readFileSync(sourcePath, 'utf8'), {
    require: name => name === 'express' ? Object.assign(() => app, express)
      : name === './database' ? store : name === './mailer' ? {} : realRequire(name),
    process: { env: { JWT_SECRET: secret } }, __dirname: path.dirname(sourcePath), console,
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  async function request(method, url, who, body, authMethod = 'microsoft') {
    const user = users.find(u => u.id === who);
    const headers = { 'Content-Type': 'application/json' };
    if (user) headers.Authorization = 'Bearer ' + jwt.sign({ id: user.id, roles: user.roles, auth_method: authMethod, session_fingerprint:require('../hardening').fingerprint(user) }, secret);
    return fetch(base + url, { method, headers, body: body && JSON.stringify(body) });
  }
  assert.equal((await request('PUT', '/api/store/users', 'employee', { ...users[0], microsoft_oid: oid })).status, 403);
  assert.equal((await request('PUT', '/api/store/users', 'finance', { ...users[0], microsoft_oid: 'not-an-id' })).status, 400);
  assert.equal((await request('PUT', '/api/store/users', 'finance', { ...users[0], microsoft_oid: oid })).status, 200);
  assert.equal((await request('PUT', '/api/store/users', 'finance', { ...users[1], microsoft_oid: oid })).status, 400);
  assert.equal((await request('PUT', '/api/store/users', 'employee', { ...users[0], microsoft_oid: '66666666-6666-6666-6666-666666666666' })).status, 403);
  assert.equal((await request('DELETE', '/api/store/users/finance', 'employee')).status, 403);
  // An old client omitting the new field must not silently unlink an account.
  const edited = { ...users[0], full_name: 'Updated Name' }; delete edited.microsoft_oid;
  assert.equal((await request('PUT', '/api/store/users', 'employee', edited)).status, 200);
  assert.equal(users[0].microsoft_oid, oid);
  const passwordLogin = await request('POST', '/api/login', null, { username: 'employee', password: 'test-password' });
  assert.equal(passwordLogin.status, 403);
  for (const route of ['/api/forgot-password', '/api/reset-password', '/api/change-password']) {
    assert.equal((await request('POST', route, 'employee', {})).status, 403);
  }
  for (const method of ['password', undefined]) {
    const token = jwt.sign({ id: 'employee', roles: ['employee'], auth_method: method }, secret);
    const response = await fetch(base + '/api/me', { headers: { Authorization: 'Bearer ' + token } });
    assert.equal(response.status, 401);
  }
  users[0].roles = [];
  assert.equal((await request('GET', '/api/me', 'employee')).status, 200);
  for (const [method, route, body] of [
    ['GET', '/api/store/users'], ['GET', '/api/store/reports'],
    ['PUT', '/api/store/users', { ...users[0], roles: ['finance'] }],
    ['POST', '/api/backup/run', {}],
  ]) assert.equal((await request(method, route, 'employee', body)).status, 403);
  users[0].roles = ['employee'];
  assert.equal((await request('GET', '/api/store/users', 'employee')).status, 200);
  const microsoftMe = await (await request('GET', '/api/me', 'employee', null, 'microsoft')).json();
  assert.equal(microsoftMe.must_change_password, false);
  assert.equal(users[0].must_change_password, true);
  assert.equal(microsoftMe.password_hash, undefined);
});
