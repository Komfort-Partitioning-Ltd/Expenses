const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { createRequire } = require('node:module');
const express = require('express');
const jwt = require('jsonwebtoken');
test('only finance can delete users, preserving self, expense history and approval routes', async t => {
  const app = express();
  const users = [
    { id: 'admin', roles: ['finance'], active: 1, microsoft_oid: 'linked-admin' },
    { id: 'employee', roles: ['employee'], active: 1, microsoft_oid: 'linked-employee' },
    { id: 'unused', roles: [], active: 1, microsoft_oid: 'linked-unused' },
    { id: 'owner', roles: ['employee'], active: 1, microsoft_oid: 'linked-owner' },
    { id: 'approver', roles: ['manager'], active: 1, microsoft_oid: 'linked-approver' },
  ];
  users[1].approver1_id = 'approver';
  const reports = [{ id: 'expense', user_id: 'owner' }];
  const store = {
    getAll: s => structuredClone(s === 'users' ? users : s === 'reports' ? reports : []),
    get: (s, id) => structuredClone((s === 'users' ? users : reports).find(u => u.id === id)),
    del: (s, id) => { assert.equal(s, 'users'); users.splice(users.findIndex(u => u.id === id), 1); },
    put: (s) => { assert.equal(s, 'audit_log'); },
    initDb: () => new Promise(() => {}),
  };
  const sourcePath = path.join(__dirname, '../server.js');
  const realRequire = createRequire(sourcePath);
  vm.runInNewContext(fs.readFileSync(sourcePath, 'utf8'), {
    require: name => name === 'express' ? Object.assign(() => app, express)
      : name === './database' ? store : name === './mailer' ? {} : realRequire(name),
    process: { env: { JWT_SECRET: 'deletion-test-secret-strong-synthetic-secret-2026' } }, __dirname: path.dirname(sourcePath), console,
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const token = id => jwt.sign({ id, auth_method: 'microsoft', session_fingerprint:require('../hardening').fingerprint(users.find(u=>u.id===id)) }, 'deletion-test-secret-strong-synthetic-secret-2026');
  const base = `http://127.0.0.1:${server.address().port}`;
  const remove = (who, target) => fetch(base + '/api/store/users/' + target,
    { method: 'DELETE', headers: { Authorization: 'Bearer ' + token(who) } });
  assert.equal((await remove('employee', 'unused')).status, 403);
  assert.equal((await remove('admin', 'admin')).status, 400);
  assert.equal((await remove('admin', 'owner')).status, 409);
  assert.equal((await remove('admin', 'approver')).status, 409);
  assert.equal((await remove('admin', 'missing')).status, 404);
  const deletedToken = token('unused');
  assert.equal((await remove('admin', 'unused')).status, 200);
  assert.ok(!users.some(u => u.id === 'unused'));
  assert.equal((await fetch(base + '/api/me', { headers: { Authorization: 'Bearer ' + deletedToken } })).status, 401);
  assert.equal(reports.length, 1);
  // Reassigning approval routes allows an otherwise unused approver to be removed.
  users[1].approver1_id = 'admin';
  assert.equal((await remove('admin', 'approver')).status, 200);
});
