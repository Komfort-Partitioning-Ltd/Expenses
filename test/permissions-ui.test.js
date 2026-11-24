const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
test('pending users see the permissions screen without fetching expense data', async () => {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { style: {}, classList: { add() {}, remove() {} } });
    return elements.get(id);
  };
  let ready = false;
  const context = {
    state: { user: { roles: [] } },
    document: { getElementById: element },
    refreshCaches() { throw new Error('Pending user must not fetch data'); },
    window: { KomfortAndroid: { postMessage() { ready = true; } } },
  };
  vm.createContext(context);
  vm.runInContext(html.slice(html.indexOf('function hasPermissions(){'), html.indexOf('async function refreshCaches(){')), context);
  await context.enterApp();
  assert.equal(element('permissions-pending').style.display, 'flex');
  assert.equal(element('login-view').style.display, 'none');
  assert.equal(ready, true);
  assert.match(html, /Ask an admin to assign you permissions/);
});
test('all inline website scripts parse', () => {
  for (const match of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)) new vm.Script(match[1]);
});
