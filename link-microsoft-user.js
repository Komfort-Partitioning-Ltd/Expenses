// Run locally while the server is stopped; never guesses or auto-links an identity.
const store = require('./database');
const { UUID } = require('./microsoft-auth');
async function main() {
  const [username, value] = process.argv.slice(2);
  const oid = String(value || '').trim().toLowerCase();
  if (!username || !UUID.test(oid)) throw new Error('Usage: node link-microsoft-user.js <username> <Microsoft-user-object-ID>');
  await store.initDb();
  const users = store.getAll('users');
  const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user?.active) throw new Error('No active Expenses user with that username.');
  if (users.some(u => u.id !== user.id && u.microsoft_oid?.toLowerCase() === oid))
    throw new Error('That Microsoft identity is already linked to another user.');
  user.microsoft_oid = oid;
  store.put('users', user.id, user);
  store.save();
  console.log('Linked Microsoft identity for ' + user.username);
}
main().then(() => process.exit(0)).catch(error => { console.error(error.message); process.exit(1); });
