// Sets the password of the break-glass admin account (ADMIN_LOGIN_USERNAME, default "admin").
// Run on the server machine while the server is stopped:
//   npm run set-admin-password            -> generates a random password and prints it
//   npm run set-admin-password -- <pw>    -> uses the password you give (min 12 characters)
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const store = require('./database');

async function main() {
  const username = String(process.env.ADMIN_LOGIN_USERNAME || 'admin').toLowerCase();
  const given = process.argv[2];
  if (given !== undefined && given.length < 12) throw new Error('Use a password of at least 12 characters.');
  const password = given || crypto.randomBytes(15).toString('base64url');
  await store.initDb();
  const user = store.getAll('users').find(u => String(u.username).toLowerCase() === username);
  if (!user) throw new Error(`No user named "${username}". Set ADMIN_LOGIN_USERNAME to an existing finance username.`);
  if (!user.active) throw new Error(`User "${user.username}" is disabled.`);
  if (!Array.isArray(user.roles) || !user.roles.includes('finance'))
    console.warn(`Warning: "${user.username}" does not have the finance role, so it cannot manage users.`);
  user.password_hash = bcrypt.hashSync(password, 10);
  user.must_change_password = false;
  user.session_version = (user.session_version || 0) + 1; // sign out any existing sessions
  store.put('users', user.id, user);
  store.save();
  console.log(`Password set for "${user.username}".`);
  if (!given) console.log(`Password: ${password}`);
}
main().then(() => process.exit(0)).catch(error => { console.error(error.message); process.exit(1); });
