# Hosting Komfort Expenses on a Cloudflare Tunnel

This replaces the Render deployment. The app runs on a company Windows machine, listens only on
`127.0.0.1:3000`, and is published at your own domain through a Cloudflare Tunnel. No inbound
firewall ports are opened. Sign-in is Microsoft Entra only (see `MICROSOFT-SIGNIN.md`).

Below, `expenses.example.co.uk` stands for your real hostname.

> **Deploying to Render instead (or first)?** See [Running on Render](#running-on-render) at the end.

## 1. Prerequisites

- An always-on Windows machine with **Node.js 22.13 or newer** (`node --version`).
- The domain added to a Cloudflare account, with its nameservers pointed at Cloudflare.
- Entra admin rights (or someone who has them) for the app registration.

## 2. Microsoft Entra app registration

Entra admin centre → App registrations → New registration:

- Supported account types: **Single tenant**
- Redirect URI (platform **Web**): `https://expenses.example.co.uk/api/auth/microsoft/callback`

Then Certificates & secrets → New client secret, and note the **Directory (tenant) ID**,
**Application (client) ID** and the secret **Value**. No API permissions beyond the default
`openid profile` are needed. If you already registered an app for local testing, you can add
the HTTPS redirect URI to that same registration instead.

## 3. Install the app

```powershell
cd C:\KomfortExpenses\app          # wherever this repo is checked out
npm ci
npm test
copy .env.example .env
notepad .env                        # fill in JWT_SECRET, MICROSOFT_*, APP_URL, mail settings, DATA_DIR
```

Generate `JWT_SECRET` with
`node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`.

Copy the mail settings (`GRAPH_*` or `SMTP_*`) from the Render dashboard → Environment.

## 4. Move the data off Render

1. Sign in to the **current live site** (Render) as a finance user. The site has a finance-only
   `/api/backup` endpoint but no button for it, so open the browser console (F12 → Console) and run:

   ```js
   fetch('/api/backup', { headers: { Authorization: 'Bearer ' + localStorage.getItem('exp_token') } })
     .then(r => { if (!r.ok) throw new Error(r.status); return r.blob(); })
     .then(b => { const a = document.createElement('a'); a.href = URL.createObjectURL(b);
                  a.download = 'expenses-system.db'; a.click(); });
   ```
2. Move the downloaded `expenses-system.db` into the `DATA_DIR` folder from `.env`.
3. Do this as close to the cutover as possible; anything entered on Render afterwards will not
   come across. Consider telling staff to pause entries for the switchover window.

## 5. Admin set-up sign-in (break-glass)

With `ADMIN_LOGIN_ENABLED=true` in `.env`, open **http://localhost:3000/admin on the server machine**
and sign in with the `admin` account's password. The page only works on that machine: through the
tunnel it returns 404, and sessions from it stop working the moment the flag is turned off.
If you don't know the admin password (e.g. after moving the database), stop the server and run
`npm run set-admin-password`, which prints a new random one. Use the session to link Microsoft
accounts (below), then set `ADMIN_LOGIN_ENABLED=false` and restart.

## 6. Link existing users to Microsoft

Existing accounts have no Microsoft identity yet, and because their email already exists the
auto-creation for `@komfort.co.uk` will **not** take over their account. Link at least one finance
user before starting the server (server must be stopped):

```powershell
npm run link-user -- <existing-username> <Microsoft-user-Object-ID>
```

The Object ID is on the user's page in Entra → Users (not the app's Object ID). Once that finance
user can sign in, link everyone else from **Users → Edit → Microsoft user object ID**.
Brand-new staff with an `@komfort.co.uk` address get an account automatically with no roles,
and finance assigns roles under Users.

## 7. Run the app as a background task

From an **elevated** PowerShell in the repo folder:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\install-app-task.ps1
```

This registers a `KomfortExpenses` scheduled task that starts at boot as SYSTEM and restarts Node
if it exits. Logs go to `logs\server.log`. Check it with `curl http://127.0.0.1:3000/`.

## 8. Create the Cloudflare Tunnel

```powershell
winget install --id Cloudflare.cloudflared
cloudflared tunnel login                       # opens a browser; pick the domain
cloudflared tunnel create komfort-expenses     # prints the tunnel UUID and writes <UUID>.json
cloudflared tunnel route dns komfort-expenses expenses.example.co.uk
```

Copy `deploy\cloudflared-config.example.yml` to `%USERPROFILE%\.cloudflared\config.yml`, fill in the
UUID, credentials path and hostname, then test in the foreground:

```powershell
cloudflared tunnel run komfort-expenses
```

Open `https://expenses.example.co.uk` and sign in with Microsoft. When it works, stop it (Ctrl+C) and
install it as a Windows service (elevated):

```powershell
cloudflared service install
```

The service runs as SYSTEM and reads its config from
`C:\Windows\System32\config\systemprofile\.cloudflared\`; copy `config.yml` and the `<UUID>.json`
there and update `credentials-file` in the copy to point at that folder.

(Alternatively, create the tunnel in the Cloudflare Zero Trust dashboard → Networks → Tunnels,
add a public hostname `expenses.example.co.uk` → `http://127.0.0.1:3000`, and run the
`cloudflared service install <token>` command it gives you. That skips the config file entirely.)

## 9. Cutover checklist

- [ ] Final backup downloaded from Render and placed in `DATA_DIR`.
- [ ] Finance user linked; Microsoft sign-in works at the new domain.
- [ ] `ADMIN_LOGIN_ENABLED=false` in `.env` and the server restarted.
- [ ] A test email sends (Settings → test email) and its link points at the new domain.
- [ ] The **Android app**: release builds have the website URL built in. If the domain changes,
      rebuild the release app with the new URL (`-PkomfortUrl=https://expenses.example.co.uk/`)
      or point the old hostname at the tunnel.
- [ ] Suspend the Render service (and disconnect its GitHub auto-deploy) so nobody keeps using it.

## Notes

- **Backups**: the app keeps dated snapshots in `DATA_DIR\backups`. The machine is now the only copy,
  so make sure `DATA_DIR` is included in the company's regular backups.
- **Client IPs**: the server trusts `X-Forwarded-For` only from loopback (cloudflared), so rate limits
  apply per visitor. Override with `TRUST_PROXY` if your setup differs.
- **Optional extra gate**: Cloudflare Access can put an Entra-login wall in front of the whole hostname.
  It is not required (the app already requires Entra sign-in), and it complicates the Android app, so
  only add it if you want defence in depth for the website.

## Running on Render

The same code runs on the existing Render service (with its 1 GB persistent disk). The server
detects Render automatically: it listens on all interfaces and trusts Render's proxy for visitor IPs.

### Before deploying

1. **Back up the live database** (step 4 above: the console snippet as a finance user). This is your
   rollback point; the new version adds messages, audit entries and Microsoft links to the data.
2. **Entra:** in the app registration → Authentication → Web, add
   `https://<your-render-address>/api/auth/microsoft/callback` (your custom domain if Render serves one).
3. **Render → Environment**, add:

   | Key | Value |
   |---|---|
   | `NODE_VERSION` | `22` (the app needs Node 22.13+) |
   | `MICROSOFT_TENANT_ID` | Directory (tenant) ID |
   | `MICROSOFT_CLIENT_ID` | Application (client) ID |
   | `MICROSOFT_CLIENT_SECRET` | the secret **Value** |
   | `MICROSOFT_REDIRECT_URI` | `https://<your-render-address>/api/auth/microsoft/callback` |
   | `APP_URL` | `https://<your-render-address>` |
   | `ADMIN_LOGIN_ENABLED` | `true` (temporary) |
   | `ADMIN_SETUP_KEY` | a long random key (temporary), from `node -e "console.log(require('crypto').randomBytes(36).toString('base64url'))"` |

   Keep the existing `JWT_SECRET`, `DATA_DIR` and mail settings. `JWT_SECRET` must be at least 32
   characters (Render's generated value is). Keep the key in a password manager, not in email or chat.

### One-time linking

1. Deploy the branch. Everyone's existing password sessions end; only Microsoft sign-in is offered.
2. Open `https://<your-render-address>/admin`, enter the `admin` username, its password and the setup key.
   (If you don't know the live `admin` password, ask before deploying; it can't be reset from Render while
   the server runs.)
3. **Users → Edit → Microsoft user object ID**: add your own Object ID first, then everyone else's.
   Duplicate or malformed IDs are refused. New `@komfort.co.uk` staff who sign in unlinked get an account
   with no roles, which finance then assigns.
4. Sign out, sign in with Microsoft and confirm you land on your finance account.
5. **Delete `ADMIN_SETUP_KEY` and set `ADMIN_LOGIN_ENABLED=false`** in Render, then redeploy/restart.
   `/admin` becomes a 404 and any session opened with the key stops working immediately.
6. Optional: disable the `admin` user under Users once everyone is linked.

### Rolling back

Redeploy `main` in Render. If you need the data exactly as it was, restore the backup from step 1
onto the disk (Render Shell → replace `$DATA_DIR/expenses-system.db`, then restart). Note that
password sign-in will work again for everyone once `main` is running.
