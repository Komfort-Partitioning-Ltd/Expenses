# Hosting Komfort Expenses on a Cloudflare Tunnel

This replaces the Render deployment. The app runs on a company Windows machine, listens only on
`127.0.0.1:3000`, and is published at your own domain through a Cloudflare Tunnel. No inbound
firewall ports are opened. Sign-in is Microsoft Entra only (see `MICROSOFT-SIGNIN.md`).

Below, `expenses.example.co.uk` stands for your real hostname.

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
