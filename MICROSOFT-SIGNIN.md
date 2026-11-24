# Microsoft-only sign-in (local version)

The website and Android app require **Sign in with Microsoft**. Local password login,
password reset and password change are disabled, including direct API calls. Existing
password sessions are rejected. Users keep their existing expense accounts and roles.
An unconfigured Microsoft provider leaves login unavailable; there is no password fallback.

## Local setup

Register a single-tenant Microsoft Entra application with a Web redirect URI:
`http://localhost:3000/api/auth/microsoft/callback`.
The backend uses authorization code flow, PKCE, and `openid profile` scopes.
Set the following environment variables in the backend terminal before `npm start`
(the server does not load .env files automatically):

```powershell
$env:MICROSOFT_TENANT_ID = 'your-directory-uuid'
$env:MICROSOFT_CLIENT_ID = 'your-app-registration-uuid'
$env:MICROSOFT_CLIENT_SECRET = 'your-secret-value'
$env:MICROSOFT_REDIRECT_URI = 'http://localhost:3000/api/auth/microsoft/callback'
$env:JWT_SECRET = 'your-long-random-secret'
npm ci
```

Before starting the server, link your existing finance account to your Microsoft user
Object ID. Stop the server before running this local maintenance command:

```powershell
node link-microsoft-user.js admin YOUR-MICROSOFT-USER-OBJECT-ID
npm start
```

Replace `admin` with your existing finance username. On a fresh database the bootstrap
creates `admin`; its generated password cannot be used to sign in. The linking command
preserves user roles and rejects duplicate identities. Use the user Object ID from
Entra Users, not an application Object ID or email address. After signing in, finance
can link other existing users through Users > Edit > Microsoft user object ID.
The script uses DATA_DIR if configured, just like the server.

## Local Android

```powershell
adb reverse tcp:3000 tcp:3000
# From ExpensesApplication:
.\gradlew.bat installDebug
```

Debug builds default to `http://localhost:3000/`. The optional `-PkomfortUrl=...`
overrides it. The app and system browser must reach the same backend. Microsoft opens
in the system browser; return to the app to finish. Release builds retain their existing
website URL. These local changes do not change the hosted website.

## Verification

Run `npm test`. Coverage includes blocked password endpoints and password/legacy
sessions, account linking permissions, identity validation and browser/Android handoff.
A configured tenant and a device are still needed to check a real Microsoft login.
Microsoft applies the organization's sign-in policies. Signing out clears the Expenses
session, not the global Microsoft session. Disabled or unlinked users cannot use the API.

Pending sign-ins expire after five minutes and are kept in server memory. Restarting the
server cancels them. Multiple server processes require a shared transaction store.

## Automatic Komfort account creation

After Microsoft identity and tenant validation, a new user with an exact
`@komfort.co.uk` sign-in address receives an active account with an empty role list.
Existing links retain their permissions; disabled identities are never recreated.
Other domains, guest identities marked by Microsoft, and address collisions require
an administrator to resolve the account. Matching email addresses never grant access
to an existing account automatically.

Users without roles see “Ask an admin to assign you permissions”, with Check permissions
and Sign out buttons. They cannot read or write expense data through the API. Finance
administrators can assign roles through Users; the user can then select Check permissions.
