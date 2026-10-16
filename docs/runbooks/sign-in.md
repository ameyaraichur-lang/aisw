# Sign-in (OIDC through the BFF)

ADR-026. Any standards-compliant OIDC provider works; nothing is IdP-specific.

## Register the client at the IdP
- Client type: confidential, authorization code flow, PKCE S256 required, client authentication `client_secret_basic`.
- Redirect URI: `https://<console-host>/api/v1/auth/callback` (exactly; the app refuses any other path).
- Scopes: `openid profile email` (override with `AISW_OIDC_SCOPES`).
- Claims in the ID token (and in access tokens for API clients):
  - `sub`: the actor id shown in audit events.
  - `tenant`: the AISW tenant id. A different claim name can be set with `AISW_OIDC_TENANT_CLAIM`.
  - `roles`: AISW role names or IdP group values; a list or a space-separated string. A different claim name can be set with `AISW_OIDC_ROLES_CLAIM`.
- Post-logout redirect: the console URL, if the IdP requires one.

## Configure AISW
Put the secrets in the secret provider, never in the repo:
```
AISW_OIDC_ISSUER=https://idp.example.com/realms/security
AISW_OIDC_CLIENT_ID=aisw-console
AISW_OIDC_CLIENT_SECRET=<from the secret provider>
AISW_OIDC_REDIRECT_URI=https://console.example.com/api/v1/auth/callback
AISW_SESSION_SECRET=<at least 32 random characters, from the secret provider>
AISW_OIDC_ROLE_MAP={"sec-admins":"project_admin","sec-operators":"assessment_operator","sec-approvers":"approver","sec-readers":"report_reader","sec-audit":"auditor"}
AISW_OIDC_SESSION_MINUTES=480
```
Startup fails closed in these cases:
- a non-https issuer or callback outside dev/test;
- a missing client id or session secret;
- a role map that names an unknown AISW role.

`GET /api/v1/auth/mode` returns `{"mode": "oidc", "sso": true}` when SSO is configured.

## Verify
1. Open the console and choose **Sign in with single sign-on**. After you sign in at the IdP you should be back on the page you started from.
2. `GET /api/v1/me` should show the expected tenant, actor and roles. Audit should contain an `auth.login` event.
3. Choose **Sign out**. Audit should contain `auth.logout`. Replaying the old cookie should get 401.

## Rotate or revoke
- **IdP signing keys.** Picked up automatically. An unknown `kid` causes one key-set refetch, at most once every 30 s.
- **`AISW_SESSION_SECRET`.** Rotating it signs everyone out, because every session cookie stops verifying. Use it as an emergency sign-out for all users.
- **Client secret.** Rotate at the IdP, update the secret provider, then restart the API.
- **A user's session.** It ends when they sign out, when it expires, or when the session secret is rotated. Session roles are a snapshot taken at sign-in, so removing a role at the IdP takes effect at the next sign-in.

## Troubleshooting
- If you land on `/login?error=sso_failed`, the API log line `sso callback rejected: <reason>` names the cause: state mismatch, an expired login cookie (the user took more than 10 minutes), a nonce mismatch, or a token rejection.
- `503 sso_unavailable` on `/auth/login` means discovery failed. Check that the IdP is reachable from the API host and that the issuer in discovery matches `AISW_OIDC_ISSUER` exactly. Proxy environment variables are ignored.
- If you are signed in but get `403`, either the CSRF header is missing (only browsers using the cookie need it) or the role map does not grant the permission.

## Local and e2e
`backend/tests/oidc_idp.py` is a loopback mock IdP. It is test-only; never point a real deployment at it. The Playwright server (`backend/e2e/server.py`) starts one, so the login page offers both the dev picker and SSO.
