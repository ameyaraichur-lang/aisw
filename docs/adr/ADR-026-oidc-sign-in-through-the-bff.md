# ADR-026: Generic OIDC sign-in through the BFF

**Status:** Accepted (implemented and tested against a loopback mock IdP; no real tenant connected yet). Amends ADR-006.

## Context
ADR-006 named Keycloak for deployments, but only the dev identity stub existed, and the app refuses the stub outside dev/test. So the console could not be deployed (pending-plan P0-1). The product owner chose: generic OIDC only, nothing IdP-specific, tested against a local mock IdP until a real tenant is available.

## Decision
- **Any standards-compliant OIDC provider** (Keycloak, Entra ID, Okta and others) is configured with `AISW_OIDC_ISSUER`, `AISW_OIDC_CLIENT_ID`, `AISW_OIDC_CLIENT_SECRET` and `AISW_OIDC_REDIRECT_URI`. Endpoints come from discovery, and the issuer that discovery reports must equal the configured one. Discovery, key and token calls ignore proxy environment variables, refuse redirects and cap responses at 512 KiB. The issuer, the callback and every discovered endpoint must use https; plain http is accepted only on loopback outside prod.
- **Backend-for-frontend (BFF).** The console uses the authorization-code flow with PKCE S256, `state` and `nonce`. A confidential client authenticates at the token endpoint with `client_secret_basic`. The browser never receives an IdP token: the callback verifies the ID token server-side and issues signed cookies.
  - `aisw_session` is HttpOnly, SameSite=Lax, Secure (whenever the callback is https) and scoped to `/api`. It is HMAC-signed with `AISW_SESSION_SECRET` (at least 32 characters), carries its own expiry (`AISW_OIDC_SESSION_MINUTES`, default 480), and holds the session id, tenant, subject, roles and a CSRF token.
  - `aisw_csrf` is readable by the page. Every unsafe request authenticated by the session cookie must echo it in `X-AISW-CSRF`, otherwise the answer is 403.
  - `aisw_login` is a 10-minute cookie scoped to `/api/v1/auth`. It holds `state`, `nonce`, the PKCE verifier and the return path.
  - The HMAC key is derived per purpose, so a login cookie cannot be replayed as a session cookie.
- **Token verification.** Only asymmetric algorithms are accepted (RS256, PS256, ES256, EdDSA), never `none` or HMAC, and a `kid` is required. Validation requires an exact issuer and audience, plus `exp`, `iat` and `sub`, with 60 s leeway. When a token carries several audiences, `azp` must name this client. An unknown `kid` triggers at most one key-set refetch, and refetches are throttled to one every 30 s, so forged `kid`s cannot drive traffic to the IdP.
- **Identity.**
  - The actor is the verified `sub`, not `preferred_username`, which is neither unique nor stable.
  - The tenant comes from `AISW_OIDC_TENANT_CLAIM` (default `tenant`) and must look like a tenant id.
  - Roles come from `AISW_OIDC_ROLES_CLAIM` (default `roles`; a list or a space-separated string). They pass through `AISW_OIDC_ROLE_MAP`, a JSON object of IdP value to AISW role. Values that are not mapped are dropped.
  - Nothing in a request body or an unverified header can choose a tenant or a role.
- **API bearer tokens.** Machine clients may send an IdP-issued JWT as `Authorization: Bearer`, checked for audience `AISW_OIDC_AUDIENCE` (default: the client id). A bearer header takes precedence over the cookie. CSRF does not apply to bearer callers, because browsers do not attach them automatically.
- **Logout.** Logout is a POST that requires CSRF. It records the session id in `auth_session_revocations` (migration 0011, tenant RLS forced, insert and select only), writes an `auth.logout` audit event and clears the cookies. Its response includes the IdP's `end_session_endpoint` so the console can end the IdP session too. Sign-in writes `auth.login`. A revoked or expired session cookie gets 401.
- **Open redirects.** The return path accepts only same-origin absolute paths. `//host`, `/\host`, schemes, control characters and anything longer than 512 characters become `/`.
- **Failures.** A callback failure redirects to `/login?error=sso_failed`; the reason is logged, never shown. An unreachable IdP returns 503 on `/auth/login` and 401 on bearer calls.
- The dev stub is unchanged and still refused outside dev/test. In dev/test both can be enabled together: `/auth/mode` reports `sso: true` beside the picker.

## Consequences
- The app is deployable behind an IdP once a client is registered. Session roles are a snapshot taken at sign-in, so a role removed at the IdP takes effect at the next sign-in or when the session expires. Keep `AISW_OIDC_SESSION_MINUTES` short where that matters, or revoke sessions.
- Not yet proven against a real tenant: the specific claim names, group-to-role mapping and logout behaviour of the customer's IdP. Recorded as pending in P0-1.
- `PyJWT` is a new runtime dependency (MIT, already pulled in with `cryptography`); the SBOM is regenerated.

## Tests
- `tests/unit/test_oidc.py`:
  - the token rejection matrix: expired, wrong aud, wrong iss, `none`, HS256 confusion, unknown kid, missing claims, tampered body;
  - nonce and `azp`;
  - key rotation with a throttled refetch;
  - claim mapping;
  - a lying discovery document and unsafe endpoints;
  - settings refusals;
  - the cookie codec: tamper, purpose and expiry;
  - the return-path filter.
- `tests/integration/test_oidc_flow.py`:
  - the full flow against `tests/oidc_idp.py`, which checks PKCE and client authentication and makes codes single use;
  - cookie flags, CSRF, logout revocation with a stolen-cookie replay, forged and expired cookies;
  - bad state, replayed code and wrong nonce;
  - open redirects;
  - RBAC and cross-tenant denial with real tokens;
  - stub and SSO coexisting;
  - an unreachable IdP.
- `web/e2e/sso.spec.ts`: a real browser signs in through the mock IdP, the session cookie is HttpOnly, CSRF is enforced, and after sign-out a replayed cookie gets 401.

## Alternatives considered
- Keycloak-specific integration (ADR-006): rejected in favour of plain OIDC so any IdP works.
- Tokens in browser storage (SPA public client): rejected, because XSS could then steal long-lived credentials.
- Server-side session table: rejected for now, since a signed cookie plus a revocation list needs no session lookup beyond the revocation check.
