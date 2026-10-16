import { Banner, PageHeader } from '../components/ui'
import { useSession } from '../auth/useSession'

export function Login() {
  const { mode, login, loginSso } = useSession()
  const failed = new URLSearchParams(window.location.search).get('error') === 'sso_failed'
  return (
    <main className="main" id="main">
      <PageHeader title="Sign in" lead="Agentic Infrastructure Security Warden: read-only assessment console" />
      {failed ? (
        <Banner tone="bad" role="alert" title="Single sign-on did not complete">
          The identity provider response could not be verified, or the sign-in took too long. Try again.
        </Banner>
      ) : null}
      {!mode ? (
        <p role="status" className="muted">Checking identity provider…</p>
      ) : (
        <>
          {mode.sso ? (
            <p>
              <button type="button" className="btn btn--primary" onClick={loginSso}>Sign in with single sign-on</button>
            </p>
          ) : null}
          {mode.mode === 'dev_stub' ? (
            <>
              <Banner tone="warn" title="Development identity stub">
                Seeded, clearly fake identities for local development and tests. This picker does not exist when the
                server runs in production mode, where single sign-on through the organisation's identity provider is used.
              </Banner>
              <ul className="list-plain" aria-label="Development identities">
                {mode.users.map((u) => (
                  <li key={u.name} className="row">
                    <button type="button" className="btn" onClick={() => login(u.name)} aria-label={`Sign in as ${u.name}`}>
                      {u.name}
                    </button>
                    <span className="muted">{u.tenant_id}: {u.roles.join(', ')}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : null}
          {mode.mode === 'none' ? (
            <Banner tone="bad" role="alert" title="No identity provider is configured">
              Sign-in is unavailable. An administrator must configure OIDC; nothing is accessible anonymously.
            </Banner>
          ) : null}
        </>
      )}
    </main>
  )
}
