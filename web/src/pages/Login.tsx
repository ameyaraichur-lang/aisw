import { Banner, PageHeader } from '../components/ui'
import { useSession } from '../auth/useSession'

export function Login() {
  const { mode, login } = useSession()
  return (
    <main className="main" id="main">
      <PageHeader title="Sign in" lead="Agentic Infrastructure Security Warden: read-only assessment console" />
      {!mode ? (
        <p role="status" className="muted">Checking identity provider…</p>
      ) : mode.mode === 'dev_stub' ? (
        <>
          <Banner tone="warn" title="Development identity stub">
            Seeded, clearly fake identities for local development and tests. This picker does not exist when the
            server runs in production mode (OIDC through Keycloak is used instead).
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
      ) : (
        <Banner tone="bad" role="alert" title="No identity provider is configured">
          Sign-in is unavailable. An administrator must configure OIDC; nothing is accessible anonymously.
        </Banner>
      )}
    </main>
  )
}
