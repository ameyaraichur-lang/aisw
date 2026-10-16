import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api, ApiError, csrfToken, getDevIdentity, setDevIdentity, ssoLoginUrl } from '../api/client'
import { useAuthMode, useMe } from '../api/hooks'
import { SessionContext, type Session } from './useSession'

const SSO = 'sso'

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [identity, setIdentity] = useState<string | null>(getDevIdentity() ?? (csrfToken() ? SSO : null))
  const mode = useAuthMode()
  const me = useMe(identity)
  const login = useCallback((name: string) => { setDevIdentity(name); setIdentity(name); qc.clear() }, [qc])
  const loginSso = useCallback(() => {
    const here = window.location.pathname === '/login' ? '/' : window.location.pathname + window.location.search
    window.location.assign(ssoLoginUrl(here))
  }, [])
  const logout = useCallback(() => {
    if (identity !== SSO) { setDevIdentity(null); setIdentity(null); qc.clear(); return }
    void api<{ end_session_url: string | null }>('/auth/logout', { method: 'POST' })
      .then((r) => { if (r.end_session_url) window.location.assign(r.end_session_url) })
      .catch(() => undefined)
      .finally(() => { setIdentity(null); qc.clear() })
  }, [identity, qc])
  const value = useMemo<Session>(() => {
    const unauth = me.error instanceof ApiError && me.error.status === 401
    let status: Session['status'] = 'ready'
    if (!identity || unauth) status = 'anonymous'
    else if (me.isPending || mode.isPending) status = 'loading'
    else if (me.isError) status = 'error'
    return {
      status, me: me.data ?? null, mode: mode.data ?? null, login, loginSso, logout,
      can: (p) => !!me.data?.permissions.includes(p),
    }
  }, [identity, me.data, me.error, me.isPending, me.isError, mode.data, mode.isPending, login, loginSso, logout])
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
