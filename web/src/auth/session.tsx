import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, getDevIdentity, setDevIdentity } from '../api/client'
import { useAuthMode, useMe } from '../api/hooks'
import { SessionContext, type Session } from './useSession'

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [identity, setIdentity] = useState<string | null>(getDevIdentity())
  const mode = useAuthMode()
  const me = useMe(identity)
  const login = useCallback((name: string) => { setDevIdentity(name); setIdentity(name); qc.clear() }, [qc])
  const logout = useCallback(() => { setDevIdentity(null); setIdentity(null); qc.clear() }, [qc])
  const value = useMemo<Session>(() => {
    const unauth = me.error instanceof ApiError && me.error.status === 401
    let status: Session['status'] = 'ready'
    if (!identity || unauth) status = 'anonymous'
    else if (me.isPending || mode.isPending) status = 'loading'
    else if (me.isError) status = 'error'
    return {
      status, me: me.data ?? null, mode: mode.data ?? null, login, logout,
      can: (p) => !!me.data?.permissions.includes(p),
    }
  }, [identity, me.data, me.error, me.isPending, me.isError, mode.data, mode.isPending, login, logout])
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
