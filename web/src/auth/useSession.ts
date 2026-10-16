import { createContext, useContext } from 'react'
import type { AuthMode, Me } from '../api/types'

export interface Session {
  status: 'loading' | 'anonymous' | 'ready' | 'error'
  me: Me | null
  mode: AuthMode | null
  login: (name: string) => void
  logout: () => void
  /** UI convenience only: the server re-authorises every request. */
  can: (permission: string) => boolean
}
export const SessionContext = createContext<Session | null>(null)

export function useSession(): Session {
  const v = useContext(SessionContext)
  if (!v) throw new Error('SessionProvider missing')
  return v
}
