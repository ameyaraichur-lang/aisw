import { createContext, useContext } from 'react'
import type { AuthMode, Me } from '../api/types'

export interface Session {
  status: 'loading' | 'anonymous' | 'ready' | 'error'
  me: Me | null
  mode: AuthMode | null
  login: (name: string) => void
  /** Leaves the page for the IdP; the BFF brings the browser back to the current path. */
  loginSso: () => void
  logout: () => void
  /** UI convenience only: the server re-authorises every request. With a project id: tenant-wide or
   *  on that project; without: tenant-wide or on any project (for navigation). */
  can: (permission: string, projectId?: string) => boolean
}
export const SessionContext = createContext<Session | null>(null)

export function useSession(): Session {
  const v = useContext(SessionContext)
  if (!v) throw new Error('SessionProvider missing')
  return v
}
