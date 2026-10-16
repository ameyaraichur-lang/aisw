import type { ReactNode } from 'react'
import { useSession } from '../auth/useSession'
import { Banner, PageHeader } from './ui'

/** UI courtesy only: shows an explicit denied state. The API enforces every permission regardless. */
export function RequirePermission({ need, title, children }: { need: string[]; title: string; children: ReactNode }) {
  const { can } = useSession()
  if (need.some((p) => can(p))) return <>{children}</>
  return (
    <>
      <PageHeader title={title} />
      <Banner tone="warn" role="alert" title="Access denied">
        Your role does not include {need.join(' or ')}. Ask an administrator if you need it. The server enforces this independently of the interface.
      </Banner>
    </>
  )
}
