import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { ApiError } from '../api/client'
import type { Display } from '../lib/status'

/** Status is always label + icon + tone; never colour alone. */
export function Badge({ d, title }: { d: Display; title?: string }) {
  return (
    <span className={`badge badge--${d.tone}`} title={title}>
      <span aria-hidden="true" className="badge__icon">{d.icon}</span>
      <span>{d.label}</span>
    </span>
  )
}

export function Banner({ tone, title, children, role = 'status' }: { tone: Display['tone']; title: string; children?: ReactNode; role?: 'status' | 'alert' }) {
  return (
    <div className={`banner banner--${tone}`} role={role}>
      <strong>{title}</strong>
      {children ? <div>{children}</div> : null}
    </div>
  )
}

export function PageHeader({ title, children, lead }: { title: string; children?: ReactNode; lead?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1 tabIndex={-1}>{title}</h1>
        {lead ? <p className="lead">{lead}</p> : null}
      </div>
      {children ? <div className="page-header__actions">{children}</div> : null}
    </header>
  )
}

export function ErrorView({ error, retry }: { error: unknown; retry?: () => void }) {
  if (error instanceof ApiError) {
    if (error.status === 401) return <Banner tone="warn" role="alert" title="Session expired">Sign in again to continue.</Banner>
    if (error.status === 403)
      return (
        <Banner tone="warn" role="alert" title="Access denied">
          Your role does not allow this. The server enforces access; hiding a control is never the boundary.
        </Banner>
      )
    if (error.status === 404) return <Banner tone="neutral" role="alert" title="Not found">It does not exist or is outside your tenant.</Banner>
  }
  return (
    <Banner tone="bad" role="alert" title="Could not load this data">
      {String((error as Error)?.message ?? error)}{' '}
      {retry ? <button type="button" className="btn btn--small" onClick={retry}>Retry</button> : null}
    </Banner>
  )
}

/** Covers loading / denied / error / empty uniformly. */
export function DataState<T>({ q, isEmpty, empty, children, label }: { q: UseQueryResult<T>; isEmpty?: (d: T) => boolean; empty?: ReactNode; children: (d: T) => ReactNode; label: string }) {
  if (q.isPending) return <p role="status" className="muted">Loading {label}…</p>
  if (q.isError) return <ErrorView error={q.error} retry={() => void q.refetch()} />
  if (isEmpty?.(q.data)) return <>{empty ?? <p className="muted">Nothing to show yet.</p>}</>
  return <>{children(q.data)}</>
}

export function Card({ title, children, to }: { title: string; children: ReactNode; to?: ReactNode }) {
  return (
    <section className="card" aria-label={title}>
      <h2 className="card__title">{title}</h2>
      <div>{children}</div>
      {to ? <div className="card__link">{to}</div> : null}
    </section>
  )
}

export function ShortHash({ value }: { value: string }) {
  return <code className="hash" title={value}>{value.replace('sha256:', '').slice(0, 12)}…</code>
}

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [done, setDone] = useState(false)
  return (
    <button type="button" className="btn btn--small" onClick={() => { void navigator.clipboard?.writeText(value); setDone(true); setTimeout(() => setDone(false), 1500) }} aria-label={`Copy ${label}`}>
      {done ? 'Copied' : 'Copy'}
    </button>
  )
}

export function Pagination({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (o: number) => void }) {
  if (total <= limit) return <p className="muted" aria-live="polite">{total} item(s)</p>
  const page = Math.floor(offset / limit) + 1
  const pages = Math.ceil(total / limit)
  return (
    <nav aria-label="Pagination" className="pager">
      <button type="button" className="btn btn--small" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</button>
      <span aria-live="polite">Page {page} of {pages} ({total} items)</span>
      <button type="button" className="btn btn--small" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button>
    </nav>
  )
}

/** Native <dialog>: focus trap and Esc handling come from the platform. */
export function ConfirmDialog({ open, title, children, confirmLabel, busy, onConfirm, onCancel, confirmDisabled }: { open: boolean; title: string; children: ReactNode; confirmLabel: string; busy?: boolean; confirmDisabled?: boolean; onConfirm: () => void; onCancel: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const d = ref.current
    if (!d) return
    if (open && !d.open) d.showModal()
    if (!open && d.open) d.close()
  }, [open])
  return (
    <dialog ref={ref} className="dialog" aria-labelledby="dlg-title" onCancel={(e) => { e.preventDefault(); if (!busy) onCancel() }}>
      <h2 id="dlg-title">{title}</h2>
      <div>{children}</div>
      <div className="dialog__actions">
        <button type="button" className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
        <button type="button" className="btn btn--primary" onClick={onConfirm} disabled={busy || confirmDisabled}>{busy ? 'Working…' : confirmLabel}</button>
      </div>
    </dialog>
  )
}
