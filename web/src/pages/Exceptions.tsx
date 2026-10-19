import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useExceptions } from '../api/hooks'
import type { ExceptionItem, FindingDetail, ReviewAction } from '../api/types'
import { Badge, Banner, ConfirmDialog, DataState, PageHeader } from '../components/ui'
import { fmtTime } from '../lib/format'
import { EXCEPTION_DISPLAY, LIFECYCLE_LABEL, display } from '../lib/status'

const ACTION_LABEL: Record<ReviewAction, string> = {
  CONFIRM: 'Confirm finding',
  REJECT: 'Reject as false positive',
  REOPEN: 'Reopen',
  REQUEST_EXCEPTION: 'Request exception',
}
const HISTORY_LABEL: Record<string, string> = {
  CONFIRM: 'confirmed', REJECT: 'rejected as a false positive', REOPEN: 'reopened',
  REQUEST_EXCEPTION: 'requested an exception', EXCEPTION_APPROVED: 'approved the exception',
  EXCEPTION_REJECTED: 'rejected the exception', EXCEPTION_REVOKED: 'revoked the exception',
}
const STATES = ['PENDING', 'ACTIVE', 'EXPIRED', 'REJECTED', 'REVOKED'] as const

const isoDay = (d: Date) => d.toISOString().slice(0, 10)
const endOfDayUtc = (day: string) => new Date(`${day}T23:59:59Z`).toISOString()

function ExceptionSummary({ e }: { e: ExceptionItem }) {
  return (
    <dl className="kv">
      <dt>State</dt><dd><Badge d={display(EXCEPTION_DISPLAY, e.state)} />{e.days_left !== null ? <span className="muted"> {e.days_left} day(s) left</span> : null}</dd>
      <dt>Expires</dt><dd>{fmtTime(e.expires_at)}</dd>
      <dt>Requested</dt><dd>{e.requested_by} on {fmtTime(e.requested_at)}: {e.reason}</dd>
      {e.decided_by ? <><dt>Decision</dt><dd>{e.decided_by} on {fmtTime(e.decided_at)}: {e.decision_reason}</dd></> : null}
      {e.revoked_by ? <><dt>Revoked</dt><dd>{e.revoked_by} on {fmtTime(e.revoked_at)}: {e.revoke_reason}</dd></> : null}
    </dl>
  )
}

/** Review actions on one finding. The server decides which actions are allowed; this only offers them. */
export function ReviewPanel({ runId, d }: { runId: string; d: FindingDetail }) {
  const qc = useQueryClient()
  const [action, setAction] = useState<ReviewAction | null>(null)
  const [reason, setReason] = useState('')
  const [until, setUntil] = useState('')
  const [today] = useState(() => new Date())
  const maxDay = isoDay(new Date(today.getTime() + d.exception_max_days * 86_400_000))
  const save = useMutation({
    mutationFn: () => api(`/assessments/${runId}/findings/${d.finding.finding_id}/review`, {
      method: 'POST',
      body: { action, reason: reason.trim(), ...(action === 'REQUEST_EXCEPTION' ? { expires_at: endOfDayUtc(until) } : {}) },
    }),
    onSuccess: () => { setAction(null); void qc.invalidateQueries({ queryKey: ['run', runId] }); void qc.invalidateQueries({ queryKey: ['exceptions'] }) },
  })
  const open = (a: ReviewAction) => {
    save.reset(); setReason(''); setAction(a)
    setUntil(isoDay(new Date(today.getTime() + Math.min(90, d.exception_max_days) * 86_400_000)))
  }
  const err = save.error instanceof ApiError ? save.error : null
  return (
    <section className="panel" aria-labelledby="ra">
      <h2 id="ra">Review actions</h2>
      <p>Lifecycle: <strong data-testid="lifecycle">{LIFECYCLE_LABEL[d.lifecycle] ?? d.lifecycle}</strong></p>
      <p className="hint">A review changes the lifecycle only. The outcome, severity and assurance verdict stay as recorded.</p>
      {d.review_actions.length ? (
        <div className="row">{d.review_actions.map((a) => <button key={a} type="button" className="btn btn--small" onClick={() => open(a)}>{ACTION_LABEL[a]}</button>)}</div>
      ) : <p className="muted">No review action is available to you for this finding.</p>}
      {d.exception ? (
        <>
          <h3>Exception <code>{d.exception.exception_id}</code></h3>
          <ExceptionSummary e={d.exception} />
          <p className="hint">An exception covers this rule on this asset in later runs while it is in force; when it expires the finding is reported again. <Link to="/exceptions">All exceptions</Link></p>
        </>
      ) : null}
      <h3>History</h3>
      {d.review_history.length ? (
        <ol data-testid="review-history">{d.review_history.map((h, i) => <li key={i}>{fmtTime(h.at)}: {h.actor} {HISTORY_LABEL[h.action] ?? h.action} ({h.reason})</li>)}</ol>
      ) : <p className="muted">No review recorded yet.</p>}
      <ConfirmDialog open={action !== null} title={action ? ACTION_LABEL[action] : ''} confirmLabel="Record" busy={save.isPending}
        confirmDisabled={!reason.trim() || (action === 'REQUEST_EXCEPTION' && !until)} onConfirm={() => save.mutate()} onCancel={() => setAction(null)}>
        {action === 'REQUEST_EXCEPTION' ? (
          <>
            <p>An approver other than you must approve the exception. It applies only to later runs and only until it expires.</p>
            <label htmlFor="exc-until">Expires at the end of (UTC)</label>
            <input id="exc-until" type="date" value={until} min={isoDay(new Date(today.getTime() + 86_400_000))} max={maxDay} onChange={(e) => setUntil(e.target.value)} />
            <p className="hint">At most {d.exception_max_days} days.</p>
          </>
        ) : null}
        <label htmlFor="review-reason">Reason (recorded in the audit trail)</label>
        <textarea id="review-reason" rows={3} maxLength={1000} value={reason} onChange={(e) => setReason(e.target.value)} />
        {err ? <Banner tone="bad" role="alert" title="Not recorded">{err.message}</Banner> : null}
      </ConfirmDialog>
    </section>
  )
}

export function Exceptions() {
  const [sp, setSp] = useSearchParams()
  const st = sp.get('state') ?? ''
  const q = useExceptions({ state: st || undefined })
  const [pending, setPending] = useState<{ e: ExceptionItem; kind: 'APPROVE' | 'REJECT' | 'REVOKE' } | null>(null)
  return (
    <>
      <PageHeader title="Exceptions" lead="Time-boxed risk acceptances for one rule on one asset. Each needs an approver other than the requester, covers only later runs, and lapses on its expiry date." />
      <label htmlFor="exc-state">State</label>
      <select id="exc-state" value={st} onChange={(e) => { const p = new URLSearchParams(); if (e.target.value) p.set('state', e.target.value); setSp(p) }}>
        <option value="">All</option>
        {STATES.map((s) => <option key={s} value={s}>{EXCEPTION_DISPLAY[s].label}</option>)}
      </select>
      <div style={{ marginTop: '1rem' }}>
        <DataState q={q} label="exceptions" isEmpty={(d) => d.items.length === 0} empty={<p className="muted">No exceptions match. Request one from a finding&apos;s review actions.</p>}>
          {(d) => (
            <>
              <p className="row" data-testid="exception-counts">{STATES.map((s) => <Badge key={s} d={{ ...EXCEPTION_DISPLAY[s], label: `${d.counts[s]} ${EXCEPTION_DISPLAY[s].label.toLowerCase()}` }} />)}</p>
              <div className="table-wrap">
                <table>
                  <caption>Exceptions as of {fmtTime(d.as_of)}</caption>
                  <thead><tr><th scope="col">Check</th><th scope="col">Asset</th><th scope="col">Project</th><th scope="col">State</th><th scope="col">Expires</th><th scope="col">Requested by</th>{d.can_decide ? <th scope="col">Decision</th> : null}</tr></thead>
                  <tbody>{d.items.map((e) => (
                    <tr key={e.exception_id}>
                      <td><Link to={`/findings/${e.source_run_id}/${e.source_finding_id}`}>{e.title}</Link><div className="muted"><code>{e.exception_id}</code>: {e.reason}</div></td>
                      <td>{e.asset_id}</td><td>{e.project_name}</td>
                      <td><Badge d={display(EXCEPTION_DISPLAY, e.state)} /></td>
                      <td>{fmtTime(e.expires_at)}{e.days_left !== null ? <div className="muted">{e.days_left} day(s) left</div> : null}</td>
                      <td>{e.requested_by}</td>
                      {d.can_decide ? (
                        <td>
                          {e.state === 'PENDING' ? (
                            <div className="row">
                              <button type="button" className="btn btn--small" aria-label={`Approve exception ${e.exception_id}`} onClick={() => setPending({ e, kind: 'APPROVE' })}>Approve</button>
                              <button type="button" className="btn btn--small" aria-label={`Reject exception ${e.exception_id}`} onClick={() => setPending({ e, kind: 'REJECT' })}>Reject</button>
                            </div>
                          ) : e.state === 'ACTIVE' ? (
                            <button type="button" className="btn btn--small btn--danger" aria-label={`Revoke exception ${e.exception_id}`} onClick={() => setPending({ e, kind: 'REVOKE' })}>Revoke</button>
                          ) : <span className="muted">{e.decided_by ? `by ${e.decided_by}` : '–'}</span>}
                        </td>
                      ) : null}
                    </tr>))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </DataState>
      </div>
      {pending ? <DecisionDialog e={pending.e} kind={pending.kind} onClose={() => setPending(null)} /> : null}
    </>
  )
}

function DecisionDialog({ e, kind, onClose }: { e: ExceptionItem; kind: 'APPROVE' | 'REJECT' | 'REVOKE'; onClose: () => void }) {
  const qc = useQueryClient()
  const [reason, setReason] = useState('')
  const save = useMutation({
    mutationFn: () => kind === 'REVOKE'
      ? api(`/exceptions/${e.exception_id}/revoke`, { method: 'POST', body: { reason: reason.trim() } })
      : api(`/exceptions/${e.exception_id}/decision`, { method: 'POST', body: { decision: kind, reason: reason.trim() } }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['exceptions'] }); void qc.invalidateQueries({ queryKey: ['run'] }); void qc.invalidateQueries({ queryKey: ['overview'] }); onClose() },
  })
  const err = save.error instanceof ApiError ? save.error : null
  const verb = { APPROVE: 'Approve', REJECT: 'Reject', REVOKE: 'Revoke' }[kind]
  return (
    <ConfirmDialog open title={`${verb} exception ${e.exception_id}`} confirmLabel={verb} busy={save.isPending} confirmDisabled={!reason.trim()} onConfirm={() => save.mutate()} onCancel={onClose}>
      <p><strong>{e.title}</strong> on {e.asset_id}, requested by {e.requested_by}: {e.reason}</p>
      <p>Expires {fmtTime(e.expires_at)}.{kind === 'APPROVE' ? ' Later runs will report this check as an exception, not a finding, until then.' : kind === 'REVOKE' ? ' Later runs will report the finding again.' : ''}</p>
      <label htmlFor="exc-reason">Reason (recorded in the audit trail)</label>
      <textarea id="exc-reason" rows={3} maxLength={1000} value={reason} onChange={(ev) => setReason(ev.target.value)} />
      {err ? <Banner tone="bad" role="alert" title="Not recorded">{err.message}</Banner> : null}
    </ConfirmDialog>
  )
}
