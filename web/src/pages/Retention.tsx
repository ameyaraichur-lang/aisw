import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useRetentionActions, useRetentionChecks, useRetentionHolds, useRetentionPlan } from '../api/hooks'
import type { RetentionCheck, RetentionPlan } from '../api/types'
import { useSession } from '../auth/useSession'
import { Badge, Banner, ConfirmDialog, DataState, PageHeader, ShortHash } from '../components/ui'
import { fmtTime } from '../lib/format'

const OUTCOME: Record<RetentionCheck['outcome'], { icon: string; label: string; tone: 'ok' | 'warn' | 'bad' | 'info' }> = {
  NOTHING_DUE: { icon: '✓', label: 'Nothing due', tone: 'ok' },
  DUE: { icon: '◐', label: 'Due: awaiting a retention manager', tone: 'warn' },
  AWAITING_CONFIRMATION: { icon: '◐', label: 'Due: waiting for the confirmation window', tone: 'warn' },
  EXECUTED: { icon: '⇢', label: 'Moved to quarantine by the scheduler', tone: 'info' },
  PLAN_CHANGED: { icon: '⚠', label: 'Plan changed during execution: nothing moved', tone: 'bad' },
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

function PlanPanel({ plan }: { plan: RetentionPlan }) {
  const qc = useQueryClient()
  const [reason, setReason] = useState('')
  const [open, setOpen] = useState(false)
  const exec = useMutation({
    mutationFn: () => api<{ items: number; blobs_moved_to_quarantine: number; blobs_not_found: number }>('/retention/execute', { method: 'POST', body: { plan_hash: plan.plan_hash, reason } }),
    onSettled: () => { setOpen(false); void qc.invalidateQueries({ queryKey: ['retention'] }) },
    onSuccess: () => setReason(''),
  })
  const err = exec.error instanceof ApiError ? exec.error : null
  return (
    <section className="panel" aria-labelledby="plan-h">
      <h2 id="plan-h">Current plan</h2>
      <Banner tone="info" title="Dry run: nothing has been changed">
        Built {fmtTime(plan.as_of)}, plan <ShortHash value={plan.plan_hash} />. Executing moves blobs to a quarantine folder; nothing is deleted.
      </Banner>
      <dl className="kv" data-testid="plan-summary">
        <dt>Due</dt><dd>{plan.items.length} items, {plan.blobs} blobs, {fmtBytes(plan.bytes)}</dd>
        <dt>Under legal hold</dt><dd>{plan.held_runs.length ? plan.held_runs.length === 1 ? '1 run' : `${plan.held_runs.length} runs` : 'none'}</dd>
        <dt>Kept because shared</dt><dd>{plan.kept_shared.length ? `${plan.kept_shared.length} blobs are also used by evidence that stays` : 'none'}</dd>
      </dl>
      {plan.items.length ? (
        <table className="table" data-testid="plan-items">
          <caption className="sr-only">Items the plan would move to quarantine</caption>
          <thead><tr><th scope="col">Kind</th><th scope="col">Reference</th><th scope="col">Run</th><th scope="col">Size</th><th scope="col">Blob</th></tr></thead>
          <tbody>
            {plan.items.slice(0, 200).map((i) => (
              <tr key={`${i.kind}-${i.ref}`}>
                <td>{i.kind === 'EVIDENCE' ? 'Run evidence' : 'Uploaded import'}</td>
                <td><code>{i.ref}</code></td>
                <td>{i.run_id ? <Link to={`/assessments/${i.run_id}`}>{i.run_id}</Link> : '—'}</td>
                <td>{fmtBytes(i.size_bytes)}</td>
                <td><ShortHash value={i.content_hash} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <p className="muted">Nothing is due for retention.</p>}
      {plan.items.length > 200 ? <p className="hint">Showing the first 200 of {plan.items.length} items.</p> : null}
      {exec.isSuccess ? <Banner tone="ok" title="Moved to quarantine">{exec.data.items} items; {exec.data.blobs_moved_to_quarantine} blobs moved{exec.data.blobs_not_found ? `, ${exec.data.blobs_not_found} already missing` : ''}. Nothing was deleted.</Banner> : null}
      {err ? <Banner tone="bad" role="alert" title={err.status === 409 ? 'The plan changed' : 'Execution refused'}>{err.status === 409 ? 'Something changed since you reviewed this plan, so nothing was moved. It has been rebuilt; review it again.' : err.message}</Banner> : null}
      {plan.items.length ? (
        <div style={{ marginTop: '1rem' }}>
          <label htmlFor="ret-reason">Reason (recorded with every item)</label>
          <input id="ret-reason" value={reason} maxLength={1000} onChange={(e) => setReason(e.target.value)} />
          <p><button type="button" className="btn btn--primary" disabled={!reason.trim() || exec.isPending} onClick={() => setOpen(true)}>Move to quarantine</button></p>
        </div>
      ) : null}
      <ConfirmDialog open={open} title="Move this plan's evidence to quarantine?" confirmLabel="Move to quarantine" busy={exec.isPending} onConfirm={() => exec.mutate()} onCancel={() => setOpen(false)}>
        <p>{plan.items.length} items ({fmtBytes(plan.bytes)}) move to quarantine under plan <ShortHash value={plan.plan_hash} />. The server rebuilds the plan first and refuses if anything changed.</p>
      </ConfirmDialog>
    </section>
  )
}

function Holds({ manage }: { manage: boolean }) {
  const qc = useQueryClient()
  const holds = useRetentionHolds()
  const [runId, setRunId] = useState('')
  const [reason, setReason] = useState('')
  const place = useMutation({
    mutationFn: () => api(`/assessments/${encodeURIComponent(runId.trim())}/retention-hold`, { method: 'POST', body: { reason } }),
    onSuccess: () => { setRunId(''); setReason('') },
    onSettled: () => void qc.invalidateQueries({ queryKey: ['retention'] }),
  })
  const release = useMutation({
    mutationFn: (id: string) => api(`/assessments/${encodeURIComponent(id)}/retention-hold/release`, { method: 'POST' }),
    onSettled: () => void qc.invalidateQueries({ queryKey: ['retention'] }),
  })
  const err = place.error instanceof ApiError ? place.error : null
  return (
    <section className="panel" aria-labelledby="holds-h">
      <h2 id="holds-h">Legal holds</h2>
      <p className="hint">A held run keeps all of its evidence, and any blob it shares with other runs, until the hold is released.</p>
      <DataState q={holds} label="holds" isEmpty={(d) => d.length === 0} empty={<p className="muted">No active holds.</p>}>
        {(rows) => (
          <table className="table" data-testid="holds">
            <caption className="sr-only">Active legal holds</caption>
            <thead><tr><th scope="col">Run</th><th scope="col">Project</th><th scope="col">Reason</th><th scope="col">Placed</th>{manage ? <th scope="col"><span className="sr-only">Actions</span></th> : null}</tr></thead>
            <tbody>
              {rows.map((h) => (
                <tr key={h.run_id}>
                  <td><Link to={`/assessments/${h.run_id}`}>{h.run_id}</Link> <span className="muted">({h.run_state})</span></td>
                  <td>{h.project_name}</td>
                  <td>{h.reason}</td>
                  <td>{h.placed_by}, {fmtTime(h.placed_at)}</td>
                  {manage ? <td><button type="button" className="btn btn--small" disabled={release.isPending} onClick={() => release.mutate(h.run_id)}>Release hold</button></td> : null}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </DataState>
      {manage ? (
        <form className="row" style={{ marginTop: '1rem' }} onSubmit={(e) => { e.preventDefault(); place.mutate() }}>
          <label htmlFor="hold-run">Run id</label>
          <input id="hold-run" value={runId} onChange={(e) => setRunId(e.target.value)} />
          <label htmlFor="hold-reason">Reason</label>
          <input id="hold-reason" value={reason} maxLength={1000} onChange={(e) => setReason(e.target.value)} />
          <button type="submit" className="btn" disabled={!runId.trim() || !reason.trim() || place.isPending}>Place hold</button>
        </form>
      ) : null}
      {err ? <p className="field-error" role="alert">Hold refused: {err.status === 404 ? 'no such run in this tenant' : err.message}</p> : null}
    </section>
  )
}

function Checks() {
  const checks = useRetentionChecks()
  return (
    <section className="panel" aria-labelledby="checks-h">
      <h2 id="checks-h">Scheduled checks</h2>
      <DataState q={checks} label="scheduled checks" isEmpty={(d) => d.length === 0} empty={<p className="muted">The scheduler has not run yet. It runs daily from <code>aisw-retention.timer</code>.</p>}>
        {(rows) => (
          <table className="table" data-testid="retention-checks">
            <caption className="sr-only">Recent scheduled retention checks</caption>
            <thead><tr><th scope="col">When</th><th scope="col">Outcome</th><th scope="col">Due</th><th scope="col">Held runs</th><th scope="col">Plan</th></tr></thead>
            <tbody>
              {rows.map((c) => (
                <tr key={`${c.checked_at}-${c.plan_hash}`}>
                  <td>{fmtTime(c.checked_at)}</td>
                  <td><Badge d={OUTCOME[c.outcome]} /></td>
                  <td>{c.items} items, {fmtBytes(c.bytes)}</td>
                  <td>{c.held_runs}</td>
                  <td><ShortHash value={c.plan_hash} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </DataState>
    </section>
  )
}

function PurgeLog() {
  const actions = useRetentionActions(true)
  return (
    <section className="panel" aria-labelledby="log-h">
      <h2 id="log-h">Quarantine log</h2>
      <DataState q={actions} label="retention log" isEmpty={(d) => d.length === 0} empty={<p className="muted">Nothing has been moved to quarantine.</p>}>
        {(rows) => (
          <table className="table" data-testid="retention-log">
            <caption className="sr-only">Items moved to quarantine</caption>
            <thead><tr><th scope="col">When</th><th scope="col">By</th><th scope="col">Item</th><th scope="col">Blob</th><th scope="col">Reason</th></tr></thead>
            <tbody>
              {rows.slice(0, 200).map((a) => (
                <tr key={`${a.kind}-${a.ref}`}>
                  <td>{fmtTime(a.executed_at)}</td>
                  <td>{a.executed_by}</td>
                  <td>{a.kind === 'EVIDENCE' ? 'Run evidence' : 'Uploaded import'} <code>{a.ref}</code></td>
                  <td><ShortHash value={a.content_hash} /> {a.quarantined ? 'quarantined' : 'already missing'}</td>
                  <td>{a.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </DataState>
    </section>
  )
}

export function RetentionPage() {
  const { can } = useSession()
  const manage = can('retention:manage')
  const plan = useRetentionPlan(manage)
  return (
    <>
      <PageHeader title="Evidence Retention" lead="Evidence leaves only through a reviewed, hash-pinned plan, and only to quarantine. Final deletion is a separate manual step." />
      {manage ? (
        <DataState q={plan} label="retention plan">
          {(p) => (
            <>
              <p className="hint" data-testid="retention-schedule">
                Scheduled checks record this plan daily. Automatic execution is <strong>{p.schedule.auto_execute ? 'on' : 'off'}</strong>
                {p.schedule.auto_execute ? `: the scheduler moves a plan only after seeing the identical plan ${p.schedule.confirm_hours} hours earlier.` : ': a retention manager executes a reviewed plan here.'}
                {' '}Uploaded imports no run used are due after {p.schedule.import_retention_days} days.
              </p>
              <PlanPanel plan={p} />
            </>
          )}
        </DataState>
      ) : <p className="hint">You can read the schedule, holds and log. Planning and executing retention needs the retention:manage permission.</p>}
      <Holds manage={manage} />
      <Checks />
      {can('audit:read') ? <PurgeLog /> : null}
    </>
  )
}
