import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAgents, useRenderedTicket, useTicketOutbox } from '../api/hooks'
import type { ItsmTarget, OutboxRow } from '../api/types'
import { useSession } from '../auth/useSession'
import { Badge, Banner, ConfirmDialog, DataState, PageHeader } from '../components/ui'
import { fmtTime } from '../lib/format'
import { TICKET_DISPLAY, display } from '../lib/status'

const TARGET_LABEL: Record<ItsmTarget, string> = { jira: 'Jira', servicenow: 'ServiceNow' }
const ERROR_LABEL: Record<string, string> = {
  ITSM_UNREACHABLE: 'The ticketing system did not answer in time. Sending again first checks whether the ticket was created, so it is never duplicated.',
  ITSM_REFUSED_401: 'The ticketing system refused the service credentials.',
  ITSM_REFUSED_403: 'The service account may not create tickets there.',
}

function errorText(code: string | null): string | null {
  if (!code) return null
  return ERROR_LABEL[code] ?? `The ticketing system answered with ${code}.`
}

function Preview({ row }: { row: OutboxRow }) {
  const [target, setTarget] = useState<ItsmTarget | null>(row.target)
  const q = useRenderedTicket(row.outbox_id, target)
  const id = `tgt-${row.outbox_id}`
  return (
    <div>
      <label htmlFor={id}>Render for</label>{' '}
      <select id={id} value={target ?? ''} disabled={row.target !== null} onChange={(e) => setTarget((e.target.value || null) as ItsmTarget | null)}>
        <option value="">Configured system</option>
        <option value="jira">Jira</option>
        <option value="servicenow">ServiceNow</option>
      </select>
      <DataState q={q} label="ticket preview">
        {(d) => (
          <>
            <p className="hint">
              {TARGET_LABEL[d.target]} payload exactly as it would be sent. Correlation key <code>{d.correlation_key}</code> lets a retry find this ticket instead of creating a second one.
            </p>
            <pre className="code" data-testid="ticket-payload" tabIndex={0} aria-label={`${TARGET_LABEL[d.target]} payload`}>{JSON.stringify(d.payload, null, 2)}</pre>
          </>
        )}
      </DataState>
    </div>
  )
}

function SendControl({ row, target }: { row: OutboxRow; target: ItsmTarget }) {
  const { can, me } = useSession()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const send = useMutation({
    mutationFn: () => api<OutboxRow>(`/tickets/drafts/${row.outbox_id}/send`, { method: 'POST' }),
    onSettled: () => { setOpen(false); void qc.invalidateQueries({ queryKey: ['tickets'] }) },
  })
  if (row.status === 'SENT') return null
  if (!can('recommendation:decide')) return <p className="hint">Sending a ticket needs the approver role.</p>
  if (me?.actor_id === row.created_by) return <p className="hint">You drafted this ticket, so another approver sends it.</p>
  const err = send.error instanceof ApiError ? (send.error.body as { detail?: { code?: string } | string } | null)?.detail : null
  const code = err && typeof err === 'object' ? err.code ?? null : null
  return (
    <div>
      {send.error && !code ? <Banner tone="bad" role="alert" title="Not sent">{typeof err === 'string' ? err : send.error.message}</Banner> : null}
      <p><button type="button" className="btn btn--primary" onClick={() => setOpen(true)}>{row.status === 'FAILED' ? `Retry sending to ${TARGET_LABEL[target]}` : `Send to ${TARGET_LABEL[target]}`}</button></p>
      <ConfirmDialog
        open={open}
        title={`Send to ${TARGET_LABEL[target]}: ${row.payload.summary}`}
        confirmLabel="Send ticket"
        busy={send.isPending}
        onConfirm={() => send.mutate()}
        onCancel={() => setOpen(false)}
      >
        <p>This creates one ticket in {TARGET_LABEL[target]} from the draft drafted by {row.created_by}. <strong>It does not change any system AISW assessed.</strong></p>
        <p>The ticket is never updated or closed by AISW afterwards.</p>
      </ConfirmDialog>
    </div>
  )
}

function OutboxItem({ row, target }: { row: OutboxRow; target: ItsmTarget | null }) {
  const problem = row.status === 'FAILED' ? errorText(row.last_error) : null
  const hid = `tk-${row.outbox_id}`
  return (
    <li>
      <section className="panel" aria-labelledby={hid}>
        <h2 id={hid}>{row.payload.summary}</h2>
        <p className="row">
          <Badge d={display(TICKET_DISPLAY, row.status)} />
          <Link to={`/assessments/${row.run_id}/analysis`}>Run {row.run_id.slice(0, 8)}</Link>
          <span className="muted">Drafted by {row.created_by} on {fmtTime(row.created_at)}</span>
        </p>
        {row.status === 'SENT' ? (
          <p>
            {TARGET_LABEL[row.target ?? 'jira']} ticket{' '}
            {row.external_url ? <a href={row.external_url} rel="noreferrer noopener" target="_blank">{row.external_ref}</a> : <strong>{row.external_ref}</strong>}
            {' '}sent by {row.sent_by} on {fmtTime(row.sent_at ?? '')} after {row.attempts} attempt(s).
          </p>
        ) : null}
        {problem ? <Banner tone="warn" title={`Attempt ${row.attempts} failed`}>{problem}</Banner> : null}
        <details>
          <summary>Ticket payload</summary>
          <Preview row={row} />
        </details>
        {target ? <SendControl row={row} target={row.target ?? target} /> : null}
      </section>
    </li>
  )
}

export function TicketOutbox() {
  const [sp] = useSearchParams()
  const run = sp.get('run') ?? undefined
  const q = useTicketOutbox(run)
  const agents = useAgents()
  const delivery = agents.data?.ticket_delivery
  return (
    <>
      <PageHeader
        title="Ticket Outbox"
        lead="Ticket drafts made from accepted recommendations. A draft is rendered for Jira or ServiceNow, and a second approver may send it once. Nothing here changes an assessed system."
      />
      {delivery?.enabled && delivery.target ? (
        <Banner tone="info" title={`Delivery to ${TARGET_LABEL[delivery.target]} is on`}>
          A draft is sent only by an approver other than the one who drafted it. Effort is never estimated by AISW.
        </Banner>
      ) : (
        <Banner tone="info" title="Delivery is off">
          Drafts stay here and can be previewed or copied. An administrator turns delivery on once the ticketing system, its service account and the egress rule are approved.
        </Banner>
      )}
      <DataState q={q} label="ticket drafts" isEmpty={(d) => d.length === 0} empty={<p className="muted">No ticket drafts yet. An approver creates one from an accepted recommendation on the <Link to="/architecture">Architecture</Link> page.</p>}>
        {(d) => (
          <>
            <p role="status">{d.length} draft(s), {d.filter((r) => r.status === 'SENT').length} sent</p>
            <ul className="list-plain">
              {d.map((r) => <OutboxItem key={r.outbox_id} row={r} target={delivery?.enabled ? delivery.target : null} />)}
            </ul>
          </>
        )}
      </DataState>
    </>
  )
}
