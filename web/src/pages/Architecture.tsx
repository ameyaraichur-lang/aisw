import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAgents, useAllRecommendations } from '../api/hooks'
import type { Recommendation, TicketDraft } from '../api/types'
import { useSession } from '../auth/useSession'
import { RecommendationBody, RecommendationHeader } from '../components/analysis'
import { Banner, ConfirmDialog, DataState, PageHeader, Pagination } from '../components/ui'
import { fmtTime } from '../lib/format'

type Row = Recommendation & { run_id: string; project_name: string }
type Decision = 'ACCEPT' | 'REJECT' | 'DEFER'
const LABEL: Record<Decision, string> = { ACCEPT: 'Accept for planning', DEFER: 'Defer', REJECT: 'Reject' }

function AgentsPanel() {
  const q = useAgents()
  return (
    <DataState q={q} label="agents">
      {(d) => (
        <section className="panel" aria-labelledby="agents-h">
          <h2 id="agents-h">Bounded agents</h2>
          <p className="hint">
            Every agent is read-only. AI is <strong>{d.ai.enabled ? 'enabled' : 'disabled'}</strong>
            {d.ai.enabled
              ? d.ai.provider === 'astra'
                ? <> (Astra deployment <code>{d.ai.model_id}</code>, remote Azure OpenAI endpoint; redacted findings leave this host under an approved data-handling decision)</>
                : <> (model <code>{d.ai.model_id}</code>, licence {d.ai.model_license}, local endpoint only)</>
              : null}
            {d.ai.validation_enabled ? <>. Agent outcomes are reviewed by an AI validator (<code>{d.ai.validation_model}</code>) that can only hold items for human review</> : null}
            {'. '}A model never has tools and never decides: deterministic checks do. Risk rubric <code>{d.rubric_version}</code>
            {d.signoffs.rubric !== 'APPROVED' ? ' (sample, awaiting policy-owner approval)' : null}.
          </p>
          <div className="table-wrap">
            <table>
              <caption>Agents and their adapters</caption>
              <thead><tr><th scope="col">Agent</th><th scope="col">Purpose</th><th scope="col">Adapters</th><th scope="col">AI</th></tr></thead>
              <tbody>
                {d.agents.map((a) => (
                  <tr key={a.agent_id}>
                    <th scope="row">{a.agent_id}. {a.name}</th>
                    <td>{a.purpose}</td>
                    <td>{a.adapters.length ? a.adapters.join(', ') : '–'}</td>
                    <td>
                      {a.ai_active ? 'Explanations on' : a.ai_capable ? 'Off' : 'Not used'}
                      {a.ai_validated ? <><br /><span className="muted">Outcomes reviewed by AI validator</span></> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </DataState>
  )
}

function Decide({ r, ticketsEnabled }: { r: Row; ticketsEnabled: boolean }) {
  const { can } = useSession()
  const qc = useQueryClient()
  const [pending, setPending] = useState<Decision | null>(null)
  const [reason, setReason] = useState('')
  const [draft, setDraft] = useState<TicketDraft | null>(null)
  const refresh = () => qc.invalidateQueries({ queryKey: ['recommendations'] })
  const decide = useMutation({
    mutationFn: (d: Decision) =>
      api(`/assessments/${r.run_id}/recommendations/${r.recommendation_id}/decision`, { method: 'POST', body: { decision: d, reason } }),
    onSuccess: () => { setPending(null); setReason(''); void refresh() },
  })
  const ticket = useMutation({
    mutationFn: () => api<TicketDraft>('/tickets/drafts', { method: 'POST', body: { run_id: r.run_id, recommendation_id: r.recommendation_id } }),
    onSuccess: (d) => setDraft(d),
  })
  const err = (decide.error ?? ticket.error) instanceof ApiError ? ((decide.error ?? ticket.error) as ApiError) : null
  const final = r.status === 'APPROVED_FOR_PLANNING' || r.status === 'REJECTED'
  if (!can('recommendation:decide')) {
    return <p className="hint">Deciding on recommendations needs the approver role. Your role can read them.</p>
  }
  return (
    <div>
      {r.decided_by ? <p className="hint">Decided by {r.decided_by} at {fmtTime(r.decided_at ?? '')}: {r.decision_reason}</p> : null}
      {err ? <Banner tone="bad" role="alert" title="Not done">{String((err.body as { detail?: string } | null)?.detail ?? err.message)}</Banner> : null}
      {!final ? (
        <p className="row">
          {(['ACCEPT', 'DEFER', 'REJECT'] as Decision[]).map((d) => (
            <button key={d} type="button" className={d === 'ACCEPT' ? 'btn btn--primary' : 'btn'} onClick={() => setPending(d)}>{LABEL[d]}</button>
          ))}
        </p>
      ) : null}
      {r.status === 'APPROVED_FOR_PLANNING' && ticketsEnabled ? (
        <p><button type="button" className="btn" onClick={() => ticket.mutate()} disabled={ticket.isPending}>Create ticket draft</button></p>
      ) : null}
      {draft ? (
        <Banner tone="ok" title="Ticket draft saved (not sent)">
          <p>{draft.payload.summary}</p>
          <p>Drafts stay in the outbox. Nothing is delivered to any ticketing system.</p>
        </Banner>
      ) : null}
      <ConfirmDialog
        open={pending !== null}
        title={pending ? `${LABEL[pending]}: ${r.title ?? r.recommendation_id}` : ''}
        confirmLabel={pending ? LABEL[pending] : 'Confirm'}
        busy={decide.isPending}
        confirmDisabled={reason.trim().length < 3}
        onConfirm={() => pending && decide.mutate(pending)}
        onCancel={() => { setPending(null); setReason('') }}
      >
        <p>This records your decision and the reason. <strong>It does not change any system.</strong></p>
        <label htmlFor={`why-${r.recommendation_id}`}>Reason (required)</label>
        <textarea id={`why-${r.recommendation_id}`} value={reason} onChange={(e) => setReason(e.target.value)} rows={3} maxLength={1000} />
      </ConfirmDialog>
    </div>
  )
}

export function Architecture() {
  const [sp, setSp] = useSearchParams()
  const status = sp.get('status') ?? ''
  const run = sp.get('run') ?? ''
  const [offset, setOffset] = useState(0)
  const q = useAllRecommendations({ status: status || undefined, run_id: run || undefined, limit: 10, offset })
  const agents = useAgents()
  return (
    <>
      <PageHeader
        title="Architecture & Modernization"
        lead="Draft recommendations built from independently accepted findings and approved target patterns. They are for planning only: nothing here changes a system."
      />
      <AgentsPanel />
      {agents.data?.signoffs.catalog === 'APPROVED'
        ? null
        : <Banner tone="info" title="Sample patterns">The target patterns come from a sample catalog that must be replaced with your approved reference architecture. Effort is never estimated by the platform.</Banner>}
      {run ? <p className="row"><span className="chip">Showing run {run.slice(0, 8)} only</span> <button type="button" className="btn" onClick={() => { setOffset(0); setSp(status ? { status } : {}) }}>Show all runs</button></p> : null}
      <fieldset>
        <legend>Filter</legend>
        <label htmlFor="rec-status">Decision status</label>{' '}
        <select id="rec-status" value={status} onChange={(e) => { setOffset(0); const n: Record<string, string> = {}; if (run) n.run = run; if (e.target.value) n.status = e.target.value; setSp(n) }}>
          <option value="">All</option>
          <option value="DRAFT">Draft</option>
          <option value="NEEDS_REVIEW">Deferred</option>
          <option value="APPROVED_FOR_PLANNING">Accepted for planning</option>
          <option value="REJECTED">Rejected</option>
        </select>
      </fieldset>
      <DataState q={q} label="recommendations" isEmpty={(d) => d.items.length === 0} empty={<p className="muted">No accepted recommendations match. Recommendations appear after an assessment finishes and passes independent assurance.</p>}>
        {(d) => (
          <>
            <p role="status">{d.total} recommendation(s)</p>
            <ul className="list-plain">
              {d.items.map((r) => (
                <li key={r.run_id + r.recommendation_id}>
                  <section className="panel" aria-labelledby={`rec-${r.run_id}-${r.recommendation_id}`}>
                    <h2 id={`rec-${r.run_id}-${r.recommendation_id}`}>{r.title}</h2>
                    <RecommendationHeader r={r}>
                      <span className="chip">{r.project_name}</span>
                      <Link to={`/assessments/${r.run_id}/analysis`}>Run {r.run_id.slice(0, 8)}</Link>
                    </RecommendationHeader>
                    <details>
                      <summary>Details, validation and rollback</summary>
                      <RecommendationBody r={r} />
                    </details>
                    <Decide r={r} ticketsEnabled={agents.data?.ticket_drafts_enabled ?? false} />
                  </section>
                </li>
              ))}
            </ul>
            <Pagination total={d.total} limit={10} offset={offset} onChange={setOffset} />
          </>
        )}
      </DataState>
    </>
  )
}
