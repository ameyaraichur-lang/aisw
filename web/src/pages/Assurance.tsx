import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAssuranceOverview, useDisagreements, useModelCalls, useTriggerPolicy } from '../api/hooks'
import type { AiDecision, Disagreement } from '../api/types'
import { useSession } from '../auth/useSession'
import { Badge, Banner, ConfirmDialog, DataState, PageHeader, Pagination, ShortHash } from '../components/ui'
import { fmtTime } from '../lib/format'
import { AI_VERDICT_DISPLAY, VERDICT_DISPLAY, display } from '../lib/status'

const STATES = [
  { value: 'open', label: 'Open dissent' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'notes', label: 'Review notes' },
  { value: 'all', label: 'All' },
] as const
const KIND_LABEL: Record<string, string> = { finding: 'Findings', risk: 'Risks', scenario: 'Scenarios', recommendation: 'Recommendations', narrative: 'AI-written text' }

function Overview() {
  const q = useAssuranceOverview()
  return (
    <DataState q={q} label="assurance overview">
      {(d) => (
        <div className="split split--2">
          <section className="panel" aria-labelledby="as-eng">
            <h2 id="as-eng">Deterministic assurance (authoritative)</h2>
            {Object.keys(d.assurance).length ? (
              <table data-testid="assurance-verdicts"><caption>Current verdicts per item kind, across runs</caption>
                <thead><tr><th scope="col">Kind</th><th scope="col">Accepted</th><th scope="col">Needs review</th><th scope="col">Rejected</th></tr></thead>
                <tbody>{Object.entries(d.assurance).map(([k, v]) => (
                  <tr key={k}><th scope="row">{KIND_LABEL[k] ?? k}</th><td>{v.ACCEPT ?? 0}</td><td>{v.NEEDS_REVIEW ?? 0}</td><td>{v.REJECT ?? 0}</td></tr>))}</tbody>
              </table>
            ) : <p className="muted">No item has been assessed yet.</p>}
            <h3>Most frequent defect codes</h3>
            {d.defects.length ? <ul className="list-plain">{d.defects.map((x) => <li key={x.code}><code>{x.code}</code> {x.count}</li>)}</ul> : <p className="muted">None.</p>}
          </section>
          <section className="panel" aria-labelledby="as-ai">
            <h2 id="as-ai">AI validation (advisory)</h2>
            <p className="row" role="status">
              {Object.entries(d.ai_validation).map(([v, n]) => <span key={v}><Badge d={display(AI_VERDICT_DISPLAY, v)} /> {n}</span>)}
              {Object.keys(d.ai_validation).length ? null : <span className="muted">No AI validation has run.</span>}
            </p>
            <p data-testid="open-dissent">{d.open_dissent} dissent(s) awaiting a human decision.</p>
            {d.triggers.length ? (
              <table><caption>Trigger decisions per agent</caption>
                <thead><tr><th scope="col">Agent</th><th scope="col">Reviewed</th><th scope="col">Skipped by policy</th></tr></thead>
                <tbody>{d.triggers.map((t) => <tr key={t.agent_id}><th scope="row">{t.agent_id}. {t.agent_name}</th><td>{t.triggered}</td><td>{t.skipped}</td></tr>)}</tbody>
              </table>
            ) : null}
          </section>
        </div>
      )}
    </DataState>
  )
}

function Queue() {
  const [state, setState] = useState<string>('open')
  const [offset, setOffset] = useState(0)
  const q = useDisagreements({ state, limit: 20, offset })
  const { can } = useSession()
  const qc = useQueryClient()
  const [pending, setPending] = useState<{ item: Disagreement; decision: AiDecision } | null>(null)
  const [reason, setReason] = useState('')
  const resolve = useMutation({
    mutationFn: (p: { item: Disagreement; decision: AiDecision }) =>
      api(`/assessments/${p.item.run_id}/ai-validations/resolutions`, { method: 'POST', body: { target_ref: p.item.target_ref, decision: p.decision, reason: reason.trim() } }),
    onSuccess: () => { setPending(null); setReason(''); void qc.invalidateQueries({ queryKey: ['assurance'] }) },
  })
  const err = resolve.error instanceof ApiError ? resolve.error : null
  return (
    <section aria-labelledby="dq-h">
      <h2 id="dq-h">Engine versus AI disagreement queue</h2>
      <p className="hint">Each row puts the deterministic assurance verdict beside the AI reviewer&apos;s. A dissent holds the item until a human decides; a review note never holds anything.</p>
      <fieldset className="row">
        <legend className="sr-only">Show</legend>
        {STATES.map((s) => <label key={s.value}><input type="radio" name="dq-state" checked={state === s.value} onChange={() => { setState(s.value); setOffset(0) }} /> {s.label}</label>)}
      </fieldset>
      <DataState q={q} label="disagreements" isEmpty={(d) => d.items.length === 0} empty={<p className="muted">Nothing here. With AI validation off, there is never a disagreement to resolve.</p>}>
        {(d) => (
          <>
            <div className="table-wrap">
              <table data-testid="disagreements">
                <caption>{STATES.find((s) => s.value === state)?.label}: {d.total} (AI-generated review, advisory)</caption>
                <thead><tr><th scope="col">Item</th><th scope="col">Engine</th><th scope="col">AI reviewer</th><th scope="col">Why</th><th scope="col">Human decision</th></tr></thead>
                <tbody>{d.items.map((i) => (
                  <tr key={i.run_id + i.target_ref}>
                    <td><code>{i.target_ref}</code><br /><span className="muted">{i.agent_id}. {i.agent_name} · {i.project_name} · <Link to={`/assessments/${i.run_id}/analysis`}>run {i.run_id.slice(0, 8)}</Link></span></td>
                    <td>{i.engine_verdict ? <Badge d={display(VERDICT_DISPLAY, i.engine_verdict)} /> : <span className="muted">No assurance item</span>}{i.engine_defects.length ? <><br /><span className="muted">{i.engine_defects.join(', ')}</span></> : null}</td>
                    <td><Badge d={display(AI_VERDICT_DISPLAY, i.ai_verdict)} /><br /><span className="muted">{i.model_id ?? 'unknown model'}{i.validator_confidence ? `, ${i.validator_confidence.toLowerCase()} confidence` : ''}</span></td>
                    <td>
                      {i.issues.length ? <ul className="list-plain">{i.issues.map((x, n) => <li key={n}><code>{x.code}</code> {x.explanation}</li>)}</ul> : null}
                      {i.human_questions.length ? <ul className="list-plain">{i.human_questions.map((x, n) => <li key={n}>Question: {x}</li>)}</ul> : null}
                    </td>
                    <td>
                      {i.resolution ? <span><Badge d={i.resolution.decision === 'OVERRULE' ? { icon: '↺', label: 'Overruled', tone: 'neutral' } : { icon: '✓', label: 'Upheld', tone: 'warn' }} /> by {i.resolution.decided_by} at {fmtTime(i.resolution.decided_at)}: {i.resolution.reason}</span>
                        : i.resolvable && can('report:approve') ? (
                          <span className="row">
                            <button type="button" className="btn" onClick={() => { resolve.reset(); setReason(''); setPending({ item: i, decision: 'OVERRULE' }) }}>Overrule</button>
                            <button type="button" className="btn" onClick={() => { resolve.reset(); setReason(''); setPending({ item: i, decision: 'UPHOLD' }) }}>Uphold</button>
                          </span>
                        ) : i.resolvable ? <span className="muted">Awaiting a reviewer</span> : <span className="muted">Note only</span>}
                    </td>
                  </tr>))}
                </tbody>
              </table>
            </div>
            <Pagination total={d.total} limit={20} offset={offset} onChange={setOffset} />
          </>
        )}
      </DataState>
      <ConfirmDialog
        open={pending !== null}
        title={pending?.decision === 'OVERRULE' ? 'Overrule this AI dissent?' : 'Uphold this AI dissent?'}
        confirmLabel={pending?.decision === 'OVERRULE' ? 'Overrule' : 'Uphold'}
        busy={resolve.isPending}
        confirmDisabled={!reason.trim()}
        onConfirm={() => { if (pending) resolve.mutate(pending) }}
        onCancel={() => setPending(null)}
      >
        <p>
          {pending?.item.effect !== 'HOLD_FOR_REVIEW'
            ? 'This dissent did not hold anything back. Your decision is recorded; the report does not change.'
            : pending?.decision === 'OVERRULE'
            ? 'Independent assurance re-runs without this dissent and a new report revision replaces the unapproved one. The item is only accepted if its evidence still holds.'
            : 'The item stays held for review. Your decision is recorded; the report does not change.'}
        </p>
        <p><code>{pending?.item.target_ref}</code></p>
        <label htmlFor="dq-reason">Reason (required, recorded in the audit log)</label>
        <textarea id="dq-reason" value={reason} maxLength={1000} rows={3} onChange={(e) => setReason(e.target.value)} />
        {err ? <Banner tone="bad" role="alert" title={err.status === 403 ? 'You cannot resolve this dissent' : 'Decision refused'}>{err.message}</Banner> : null}
      </ConfirmDialog>
    </section>
  )
}

function TriggerPolicyPanel() {
  const q = useTriggerPolicy()
  return (
    <DataState q={q} label="trigger policy">
      {(p) => (
        <section className="panel" aria-labelledby="tp-h">
          <h2 id="tp-h">AI validation trigger policy</h2>
          <p className="row">
            <span className="chip">version {p.version}</span>
            <ShortHash value={p.sha256} />
            {p.signoff !== 'APPROVED' ? <Badge d={{ icon: '◇', label: 'Sample policy: awaiting policy-owner approval', tone: 'warn' }} /> : <Badge d={{ icon: '✓', label: 'Approved', tone: 'ok' }} />}
            <span className="chip">AI validation {p.ai_validation_enabled ? 'on' : 'off'}</span>
          </p>
          <p className="hint">Configuration, not code. An outcome the policy skips is still checked by the deterministic validator; the AI reviewer can only add caution. Under a token budget, packets are sent in this order: {p.priority.map((a) => a.agent_id).join(', ')}.</p>
          <div className="table-wrap">
            <table data-testid="trigger-rules"><caption>When each agent&apos;s outcomes are reviewed</caption>
              <thead><tr><th scope="col">Agent</th><th scope="col">Rules (any one triggers)</th><th scope="col">Why</th></tr></thead>
              <tbody>{p.agents.map((a) => <tr key={a.agent_id}><th scope="row">{a.agent_id}. {a.agent_name}</th><td>{a.rules.map((r) => <code key={r}>{r} </code>)}</td><td>{a.why}</td></tr>)}</tbody>
            </table>
          </div>
        </section>
      )}
    </DataState>
  )
}

export function AssuranceConsole() {
  return (
    <>
      <PageHeader title="Assurance Console" lead="Independent assurance decides what is authoritative. The AI reviewer is advisory: where it disagrees with the engine, a human decides, with a reason." />
      <Overview />
      <Queue />
      <TriggerPolicyPanel />
    </>
  )
}

export function ModelCallsPage() {
  const [offset, setOffset] = useState(0)
  const [purpose, setPurpose] = useState('')
  const [status, setStatus] = useState('')
  const q = useModelCalls({ purpose: purpose || undefined, status: status || undefined, limit: 25, offset })
  return (
    <>
      <PageHeader title="Model-call ledger" lead="Every model call: who served it, what it cost and how it ended. Prompts and replies are never shown; their hashes are." />
      <div className="row">
        <div><label htmlFor="mc-purpose">Purpose</label>
          <select id="mc-purpose" value={purpose} onChange={(e) => { setPurpose(e.target.value); setOffset(0) }}>
            <option value="">All</option><option value="validation">AI validation</option><option value="scenario">Scenario narrative</option><option value="recommendation">Recommendation narrative</option><option value="executive">Executive summary</option><option value="verification">Verification questions</option>
          </select></div>
        <div><label htmlFor="mc-status">Outcome</label>
          <select id="mc-status" value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0) }}>
            <option value="">All</option><option value="VALIDATED">Validated</option><option value="REJECTED">Rejected</option><option value="UNAVAILABLE">Unavailable</option>
          </select></div>
      </div>
      <DataState q={q} label="model calls" isEmpty={(d) => d.items.length === 0} empty={<p className="muted">No model call is recorded. With AI off, none is ever made.</p>}>
        {(d) => (
          <>
            <p role="status" data-testid="model-call-totals">
              {d.totals.calls} call(s); {d.totals.input_tokens} input and {d.totals.output_tokens} output tokens; {d.totals.latency_ms} ms in total; {d.totals.replayed} replayed; {d.totals.unmetered} unmetered; {d.totals.not_validated} not validated.
            </p>
            <div className="table-wrap">
              <table data-testid="model-calls">
                <caption>Model calls: {d.total}</caption>
                <thead><tr><th scope="col">When</th><th scope="col">Purpose</th><th scope="col">Model</th><th scope="col">Outcome</th><th scope="col">Tokens (in/out)</th><th scope="col">Latency</th><th scope="col">Input hash</th></tr></thead>
                <tbody>{d.items.map((c) => (
                  <tr key={c.input_hash + c.created_at + c.subject_ref}>
                    <td>{fmtTime(c.created_at)}<br /><Link to={`/assessments/${c.run_id}`}>{c.project_name} · {c.run_id.slice(0, 8)}</Link></td>
                    <td><code>{c.purpose}</code><br /><span className="muted">{c.subject_ref}</span></td>
                    <td>{c.model_id ?? <span className="muted">unknown</span>}<br /><span className="muted">prompt {c.prompt_version}</span></td>
                    <td>{c.status}{c.replayed ? ' (replayed)' : ''}{c.defects.length ? <><br /><span className="muted">{c.defects.join(', ')}</span></> : null}</td>
                    <td>{c.input_tokens ?? '–'} / {c.output_tokens ?? '–'}</td>
                    <td>{c.latency_ms === null ? '–' : `${c.latency_ms} ms`}</td>
                    <td><ShortHash value={c.input_hash} /></td>
                  </tr>))}
                </tbody>
              </table>
            </div>
            <Pagination total={d.total} limit={25} offset={offset} onChange={setOffset} />
          </>
        )}
      </DataState>
    </>
  )
}
