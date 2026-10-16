import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, ApiError } from '../api/client'
import { useControlMatrix, usePolicyPacks, useRuns } from '../api/hooks'
import type { ControlMatrix as Matrix, FrameworkMapping, MappingStatus } from '../api/types'
import { Badge, Banner, ConfirmDialog, DataState, PageHeader } from '../components/ui'
import { fmtTime } from '../lib/format'
import { MAPPING_DISPLAY, OUTCOME_DISPLAY, display } from '../lib/status'

const FINISHED = ['REPORT_READY', 'PARTIAL', 'CLOSED']
const DECISIONS: { value: MappingStatus; label: string }[] = [
  { value: 'APPROVED', label: 'Approve this mapping' },
  { value: 'REJECTED', label: 'Reject this mapping' },
  { value: 'NEEDS_REVIEW', label: 'Return it to review' },
]

export function ControlMatrix() {
  const runs = useRuns({ limit: 50 })
  const packs = usePolicyPacks()
  const [runSel, setRunSel] = useState<string | null>(null)
  const [packSel, setPackSel] = useState('')
  const finished = (runs.data?.items ?? []).filter((r) => FINISHED.includes(r.state))
  const runId = runSel ?? finished[0]?.run_id ?? ''
  const pack = packSel || packs.data?.[0]?.key || ''
  const q = useControlMatrix(runId ? { run_id: runId } : { policy_version: pack })
  return (
    <>
      <PageHeader title="Control Matrix" lead="Each pack control with its outcome in a run and its proposed mappings to external frameworks. A mapping is a proposal until a policy owner approves it, and approval never changes an outcome." />
      <div className="row">
        <div>
          <label htmlFor="cm-run">Run</label>
          <select id="cm-run" value={runId} onChange={(e) => setRunSel(e.target.value)}>
            <option value="">No run: browse a policy pack</option>
            {(runs.data?.items ?? []).map((r) => <option key={r.run_id} value={r.run_id}>{r.run_id.slice(0, 8)} · {r.project_name} · {r.state}</option>)}
          </select>
        </div>
        {!runId ? (
          <div>
            <label htmlFor="cm-pack">Policy pack</label>
            <select id="cm-pack" value={pack} onChange={(e) => setPackSel(e.target.value)}>
              {(packs.data ?? []).map((p) => <option key={p.key} value={p.key}>{p.key}</option>)}
            </select>
          </div>
        ) : null}
      </div>
      <div style={{ marginTop: '1rem' }}>
        <DataState q={q} label="control matrix" isEmpty={(d) => d.controls.length === 0} empty={<p className="muted">This pack has no controls.</p>}>
          {(d) => <MatrixTable d={d} />}
        </DataState>
      </div>
    </>
  )
}

function MatrixTable({ d }: { d: Matrix }) {
  const [pending, setPending] = useState<{ control: string; m: FrameworkMapping } | null>(null)
  return (
    <>
      <Banner tone="info" title={`Mapping catalog ${d.catalog_version}`}>{d.notice}</Banner>
      <p className="row" data-testid="mapping-summary">
        <Badge d={{ ...MAPPING_DISPLAY.APPROVED, label: `${d.summary.APPROVED} approved` }} />
        <Badge d={{ ...MAPPING_DISPLAY.NEEDS_REVIEW, label: `${d.summary.NEEDS_REVIEW} awaiting review` }} />
        <Badge d={{ ...MAPPING_DISPLAY.REJECTED, label: `${d.summary.REJECTED} rejected` }} />
      </p>
      {d.run_id && !d.final ? <Banner tone="warn" title="Run not finished">Outcomes appear once policy evaluation has completed.</Banner> : null}
      <div className="table-wrap">
        <table>
          <caption>Controls in <code>{d.policy_version}</code>{d.run_id ? <> for run {d.run_id.slice(0, 8)}</> : null}</caption>
          <thead>
            <tr>
              <th scope="col">Control</th>
              {d.run_id ? <th scope="col">Outcome</th> : null}
              {d.frameworks.map((f) => <th scope="col" key={f.framework} title={f.name}>{f.framework} {f.version}</th>)}
            </tr>
          </thead>
          <tbody>
            {d.controls.map((c) => (
              <tr key={c.control_id}>
                <th scope="row"><code>{c.control_id}</code>{c.rules.map((r) => <div key={r.rule_id} className="muted">{r.title}</div>)}</th>
                {d.run_id ? <td>{c.outcome ? <Badge d={display(OUTCOME_DISPLAY as never, c.outcome)} /> : <span className="muted">No result</span>}</td> : null}
                {d.frameworks.map((f) => {
                  const ms = c.mappings.filter((m) => m.framework === f.framework)
                  return (
                    <td key={f.framework}>
                      {ms.length === 0 ? <span className="muted">–</span> : (
                        <ul className="list-plain">
                          {ms.map((m) => {
                            const st = display(MAPPING_DISPLAY, m.status)
                            const label = `${m.control_id}: ${st.label}`
                            return (
                              <li key={m.key} title={m.title}>
                                {d.can_review
                                  ? <button type="button" className={`btn btn--small badge--${st.tone}`} aria-label={`Review mapping of ${c.control_id} to ${f.framework} ${m.control_id} (${st.label})`} onClick={() => setPending({ control: c.control_id, m })}>{st.icon} {m.control_id}</button>
                                  : <span className={`badge badge--${st.tone}`} aria-label={label}>{st.icon} {m.control_id}</span>}
                              </li>
                            )
                          })}
                        </ul>
                      )}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="hint">Hover a mapping for the framework control's title. {d.can_review ? 'Select one to record your decision.' : 'Only a policy owner can approve or reject mappings.'}</p>
      {pending ? <ReviewDialog control={pending.control} m={pending.m} onClose={() => setPending(null)} /> : null}
    </>
  )
}

function ReviewDialog({ control, m, onClose }: { control: string; m: FrameworkMapping; onClose: () => void }) {
  const qc = useQueryClient()
  const [decision, setDecision] = useState<MappingStatus>(m.status === 'APPROVED' ? 'REJECTED' : 'APPROVED')
  const [reason, setReason] = useState('')
  const save = useMutation({
    mutationFn: () => api('/framework-mappings/reviews', { method: 'POST', body: { key: m.key, decision, reason: reason.trim() } }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['control-matrix'] }); void qc.invalidateQueries({ queryKey: ['run'] }); onClose() },
  })
  const err = save.error instanceof ApiError ? save.error : null
  return (
    <ConfirmDialog open title={`Mapping ${control} → ${m.framework} ${m.control_id}`} confirmLabel="Record decision" busy={save.isPending}
      confirmDisabled={!reason.trim() || decision === m.status} onConfirm={() => save.mutate()} onCancel={onClose}>
      <p><strong>{m.control_id}</strong>: {m.title} ({m.framework} {m.version})</p>
      <p>Current state: <Badge d={display(MAPPING_DISPLAY, m.status)} />{m.reviewed_by ? <> by {m.reviewed_by} on {fmtTime(m.reviewed_at)}</> : null}</p>
      {m.reason ? <p className="hint">Last reason: {m.reason}</p> : null}
      <fieldset>
        <legend>Decision</legend>
        {DECISIONS.map((x) => (
          <label key={x.value} className="inline-check"><input type="radio" name="mapping-decision" value={x.value} checked={decision === x.value} disabled={x.value === m.status} onChange={() => setDecision(x.value)} /> {x.label}</label>
        ))}
      </fieldset>
      <label htmlFor="mapping-reason">Reason (recorded in the audit trail)</label>
      <textarea id="mapping-reason" rows={3} maxLength={1000} value={reason} onChange={(e) => setReason(e.target.value)} />
      {err ? <Banner tone="bad" role="alert" title="Not recorded">{err.message}</Banner> : null}
    </ConfirmDialog>
  )
}
