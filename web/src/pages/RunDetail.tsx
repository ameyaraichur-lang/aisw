import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link, NavLink, Navigate, Route, Routes, useParams } from 'react-router-dom'
import { api, ApiError, apiText } from '../api/client'
import { useControls, useCoverage, useReportBody, useReports, useRunFindings, useRunRecommendations, useRunScenarios, useRunStatus, useTasks } from '../api/hooks'
import type { ControlRow, TaskView } from '../api/types'
import { useSession } from '../auth/useSession'
import { RecommendationBody, RecommendationHeader, ScenarioCard } from '../components/analysis'
import { Badge, Banner, ConfirmDialog, CopyButton, DataState, PageHeader, Pagination, ShortHash } from '../components/ui'
import { fmtTime } from '../lib/format'
import { deriveStages, describeEvent, tasksFinished } from '../lib/events'
import { OUTCOME_DISPLAY, RUN_STATE_DISPLAY, SEVERITY_DISPLAY, TASK_STATUS_DISPLAY, VERDICT_DISPLAY, display, type PolicyOutcome } from '../lib/status'
import { useRunStream } from '../lib/useRunStream'

const STAGE_BADGE = {
  pending: { icon: '…', label: 'Pending', tone: 'neutral' },
  running: { icon: '▶', label: 'Running', tone: 'info' },
  succeeded: { icon: '✓', label: 'Done', tone: 'ok' },
  partial: { icon: '◑', label: 'Partial', tone: 'warn' },
  failed: { icon: '✕', label: 'Failed', tone: 'bad' },
  cancelled: { icon: '⊘', label: 'Cancelled', tone: 'neutral' },
} as const

export function RunPage() {
  const { runId = '' } = useParams()
  return <RunDetail key={runId} runId={runId} />
}

function RunDetail({ runId }: { runId: string }) {
  const status = useRunStatus(runId)
  const stream = useRunStream(runId)
  const { can } = useSession()
  const qc = useQueryClient()
  const [confirmCancel, setConfirmCancel] = useState(false)
  const cancel = useMutation({
    mutationFn: () => api(`/assessments/${runId}/cancel`, { method: 'POST' }),
    onSuccess: () => { setConfirmCancel(false); void qc.invalidateQueries({ queryKey: ['run', runId] }) },
  })
  const s = status.data
  const open = s && !['CLOSED', 'FAILED', 'CANCELLED', 'EXPIRED', 'PARTIAL', 'REPORT_READY'].includes(s.state)
  return (
    <>
      <PageHeader title={`Assessment ${runId.slice(0, 8)}`} lead={s ? <>Policy <code>{s.policy_version}</code>; manifest <ShortHash value={s.manifest_hash} />; started {fmtTime(s.created_at)}</> : null}>
        <CopyButton value={runId} label="run id" />
        {can('assessment:cancel') && open && !s?.cancel_requested ? <button type="button" className="btn btn--danger" onClick={() => setConfirmCancel(true)}>Cancel run</button> : null}
      </PageHeader>
      <StreamBanner stream={stream} />
      <DataState q={status} label="run">
        {(r) => (
          <>
            <p className="row">
              <Badge d={display(RUN_STATE_DISPLAY, r.state)} />
              {r.cancel_requested && r.state !== 'CANCELLED' ? <Badge d={{ icon: '⏳', label: 'Cancellation requested', tone: 'warn' }} /> : null}
              {r.reason ? <span className="muted">reason: <code>{r.reason}</code></span> : null}
              <span className="muted">tasks: {Object.entries(r.tasks).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(', ') || 'none'}</span>
            </p>
            {r.partial || r.state === 'PARTIAL' ? (
              <Banner tone="warn" role="alert" title="Partial assessment">
                Coverage is incomplete or some tasks did not finish. Findings reflect only what was assessed; unknown and unassessed items are listed, never treated as passing.
              </Banner>
            ) : null}
            {r.state === 'FAILED' ? <Banner tone="bad" role="alert" title="Run failed">No report was produced. Reason: {r.reason ?? 'unknown'}. See the timeline for the failing task.</Banner> : null}
            {r.state === 'CANCELLED' ? <Banner tone="neutral" title="Run cancelled">No further tools will run.</Banner> : null}
          </>
        )}
      </DataState>
      <ul className="tabs" aria-label="Assessment sections">
        {['timeline', 'coverage', 'findings', 'analysis', 'controls', 'report'].map((t) => (
          <li key={t}><NavLink to={`/assessments/${runId}/${t}`} className={({ isActive }) => (isActive ? 'active' : '')}>{t[0].toUpperCase() + t.slice(1)}</NavLink></li>
        ))}
      </ul>
      <Routes>
        <Route index element={<Navigate to="timeline" replace />} />
        <Route path="timeline" element={<Timeline runId={runId} stream={stream} />} />
        <Route path="coverage" element={<Coverage runId={runId} />} />
        <Route path="findings" element={<RunFindings runId={runId} />} />
        <Route path="analysis" element={<Analysis runId={runId} />} />
        <Route path="controls" element={<ControlsTable runId={runId} />} />
        <Route path="report" element={<ReportTab runId={runId} />} />
      </Routes>
      <ConfirmDialog open={confirmCancel} title="Cancel this run?" confirmLabel="Cancel run" busy={cancel.isPending} onConfirm={() => cancel.mutate()} onCancel={() => setConfirmCancel(false)}>
        <p>Queued tasks are cancelled. A task already running finishes safely and its evidence is kept.</p>
      </ConfirmDialog>
    </>
  )
}

function StreamBanner({ stream }: { stream: ReturnType<typeof useRunStream> }) {
  if (stream.status === 'reconnecting')
    return <Banner tone="warn" role="alert" title="Live updates interrupted">Showing the last known state{stream.staleSince ? ` (stale since ${fmtTime(new Date(stream.staleSince).toISOString())})` : ''}. Reconnecting and resuming from the last event…</Banner>
  if (stream.status === 'polling')
    return <Banner tone="warn" title="Live stream unavailable">Falling back to periodic refresh. Nothing is lost: the event log is durable.</Banner>
  if (stream.status === 'denied')
    return <Banner tone="warn" role="alert" title="Live updates are not permitted for you">You can still reload to see the current state.</Banner>
  return null
}

function Timeline({ runId, stream }: { runId: string; stream: ReturnType<typeof useRunStream> }) {
  const tasks = useTasks(runId)
  const stages = useMemo(() => deriveStages(stream.events), [stream.events])
  const [sel, setSel] = useState<string | null>(null)
  const latest = stream.events.at(-1)
  const fin = tasks.data ? tasksFinished(tasks.data) : null
  const task = tasks.data?.find((t) => t.task_id === sel)
  return (
    <div className="split split--2">
      <div>
        <p className="live" aria-live="polite" data-testid="stream-status">
          <Badge d={stream.status === 'live' ? { icon: '●', label: 'Live', tone: 'ok' } : stream.status === 'ended' ? { icon: '■', label: 'Stream complete', tone: 'neutral' } : { icon: '…', label: stream.status, tone: 'warn' }} />
          {latest ? <span>Latest: {describeEvent(latest)}</span> : <span className="muted">Waiting for the first event…</span>}
        </p>
        {fin ? <p className="muted">{fin.done} of {fin.total} task(s) finished</p> : null}
        <h2>Stages</h2>
        <ol className="stages" aria-label="Run stages">
          {stages.map((s) => (
            <li key={s.key} className="stage" data-testid={`stage-${s.key}`} data-status={s.status}>
              <strong>{s.label}</strong>
              <span><Badge d={STAGE_BADGE[s.status]} /></span>
              <span>{s.detail || <span className="muted">—</span>}{s.warnings ? ` · ${s.warnings} warning(s)` : ''}{s.errors ? ` · ${s.errors} error(s)` : ''}{s.startedAt ? <span className="muted"> · {fmtTime(s.startedAt)}{s.endedAt ? ` → ${fmtTime(s.endedAt)}` : ''}</span> : null}</span>
            </li>
          ))}
        </ol>
        <h2>Tasks</h2>
        <DataState q={tasks} label="tasks" isEmpty={(d) => d.length === 0} empty={<p className="muted">No tasks.</p>}>
          {(d) => (
            <div className="table-wrap">
              <table>
                <caption>Tasks (select one for its contract details)</caption>
                <thead><tr><th scope="col">Agent</th><th scope="col">Target</th><th scope="col">Status</th><th scope="col">Attempts</th><th scope="col"><span className="sr-only">Details</span></th></tr></thead>
                <tbody>{d.map((t) => (
                  <tr key={t.task_id}>
                    <td><code>{t.agent_id}</code></td><td>{t.target}</td><td><Badge d={display(TASK_STATUS_DISPLAY, t.status)} /></td><td>{t.attempts} of {t.max_attempts}</td>
                    <td><button type="button" className="btn btn--small" aria-expanded={sel === t.task_id} onClick={() => setSel(sel === t.task_id ? null : t.task_id)}>Details</button></td>
                  </tr>))}
                </tbody>
              </table>
            </div>
          )}
        </DataState>
        {task ? <TaskPanel t={task} /> : null}
      </div>
      <div>
        <h2>Event log</h2>
        <ol className="list-plain" aria-label="Event log" data-testid="event-log">
          {stream.events.map((e) => <li key={e.event_id}><span className="muted">#{e.seq} {fmtTime(e.occurred_at)}</span> {describeEvent(e)}</li>)}
        </ol>
        <p className="hint">Shown: concise facts from the persisted log. No model reasoning is displayed or stored.</p>
      </div>
    </div>
  )
}

function TaskPanel({ t }: { t: TaskView }) {
  return (
    <section className="panel" aria-label="Task details">
      <h3>Task {t.task_id.slice(0, 8)}</h3>
      <dl className="kv">
        <dt>Contract</dt><dd>v{t.contract_version}; agent <code>{t.agent_id}</code>; profile <code>{t.profile}</code></dd>
        <dt>Target</dt><dd>{t.target_kind}: {t.target}</dd>
        <dt>Times</dt><dd>{fmtTime(t.started_at)} → {fmtTime(t.completed_at)}</dd>
        <dt>Tool version</dt><dd>{t.tool_version ?? '—'}</dd>
        <dt>Warnings</dt><dd>{t.warnings.length ? <ul>{t.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul> : 'none'}</dd>
        <dt>Errors</dt><dd>{t.errors.length ? <ul>{t.errors.map((w, i) => <li key={i}><code>{w}</code></li>)}</ul> : 'none'}</dd>
        <dt>Output evidence</dt><dd>{t.output_refs.length ? t.output_refs.map((r) => <div key={r}><code>{r}</code></div>) : 'none'}</dd>
      </dl>
    </section>
  )
}

function Coverage({ runId }: { runId: string }) {
  const q = useCoverage(runId)
  return (
    <DataState q={q} label="coverage" isEmpty={(d) => d.segments.length === 0} empty={<Banner tone="neutral" title="No coverage yet">Coverage totals appear after policy evaluation; incomplete totals are never shown as final.</Banner>}>
      {(d) => (
        <>
          {!d.final ? <Banner tone="info" title="Not final">The run is still in progress; these totals may change.</Banner> : null}
          <p>{d.complete ? <Badge d={{ icon: '✓', label: 'Coverage complete', tone: 'ok' }} /> : <Badge d={{ icon: '◑', label: 'Coverage incomplete', tone: 'warn' }} />}</p>
          <div className="table-wrap">
            <table>
              <caption>Coverage per scope segment (denominator = expected assets from inventory)</caption>
              <thead><tr><th scope="col">Segment</th><th scope="col">Expected</th><th scope="col">Discovered</th><th scope="col">Reconciled</th><th scope="col">Unknown</th><th scope="col">Unsupported</th><th scope="col">Per-asset outcome</th></tr></thead>
              <tbody>
                {d.segments.map((c) => (
                  <tr key={c.segment}>
                    <td><code>{c.segment}</code></td><td>{c.expected_count}</td><td>{c.discovered_count}</td><td>{c.reconciled_count} of {c.expected_count}</td><td>{c.unknown_count}</td><td>{c.unsupported_count}</td>
                    <td><ul className="list-plain">{Object.entries(c.assessed_by_outcome as Record<string, number>).map(([k, v]) => <li key={k}><Badge d={display(OUTCOME_DISPLAY as never, k)} /> × {v}</li>)}</ul></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {d.segments.map((c) => c.reasons && c.reasons.length ? (
            <section key={c.segment} className="panel" aria-label={`Gaps in ${c.segment}`}>
              <h3>Named gaps in <code>{c.segment}</code></h3>
              <ul>{c.reasons.map((r) => <li key={r}><code>{r}</code></li>)}</ul>
            </section>
          ) : null)}
        </>
      )}
    </DataState>
  )
}

function RunFindings({ runId }: { runId: string }) {
  const [verdict, setVerdict] = useState<'ACCEPT' | 'NEEDS_REVIEW'>('ACCEPT')
  const [severity, setSeverity] = useState('')
  const [offset, setOffset] = useState(0)
  const q = useRunFindings(runId, { verdict: [verdict], severity: severity || undefined, limit: 20, offset })
  return (
    <>
      <div className="row">
        <div><label htmlFor="fv">Show</label>
          <select id="fv" value={verdict} onChange={(e) => { setVerdict(e.target.value as 'ACCEPT'); setOffset(0) }}>
            <option value="ACCEPT">Authoritative findings</option><option value="NEEDS_REVIEW">Pending review (not authoritative)</option>
          </select></div>
        <div><label htmlFor="fs">Severity</label>
          <select id="fs" value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0) }}>
            <option value="">All</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => <option key={s}>{s}</option>)}
          </select></div>
      </div>
      <DataState q={q} label="findings" isEmpty={(d) => d.items.length === 0} empty={<p className="muted">No findings match. An empty list is not proof of security: check the coverage tab.</p>}>
        {(d) => (
          <>
            <div className="table-wrap">
              <table>
                <caption>Findings ({d.total}); every row links to its evidence</caption>
                <thead><tr><th scope="col">Severity</th><th scope="col">Title</th><th scope="col">Assets</th><th scope="col">Outcome</th><th scope="col">Assurance</th></tr></thead>
                <tbody>{d.items.map((f) => (
                  <tr key={f.finding_id}>
                    <td><Badge d={display(SEVERITY_DISPLAY, f.severity)} /></td>
                    <td><Link to={`/findings/${runId}/${f.finding_id}`}>{f.title}</Link></td>
                    <td>{f.affected_assets.join(', ')}</td>
                    <td><Badge d={display(OUTCOME_DISPLAY as never, f.outcome)} /></td>
                    <td><Badge d={display(VERDICT_DISPLAY, f.assurance_verdict)} /></td>
                  </tr>))}
                </tbody>
              </table>
            </div>
            <Pagination total={d.total} limit={20} offset={offset} onChange={setOffset} />
          </>
        )}
      </DataState>
    </>
  )
}

function Analysis({ runId }: { runId: string }) {
  const sc = useRunScenarios(runId)
  const rc = useRunRecommendations(runId)
  return (
    <>
      <section aria-labelledby="sc-h">
        <h2 id="sc-h">Correlated scenarios</h2>
        <DataState q={sc} label="scenarios" isEmpty={(d) => d.length === 0} empty={<p className="muted">No scenario was built: it takes two or more recorded weaknesses on the same asset. Nothing is inferred beyond what was observed.</p>}>
          {(d) => <>{d.map((x) => <ScenarioCard key={x.scenario_id} s={x} />)}</>}
        </DataState>
      </section>
      <section aria-labelledby="rc-h">
        <h2 id="rc-h">Draft recommendations</h2>
        <p className="hint">For planning only. Decisions are recorded in <Link to={`/architecture?run=${runId}`}>Architecture &amp; Modernization</Link>; nothing is executed.</p>
        <DataState q={rc} label="recommendations" isEmpty={(d) => d.length === 0} empty={<p className="muted">No recommendation matched an approved target pattern for this run.</p>}>
          {(d) => (
            <ul className="list-plain">
              {d.map((r) => (
                <li key={r.recommendation_id}>
                  <section className="panel" aria-labelledby={`r-${r.recommendation_id}`}>
                    <h3 id={`r-${r.recommendation_id}`}>{r.title}</h3>
                    <RecommendationHeader r={r} />
                    <details><summary>Details, validation and rollback</summary><RecommendationBody r={r} /></details>
                  </section>
                </li>
              ))}
            </ul>
          )}
        </DataState>
      </section>
    </>
  )
}

export function ControlsTable({ runId }: { runId: string }) {
  const q = useControls(runId)
  return (
    <DataState q={q} label="controls" isEmpty={(d) => d.length === 0} empty={<p className="muted">Control results appear after policy evaluation.</p>}>
      {(d: ControlRow[]) => (
        <div className="table-wrap">
          <table>
            <caption>Control outcomes (worst outcome wins; PASS only if everything applicable passed with evidence)</caption>
            <thead><tr><th scope="col">Control</th><th scope="col">Framework</th><th scope="col">Applicability</th><th scope="col">Outcome</th><th scope="col">Evidence</th></tr></thead>
            <tbody>{d.map((c) => (
              <tr key={c.control_id}>
                <td><code>{c.control_id}</code></td><td>{c.framework} {c.version}</td><td>{c.applicability}</td>
                <td><Badge d={display(OUTCOME_DISPLAY as Record<PolicyOutcome, never>, c.outcome)} /></td>
                <td>{c.evidence_refs.length} reference(s)</td>
              </tr>))}
            </tbody>
          </table>
        </div>
      )}
    </DataState>
  )
}

function ReportTab({ runId }: { runId: string }) {
  const reports = useReports(runId)
  const { can } = useSession()
  const first = reports.data?.[0]
  const body = useReportBody(first?.report_id)
  const qc = useQueryClient()
  const [html, setHtml] = useState<string | null>(null)
  const [confirm, setConfirm] = useState(false)
  const approve = useMutation({
    mutationFn: () => api(`/reports/${first!.report_id}/approve`, { method: 'POST', body: { report_hash: first!.report_hash } }),
    onSuccess: () => { setConfirm(false); void qc.invalidateQueries({ queryKey: ['run', runId] }) },
  })
  const load = async () => setHtml(await apiText(`/reports/${first!.report_id}?format=html`))
  const download = async (fmt: 'json' | 'html') => {
    const text = await apiText(`/reports/${first!.report_id}?format=${fmt}&download=1`, fmt === 'json' ? 'application/json' : 'text/html')
    const url = URL.createObjectURL(new Blob([text], { type: fmt === 'json' ? 'application/json' : 'text/html' }))
    const a = document.createElement('a'); a.href = url; a.download = `${first!.report_id}.${fmt}`; a.click(); URL.revokeObjectURL(url)
  }
  if (reports.isError)
    return reports.error instanceof ApiError && reports.error.status === 403 ? <Banner tone="warn" role="alert" title="Access denied">Reports require the report-reader or reviewer role.</Banner> : <Banner tone="bad" role="alert" title="Could not load reports">{String(reports.error)}</Banner>
  if (reports.isPending) return <p role="status" className="muted">Loading report…</p>
  if (!first) return <Banner tone="neutral" title="No report yet">A report is generated after policy evaluation and independent assurance.</Banner>
  const err = approve.error instanceof ApiError ? approve.error : null
  return (
    <>
      <p className="row">
        {first.approval_state === 'APPROVED' ? <Badge d={{ icon: '✓', label: 'Approved', tone: 'ok' }} /> : <Badge d={{ icon: '◐', label: 'Awaiting review', tone: 'warn' }} />}
        <span>Report hash <ShortHash value={first.report_hash} /> generated {fmtTime(first.generated_at)}</span>
      </p>
      <DataState q={body} label="report">
        {(b) => (
          <>
            {b.banner ? <Banner tone="warn" role="alert" title={b.banner} /> : null}
            <p className="muted">{b.disclaimer}</p>
            <dl className="kv">
              <dt>Findings (authoritative)</dt><dd data-testid="report-total">{b.finding_counts.total} {Object.entries(b.finding_counts).filter(([k]) => k !== 'total').map(([k, v]) => `${k.toLowerCase()} ${v}`).join(', ')}</dd>
              <dt>Assurance</dt><dd>{b.assurance.accepted} accepted, {b.assurance.needs_review} pending review, {b.assurance.rejected} rejected (excluded)</dd>
              <dt>Coverage</dt><dd>{b.coverage_complete ? 'complete' : 'INCOMPLETE'}</dd>
              <dt>Policy / scope</dt><dd><code>{b.policy_versions.join(', ')}</code>; scope hash <ShortHash value={b.scope_manifest_hash} /></dd>
            </dl>
            <h3>Limitations</h3>
            {b.limitations.length ? <ul>{b.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul> : <p className="muted">None recorded.</p>}
            {b.pending_review.length ? (<><h3>Pending review (not authoritative)</h3><ul>{b.pending_review.map((p) => <li key={p.finding_id}><Badge d={display(SEVERITY_DISPLAY, p.severity)} /> {p.title}</li>)}</ul></>) : null}
          </>
        )}
      </DataState>
      <div className="row" style={{ margin: '1rem 0' }}>
        <button type="button" className="btn" onClick={() => void load()}>Preview HTML report</button>
        <button type="button" className="btn" onClick={() => void download('json')}>Download JSON</button>
        <button type="button" className="btn" onClick={() => void download('html')}>Download HTML</button>
        {can('report:approve') && first.approval_state === 'PENDING' ? <button type="button" className="btn btn--primary" onClick={() => setConfirm(true)}>Approve report</button> : null}
      </div>
      {err ? <Banner tone="bad" role="alert" title={err.status === 403 ? 'You cannot approve this report' : 'Approval refused'}>{err.message}</Banner> : null}
      {html ? <iframe className="report" title="Report preview" sandbox="" srcDoc={html} /> : null}
      <ConfirmDialog open={confirm} title="Approve this report?" confirmLabel="Approve" busy={approve.isPending} onConfirm={() => approve.mutate()} onCancel={() => setConfirm(false)}>
        <p>Approval is bound to report hash <ShortHash value={first.report_hash} />. It does not certify the assessed estate.</p>
      </ConfirmDialog>
    </>
  )
}
