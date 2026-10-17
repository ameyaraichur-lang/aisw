import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { AnchorState, AuditVerify } from '../api/types'
import { useAudit, useRuns } from '../api/hooks'
import { Badge, Banner, DataState, PageHeader, Pagination } from '../components/ui'
import { fmtTime } from '../lib/format'
import { ANCHOR_PROBLEM_TEXT, RUN_STATE_DISPLAY, display } from '../lib/status'

export function NotImplemented({ title, milestone, why }: { title: string; milestone: string; why: string }) {
  return (
    <>
      <PageHeader title={title} />
      <Banner tone="neutral" title={milestone === 'planned' ? 'Planned, not built yet' : `Planned for ${milestone}`}>{why} Nothing on this page is simulated.</Banner>
    </>
  )
}

export function ReportsPage() {
  const runs = useRuns({ limit: 50 })
  return (
    <>
      <PageHeader title="Reports & Evidence" lead="Runs that produced a report. Open a run's Report tab to review, download or approve." />
      <DataState q={runs} label="runs" isEmpty={(d) => !d.items.some((r) => ['REPORT_READY', 'PARTIAL', 'CLOSED'].includes(r.state))} empty={<p className="muted">No report has been generated yet.</p>}>
        {(d) => (
          <table><caption>Runs with reports</caption>
            <thead><tr><th scope="col">Run</th><th scope="col">Project</th><th scope="col">State</th><th scope="col">Generated</th></tr></thead>
            <tbody>{d.items.filter((r) => ['REPORT_READY', 'PARTIAL', 'CLOSED'].includes(r.state)).map((r) => (
              <tr key={r.run_id}><td><Link to={`/assessments/${r.run_id}/report`}>{r.run_id.slice(0, 8)}</Link></td><td>{r.project_name}</td>
                <td><Badge d={display(RUN_STATE_DISPLAY, r.state)} /> {r.partial ? <Badge d={{ icon: '◑', label: 'Partial', tone: 'warn' }} /> : null}</td><td>{fmtTime(r.created_at)}</td></tr>))}</tbody>
          </table>
        )}
      </DataState>
    </>
  )
}

function AnchorBanner({ a }: { a: AnchorState }) {
  if (!a.witness_configured) {
    return <Banner tone="warn" title="Audit chain not anchored">No external witness is configured, so the chain can be checked only against itself. Someone with database access could rewrite it consistently.</Banner>
  }
  if (a.checked === 0) {
    return <Banner tone="warn" title="No anchors yet">A witness is configured but the anchor job has not run for this tenant.</Banner>
  }
  if (!a.ok) {
    return <Banner tone="bad" role="alert" title="Audit anchor check failed">{a.problems.map((p) => ANCHOR_PROBLEM_TEXT[p.split(':')[0]] ?? p).join(' ')}</Banner>
  }
  return <Banner tone="ok" title="Audit chain anchored">{a.checked} signed anchor(s) confirmed by witness <code>{a.witness_id}</code>; latest covers event {a.latest_seq} ({a.latest_at ? fmtTime(a.latest_at) : 'unknown time'}).</Banner>
}

export function AuditPage() {
  const [offset, setOffset] = useState(0)
  const [result, setResult] = useState('')
  const q = useAudit({ limit: 25, offset, result: result || undefined })
  const verify = useQuery({ queryKey: ['audit-verify'], queryFn: () => api<AuditVerify>('/audit/verify'), retry: false })
  return (
    <>
      <PageHeader title="Policy, Users & Audit" lead="Tamper-evident audit trail for your tenant." />
      <p className="hint">Model usage has its own ledger: <Link to="/audit/model-calls">Model-call ledger</Link>.</p>
      {verify.data ? (verify.data.ok
        ? <Banner tone="ok" title="Audit chain verified">{verify.data.checked} event(s) hash-linked with no gaps or alterations.</Banner>
        : <Banner tone="bad" role="alert" title="Audit chain broken">Broken at event {verify.data.broken_at_seq}: {verify.data.reason}</Banner>) : null}
      {verify.data ? <AnchorBanner a={verify.data.anchors} /> : null}
      <div><label htmlFor="ar">Result</label>
        <select id="ar" value={result} onChange={(e) => { setResult(e.target.value); setOffset(0) }}>
          <option value="">All</option><option>SUCCESS</option><option>DENIED</option><option>FAILURE</option>
        </select></div>
      <DataState q={q} label="audit events" isEmpty={(d) => d.items.length === 0} empty={<p className="muted">No audit events.</p>}>
        {(d) => (
          <>
            <div className="table-wrap"><table><caption>Audit events, newest first</caption>
              <thead><tr><th scope="col">#</th><th scope="col">Time</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Resource</th><th scope="col">Result</th></tr></thead>
              <tbody>{d.items.map((e) => <tr key={e.seq}><td>{e.seq}</td><td>{fmtTime(e.occurred_at)}</td><td>{e.actor}</td><td><code>{e.action}</code></td><td><code>{e.resource}</code></td>
                <td>{e.result === 'SUCCESS' ? <Badge d={{ icon: '✓', label: 'Success', tone: 'ok' }} /> : <Badge d={{ icon: '✕', label: e.result === 'DENIED' ? 'Denied' : 'Failure', tone: 'bad' }} />}</td></tr>)}</tbody></table></div>
            <Pagination total={d.total} limit={25} offset={offset} onChange={setOffset} />
          </>
        )}
      </DataState>
    </>
  )
}
