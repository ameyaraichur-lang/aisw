import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAudit, useRuns } from '../api/hooks'
import { Badge, Banner, DataState, PageHeader, Pagination } from '../components/ui'
import { fmtTime } from '../lib/format'
import { RUN_STATE_DISPLAY, display } from '../lib/status'

export function NotImplemented({ title, milestone, why }: { title: string; milestone: string; why: string }) {
  return (
    <>
      <PageHeader title={title} />
      <Banner tone="neutral" title={`Planned for ${milestone}`}>{why} Nothing on this page is simulated.</Banner>
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

export function AuditPage() {
  const [offset, setOffset] = useState(0)
  const [result, setResult] = useState('')
  const q = useAudit({ limit: 25, offset, result: result || undefined })
  const verify = useQuery({ queryKey: ['audit-verify'], queryFn: () => api<{ ok: boolean; checked: number; broken_at_seq: number | null; reason: string | null }>('/audit/verify'), retry: false })
  return (
    <>
      <PageHeader title="Policy, Users & Audit" lead="Tamper-evident audit trail for your tenant." />
      {verify.data ? (verify.data.ok
        ? <Banner tone="ok" title="Audit chain verified">{verify.data.checked} event(s) hash-linked with no gaps or alterations.</Banner>
        : <Banner tone="bad" role="alert" title="Audit chain broken">Broken at event {verify.data.broken_at_seq}: {verify.data.reason}</Banner>) : null}
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
