import { Link } from 'react-router-dom'
import { useOverview, useRuns } from '../api/hooks'
import { Badge, Card, DataState, PageHeader } from '../components/ui'
import { fmtTime } from '../lib/format'
import { RUN_STATE_DISPLAY, display } from '../lib/status'

export function CommandCenter() {
  const ov = useOverview()
  const runs = useRuns({ limit: 8 })
  return (
    <>
      <PageHeader title="Command Center" lead="Every figure shows its denominator and the time it was computed, and links to the records behind it." />
      <DataState q={ov} label="overview">
        {(o) => (
          <>
            <p className="muted" aria-live="polite">Data as of {fmtTime(o.as_of)}</p>
            <div className="grid">
              <Card title="Coverage (assessed vs expected)" to={<Link to="/controls">Open the control matrix</Link>}>
                {o.coverage.runs_considered === 0 ? (
                  <p>No finished assessment yet, so no coverage can be claimed.</p>
                ) : (
                  <>
                    <div className="big">{o.coverage.reconciled} of {o.coverage.expected}</div>
                    <p className="denominator">expected assets reconciled ({o.coverage.basis}; {o.coverage.runs_considered} run(s), {o.coverage.segments_total} segment(s))</p>
                    <ul className="list-plain">
                      <li>Unknown: {o.coverage.unknown}</li>
                      <li>Unsupported: {o.coverage.unsupported}</li>
                      <li>
                        Incomplete segments: {o.coverage.segments_incomplete} of {o.coverage.segments_total}{' '}
                        {o.coverage.segments_incomplete > 0 ? <Badge d={{ icon: '◑', label: 'Coverage incomplete', tone: 'warn' }} /> : <Badge d={{ icon: '✓', label: 'All segments complete', tone: 'ok' }} />}
                      </li>
                    </ul>
                  </>
                )}
              </Card>
              <Card title="Open critical/high findings (authoritative)" to={<Link to="/findings?severity=CRITICAL&severity=HIGH">Open the list</Link>}>
                <div className="big">{o.findings.open_critical_high_authoritative}</div>
                <p className="denominator">critical {o.findings.critical}, high {o.findings.high}; accepted by independent assurance</p>
                {o.findings.pending_review_critical_high > 0 ? (
                  <Badge d={{ icon: '?', label: `${o.findings.pending_review_critical_high} critical/high pending review`, tone: 'warn' }} />
                ) : null}
              </Card>
              <Card title="Exceptions" to={<Link to="/exceptions">Open exceptions</Link>}>
                <div className="big">{o.exceptions.active} in force</div>
                <p className="denominator">{o.exceptions.pending} awaiting approval; {o.exceptions.expired} expired and reported again</p>
                {o.exceptions.expiring_30d > 0 ? <Badge d={{ icon: '⌛', label: `${o.exceptions.expiring_30d} expire within 30 days`, tone: 'warn' }} /> : null}
              </Card>
              <Card title="Active and partial runs" to={<Link to="/assessments">All assessments</Link>}>
                <div className="big">{o.active_runs.length} active</div>
                <p className="denominator">{o.partial_runs.length} partial awaiting review; {o.runs.total} run(s) in total</p>
                <ul className="list-plain">
                  {o.partial_runs.slice(0, 3).map((r) => (
                    <li key={r.run_id}><Link to={`/assessments/${r.run_id}`}>{r.run_id.slice(0, 8)}</Link> <Badge d={display(RUN_STATE_DISPLAY, r.state)} /></li>
                  ))}
                </ul>
              </Card>
              <Card title="Connector health" to={<Link to="/integrations">Integrations</Link>}>
                <ul className="list-plain">
                  {o.connectors.map((c) => (
                    <li key={c.adapter_id}>
                      <strong>{c.adapter_id}</strong>{' '}
                      {c.enabled && c.permission_ok ? <Badge d={{ icon: '✓', label: 'Healthy permissions', tone: 'ok' }} /> : <Badge d={{ icon: '✕', label: c.enabled ? 'Permission check failed' : 'Disabled', tone: 'bad' }} />}
                    </li>
                  ))}
                </ul>
                <p className="hint">Collector heartbeats are not implemented yet; health here means registered, enabled and last permission check.</p>
              </Card>
            </div>
          </>
        )}
      </DataState>
      <h2>Recent assessments</h2>
      <DataState q={runs} label="runs" isEmpty={(d) => d.items.length === 0} empty={<p>No assessments yet. <Link to="/assessments/new">Start the first one</Link>.</p>}>
        {(d) => <RunsTable items={d.items} />}
      </DataState>
    </>
  )
}

export function RunsTable({ items }: { items: import('../api/types').RunListItem[] }) {
  return (
    <div className="table-wrap">
      <table>
        <caption>Assessment runs, newest first</caption>
        <thead><tr><th scope="col">Run</th><th scope="col">Project</th><th scope="col">State</th><th scope="col">Tasks open</th><th scope="col">Policy</th><th scope="col">Started</th></tr></thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.run_id}>
              <td><Link to={`/assessments/${r.run_id}`}>{r.run_id.slice(0, 8)}</Link></td>
              <td>{r.project_name}</td>
              <td>
                <Badge d={display(RUN_STATE_DISPLAY, r.state)} />{' '}
                {r.partial ? <Badge d={{ icon: '◑', label: 'Partial coverage', tone: 'warn' }} /> : null}
              </td>
              <td>{r.tasks_open} of {r.tasks_total}</td>
              <td><code>{r.policy_version}</code></td>
              <td>{fmtTime(r.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
