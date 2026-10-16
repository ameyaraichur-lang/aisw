import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useCoverageLedger } from '../api/hooks'
import type { LedgerProject } from '../api/types'
import { Badge, Banner, DataState, PageHeader } from '../components/ui'
import { fmtTime } from '../lib/format'

const COMPLETE = { icon: '✓', label: 'Complete', tone: 'ok' } as const
const INCOMPLETE = { icon: '!', label: 'Incomplete', tone: 'warn' } as const

function ProjectLedger({ p }: { p: LedgerProject }) {
  return (
    <section className="panel" aria-labelledby={`cov-${p.project_id}`}>
      <h2 id={`cov-${p.project_id}`}>{p.name} <span className="muted">({p.environment})</span> <Badge d={p.complete ? COMPLETE : INCOMPLETE} /></h2>
      <p className="hint">Latest finished run <Link to={`/assessments/${p.run.run_id}/coverage`}><code>{p.run.run_id.slice(0, 8)}</code></Link>, {fmtTime(p.run.created_at)}{p.run.partial ? ' (partial)' : ''}.</p>
      <table data-testid={`ledger-${p.name}`}>
        <caption>Counts per scope segment; completeness is derived, never asserted</caption>
        <thead><tr><th scope="col">Segment</th><th scope="col">Expected</th><th scope="col">Discovered</th><th scope="col">Reconciled</th><th scope="col">Unsupported</th><th scope="col">Unknown</th><th scope="col">Last success</th><th scope="col">Status</th></tr></thead>
        <tbody>{p.segments.map((s) => (
          <tr key={s.segment}>
            <th scope="row"><code>{s.segment}</code></th>
            <td>{s.expected}</td><td>{s.discovered}</td><td>{s.reconciled}</td><td>{s.unsupported}</td><td>{s.unknown}</td>
            <td>{s.last_success_at ? `${fmtTime(s.last_success_at)}${s.age_days ? ` (${s.age_days} days ago)` : ''}` : <span className="muted">never</span>}</td>
            <td><Badge d={s.complete ? COMPLETE : INCOMPLETE} />{s.source_ok ? null : <span className="hint"> source failed</span>}</td>
          </tr>
        ))}</tbody>
      </table>
      {p.segments.length === 0 ? <p className="muted">The run recorded no coverage segments.</p> : null}
      {p.segments.flatMap((s) => s.gaps).length ? (
        <>
          <h3>Gaps</h3>
          <ul className="list-plain" aria-label={`Coverage gaps for ${p.name}`}>
            {p.segments.flatMap((s) => s.gaps.map((g) => (
              <li key={s.segment + g.kind}>
                <strong>{g.label}</strong> ({g.count}){g.items.length ? ': ' : ''}
                {g.items.map((i, n) => <span key={`${i.asset_id}${n}`}>{n ? ', ' : ''}<code>{i.asset_id}</code>{i.detail ? ` (${i.detail})` : ''}</span>)}
              </li>
            )))}
          </ul>
        </>
      ) : null}
      {p.untargeted_inventory.length ? (
        <p role="note">Registered inventory the latest run did not target: {p.untargeted_inventory.map((i) => <code key={i.kind + i.selector}>{i.kind} {i.selector} </code>)}</p>
      ) : null}
    </section>
  )
}

export function CoverageLedgerPage() {
  const [incompleteOnly, setIncompleteOnly] = useState(false)
  const q = useCoverageLedger(incompleteOnly)
  return (
    <>
      <PageHeader title="Coverage Ledger" lead="What was and was not assessed, per project, from each project's latest finished run. Missing, unreachable and unsupported assets are gaps, never clean." />
      <label className="inline-check"><input type="checkbox" checked={incompleteOnly} onChange={(e) => setIncompleteOnly(e.target.checked)} /> Only show incomplete projects</label>
      <DataState q={q} label="coverage ledger">
        {(d) => (
          <>
            <p role="status" data-testid="coverage-summary">{d.summary.projects} projects: {d.summary.complete} complete, {d.summary.incomplete} incomplete, {d.summary.never_assessed} never assessed. As of {fmtTime(d.as_of)}.</p>
            {d.never_assessed.length ? (
              <Banner tone="warn" title="Never assessed">
                <ul className="list-plain">{d.never_assessed.map((p) => <li key={p.project_id}>{p.name} ({p.environment}): {p.inventory_entries} inventory entr{p.inventory_entries === 1 ? 'y' : 'ies'}, no finished run</li>)}</ul>
              </Banner>
            ) : null}
            {d.projects.length ? d.projects.map((p) => <ProjectLedger key={p.project_id} p={p} />) : <p className="muted">{incompleteOnly ? 'No incomplete projects.' : 'No finished runs yet.'}</p>}
          </>
        )}
      </DataState>
    </>
  )
}
