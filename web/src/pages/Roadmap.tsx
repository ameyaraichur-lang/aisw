import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useRoadmap, useRuns } from '../api/hooks'
import type { RoadmapCard } from '../api/types'
import { TierBadge } from '../components/analysis'
import { Badge, Banner, DataState, PageHeader } from '../components/ui'
import { RECOMMENDATION_STATUS_DISPLAY, display } from '../lib/status'

const FINISHED = ['REPORT_READY', 'PARTIAL', 'CLOSED']

function Card({ c, titles, runId }: { c: RoadmapCard; titles: Record<string, string>; runId: string }) {
  return (
    <li className="lane-card" aria-label={c.title ?? c.recommendation_id}>
      <h4>{c.title ?? c.recommendation_id}</h4>
      <p className="row"><Badge d={display(RECOMMENDATION_STATUS_DISPLAY, c.status)} /><TierBadge tier={c.risk_tier} /></p>
      <dl className="kv">
        <dt>Current</dt><dd>{c.current_state}</dd>
        <dt>Target</dt><dd>{c.target_pattern}</dd>
        <dt>Effort</dt><dd>{c.effort.value ? `${c.effort.value} (estimate)` : 'Unknown: the owner must estimate it'}</dd>
        <dt>Assets</dt><dd>{c.affected_assets.length}</dd>
        {c.depends_on.length ? <><dt>After</dt><dd>{c.depends_on.map((d) => titles[d] ?? d).join(', ')}</dd></> : null}
      </dl>
      <p className="hint">{c.reason}</p>
      <Link to={`/architecture?run=${runId}`}>Decide in Architecture &amp; Modernization</Link>
    </li>
  )
}

function Lane({ title, items, titles, runId, empty }: { title: string; items: RoadmapCard[]; titles: Record<string, string>; runId: string; empty: string }) {
  const id = `lane-${title.replace(/\W+/g, '-').toLowerCase()}`
  return (
    <section className="lane" aria-labelledby={id}>
      <h3 id={id}>{title} <span className="muted">({items.length})</span></h3>
      {items.length ? <ul>{items.map((c) => <Card key={c.recommendation_id} c={c} titles={titles} runId={runId} />)}</ul> : <p className="muted">{empty}</p>}
    </section>
  )
}

export function Roadmap() {
  const runs = useRuns({ limit: 50 })
  const [sel, setSel] = useState<string | null>(null)
  const finished = (runs.data?.items ?? []).filter((r) => FINISHED.includes(r.state))
  const runId = sel ?? finished[0]?.run_id ?? ''
  const q = useRoadmap(runId)
  return (
    <>
      <PageHeader title="Modernization Roadmap" lead="Remediation waves over accepted recommendations. A wave follows the rubric tier only; work without a tier waits for owner input instead of being given a guessed priority." />
      <div className="row">
        <div>
          <label htmlFor="rm-run">Run</label>
          <select id="rm-run" value={runId} onChange={(e) => setSel(e.target.value)}>
            {finished.length ? null : <option value="">No finished run</option>}
            {finished.map((r) => <option key={r.run_id} value={r.run_id}>{r.run_id.slice(0, 8)} · {r.project_name} · {r.state}</option>)}
          </select>
        </div>
      </div>
      {!runId ? <p className="muted">A roadmap appears once an assessment has finished.</p> : (
        <DataState q={q} label="roadmap">
          {(d) => {
            const all = [...d.waves.flatMap((w) => w.items), ...d.unrated, ...d.awaiting_validation, ...d.rejected]
            const titles = Object.fromEntries(all.map((c) => [c.recommendation_id, c.title ?? c.recommendation_id]))
            return (
              <>
                {d.catalog_signoff !== 'APPROVED' ? <Banner tone="info" title="Sample patterns">Target states come from a sample catalog awaiting policy-owner approval.</Banner> : null}
                {d.not_authoritative ? <p className="hint">{d.not_authoritative} recommendation(s) are not yet accepted by independent assurance and are not placed.</p> : null}
                <details>
                  <summary>How waves are assigned</summary>
                  <ul>{d.rules.map((r) => <li key={r}>{r}</li>)}</ul>
                </details>
                <h2>Remediation waves</h2>
                <div className="lanes" data-testid="roadmap-waves">
                  {d.waves.map((w) => <Lane key={w.wave} title={w.label} items={w.items} titles={titles} runId={d.run_id} empty="Nothing in this wave." />)}
                </div>
                <h2>Not scheduled</h2>
                <div className="lanes">
                  <Lane title="Needs owner input" items={d.unrated} titles={titles} runId={d.run_id} empty="Every recommendation has a tier." />
                  <Lane title="Implemented, awaiting validation" items={d.awaiting_validation} titles={titles} runId={d.run_id} empty="None." />
                  <Lane title="Rejected" items={d.rejected} titles={titles} runId={d.run_id} empty="None." />
                </div>
                <h2>Dependencies</h2>
                {d.edges.length ? (
                  <div className="table-wrap">
                    <table><caption>Work that must wait for another recommendation, and the evidence for it</caption>
                      <thead><tr><th scope="col">First</th><th scope="col">Then</th><th scope="col">Why</th></tr></thead>
                      <tbody>{d.edges.map((e) => <tr key={e.from + e.to}><td>{titles[e.from]}</td><td>{titles[e.to]}</td><td>Owner unknown for {e.assets.join(', ')}</td></tr>)}</tbody>
                    </table>
                  </div>
                ) : <p className="muted">No dependency is supported by the evidence. Prerequisites listed on each recommendation are owner checks, not ordering.</p>}
              </>
            )
          }}
        </DataState>
      )}
    </>
  )
}
