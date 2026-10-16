import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useAsset, useAssets, useProjects } from '../api/hooks'
import { Badge, Banner, DataState, PageHeader, Pagination } from '../components/ui'
import { useSession } from '../auth/useSession'
import { fmtTime } from '../lib/format'
import { LIFECYCLE_LABEL, OUTCOME_DISPLAY, SEVERITY_DISPLAY, display } from '../lib/status'
import type { Display } from '../lib/status'

const CONFIDENCE: Record<string, Display> = {
  HIGH: { icon: '✓', label: 'High match confidence', tone: 'ok' },
  MEDIUM: { icon: '◑', label: 'Medium match confidence', tone: 'warn' },
  LOW: { icon: '?', label: 'Low match confidence', tone: 'warn' },
}

function Sourced({ value, source }: { value: string | null; source: string | null }) {
  return value ? <>{value} <span className="muted">(source: {source ?? 'unrecorded'})</span></> : <span className="muted">Unknown</span>
}

export function Assets() {
  const [sp, setSp] = useSearchParams()
  const [offset, setOffset] = useState(0)
  const projects = useProjects()
  const f = { project_id: sp.get('project') ?? '', asset_type: sp.get('type') ?? '', q: sp.get('q') ?? '', confidence: sp.get('confidence') ?? '', owner: sp.get('owner') ?? '' }
  const q = useAssets({ ...f, limit: 25, offset })
  const set = (k: string, v: string) => { const p = new URLSearchParams(sp); if (v) p.set(k, v); else p.delete(k); setOffset(0); setSp(p) }
  return (
    <>
      <PageHeader title="Asset Explorer" lead="Assets reconciled from inventory and collected evidence. Owner and criticality show their source, or Unknown; nothing is inferred." />
      <fieldset>
        <legend>Filters</legend>
        <div className="row">
          <div>
            <label htmlFor="as-project">Project</label>
            <select id="as-project" value={f.project_id} onChange={(e) => set('project', e.target.value)}>
              <option value="">All projects</option>
              {(projects.data ?? []).map((p) => <option key={p.project_id} value={p.project_id}>{p.name}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="as-q">Search asset id or native id</label>
            <input id="as-q" type="search" defaultValue={f.q} onKeyDown={(e) => { if (e.key === 'Enter') set('q', e.currentTarget.value.trim()) }} onBlur={(e) => set('q', e.target.value.trim())} />
          </div>
          <div>
            <label htmlFor="as-conf">Match confidence</label>
            <select id="as-conf" value={f.confidence} onChange={(e) => set('confidence', e.target.value)}>
              <option value="">Any</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option>
            </select>
          </div>
          <div>
            <label htmlFor="as-owner">Owner</label>
            <select id="as-owner" value={f.owner} onChange={(e) => set('owner', e.target.value)}>
              <option value="">Any</option><option value="known">Known</option><option value="unknown">Unknown</option>
            </select>
          </div>
        </div>
      </fieldset>
      <DataState q={q} label="assets" isEmpty={(d) => d.items.length === 0 && d.types.length === 0} empty={<p className="muted">No assets match. Assets appear after an assessment reconciles inventory with collected evidence.</p>}>
        {(d) => (
          <>
            <div className="table-wrap">
              <table data-testid="asset-types">
                <caption>Asset types (counts ignore the type filter)</caption>
                <thead><tr><th scope="col">Type</th><th scope="col">Assets</th><th scope="col">Owner unknown</th><th scope="col">Low match confidence</th></tr></thead>
                <tbody>{d.types.map((t) => (
                  <tr key={t.asset_type}>
                    <td><button type="button" className="btn btn--small" aria-pressed={f.asset_type === t.asset_type} onClick={() => set('type', f.asset_type === t.asset_type ? '' : t.asset_type)}>{t.asset_type}</button></td>
                    <td>{t.count}</td><td>{t.owner_unknown}</td><td>{t.low_confidence}</td>
                  </tr>))}
                </tbody>
              </table>
            </div>
            <div className="table-wrap">
              <table data-testid="asset-list">
                <caption>Assets: {d.total}{f.asset_type ? ` of type ${f.asset_type}` : ''}</caption>
                <thead><tr><th scope="col">Asset</th><th scope="col">Type</th><th scope="col">Project</th><th scope="col">Owner</th><th scope="col">Criticality</th><th scope="col">Match</th><th scope="col">Last seen</th></tr></thead>
                <tbody>{d.items.map((a) => (
                  <tr key={a.project_id + a.asset_id}>
                    <td><Link to={`/assets/${a.project_id}/${encodeURIComponent(a.asset_id)}`}>{a.asset_id}</Link></td>
                    <td>{a.asset_type}</td><td>{a.project_name}</td>
                    <td><Sourced value={a.owner} source={a.owner_source} /></td>
                    <td><Sourced value={a.criticality} source={a.criticality_source} /></td>
                    <td><Badge d={display(CONFIDENCE, a.match_confidence)} /></td>
                    <td>{fmtTime(a.last_seen)}</td>
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

export function AssetDetailPage() {
  const { projectId = '', assetId = '' } = useParams()
  const q = useAsset(projectId, assetId)
  const { me } = useSession()
  return (
    <DataState q={q} label="asset">
      {(a) => (
        <>
          <PageHeader title={a.asset_id} lead={<>{a.asset_type} in {a.project_name}. <Link to={`/assets?project=${a.project_id}`}>All assets in this project</Link></>} />
          <div className="split split--2">
            <div>
              <section className="panel" aria-labelledby="as-id">
                <h2 id="as-id">Identity and ownership</h2>
                <dl className="kv">
                  <dt>Owner</dt><dd><Sourced value={a.owner} source={a.owner_source} /></dd>
                  <dt>Criticality</dt><dd><Sourced value={a.criticality} source={a.criticality_source} /></dd>
                  <dt>Environment</dt><dd>{a.environment ?? <span className="muted">Unknown</span>}</dd>
                  <dt>Technology</dt><dd>{a.technology ?? <span className="muted">Unknown</span>}</dd>
                  <dt>Match confidence</dt><dd><Badge d={display(CONFIDENCE, a.match_confidence)} /></dd>
                  <dt>Native identifiers</dt><dd><code>{JSON.stringify(a.native_ids)}</code></dd>
                  <dt>First / last seen</dt><dd>{fmtTime(a.first_seen)} / {fmtTime(a.last_seen)}</dd>
                </dl>
              </section>
              <section className="panel" aria-labelledby="as-rel">
                <h2 id="as-rel">Relationships</h2>
                <p className="muted">Relationships are not modelled yet. No dependency or reachability edge is shown, because none is ever invented.</p>
              </section>
              <section className="panel" aria-labelledby="as-runs">
                <h2 id="as-runs">Assessment history</h2>
                {a.runs.length ? (
                  <table><caption>Most recent runs that covered this asset</caption>
                    <thead><tr><th scope="col">Run</th><th scope="col">Segment</th><th scope="col">Status</th><th scope="col">When</th></tr></thead>
                    <tbody>{a.runs.map((r) => (
                      <tr key={r.run_id + r.segment}><td><Link to={`/assessments/${r.run_id}`}>{r.run_id.slice(0, 8)}</Link></td><td>{r.segment}</td>
                        <td>{r.status}{r.reason ? <span className="muted"> ({r.reason})</span> : null}</td><td>{fmtTime(r.at)}</td></tr>))}</tbody>
                  </table>
                ) : <p className="muted">No run has covered this asset.</p>}
              </section>
            </div>
            <div>
              <section className="panel" aria-labelledby="as-posture">
                <h2 id="as-posture">Latest posture per rule</h2>
                {a.posture.length ? (
                  <table data-testid="asset-posture"><caption>Each rule's most recent observation and the run that produced it</caption>
                    <thead><tr><th scope="col">Rule</th><th scope="col">Outcome</th><th scope="col">Observed</th><th scope="col">Run</th></tr></thead>
                    <tbody>{a.posture.map((p) => (
                      <tr key={p.rule_id}><td><code>{p.rule_id}</code></td><td><Badge d={display(OUTCOME_DISPLAY as Record<string, Display>, p.outcome)} /></td>
                        <td><code>{JSON.stringify(p.observed)}</code></td>
                        <td><Link to={`/assessments/${p.run_id}`}>{p.run_id.slice(0, 8)}</Link> <span className="muted">{fmtTime(p.observed_at)}</span></td></tr>))}</tbody>
                  </table>
                ) : <p className="muted">No observation has been recorded for this asset.</p>}
              </section>
              <section className="panel" aria-labelledby="as-find">
                <h2 id="as-find">Accepted findings</h2>
                {!a.findings_visible ? (
                  <Banner tone="neutral" title="Findings hidden">Your role{me ? ` (${me.roles.join(', ')})` : ''} cannot read findings.</Banner>
                ) : a.findings.length ? (
                  <ul className="list-plain" data-testid="asset-findings">{a.findings.map((x) => (
                    <li key={x.run_id + x.finding_id}><Badge d={display(SEVERITY_DISPLAY, x.severity)} /> <Link to={`/findings/${x.run_id}/${x.finding_id}`}>{x.title}</Link> <span className="muted">({LIFECYCLE_LABEL[x.lifecycle] ?? x.lifecycle})</span></li>))}
                  </ul>
                ) : <p className="muted">No accepted finding names this asset. That is not proof it is secure; check its posture and coverage.</p>}
              </section>
            </div>
          </div>
        </>
      )}
    </DataState>
  )
}
