import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useAllFindings, useFinding, useRuns } from '../api/hooks'
import { Badge, Banner, CopyButton, DataState, PageHeader, Pagination, ShortHash } from '../components/ui'
import { RiskPanel } from '../components/analysis'
import { fmtTime } from '../lib/format'
import { OUTCOME_DISPLAY, SEVERITY_DISPLAY, VERDICT_DISPLAY, display } from '../lib/status'
import { ControlsTable } from './RunDetail'

export function Findings() {
  const [sp, setSp] = useSearchParams()
  const severity = sp.getAll('severity')
  const verdict = sp.get('verdict') === 'NEEDS_REVIEW' ? 'NEEDS_REVIEW' : 'ACCEPT'
  const [offset, setOffset] = useState(0)
  const q = useAllFindings({ verdict, severity, limit: 25, offset })
  const toggle = (s: string) => {
    const next = severity.includes(s) ? severity.filter((x) => x !== s) : [...severity, s]
    const p = new URLSearchParams(); next.forEach((x) => p.append('severity', x)); if (verdict !== 'ACCEPT') p.set('verdict', verdict)
    setOffset(0); setSp(p)
  }
  return (
    <>
      <PageHeader title="Findings & Exposure" lead="Evidence-backed findings across runs. Only independently accepted findings are authoritative." />
      <fieldset>
        <legend>Filters</legend>
        <div className="row">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
            <label key={s} className="inline-check"><input type="checkbox" checked={severity.includes(s)} onChange={() => toggle(s)} /> {s[0] + s.slice(1).toLowerCase()}</label>
          ))}
          <label className="inline-check"><input type="checkbox" checked={verdict === 'NEEDS_REVIEW'} onChange={(e) => { const p = new URLSearchParams(sp); if (e.target.checked) p.set('verdict', 'NEEDS_REVIEW'); else p.delete('verdict'); setOffset(0); setSp(p) }} /> Show pending review instead</label>
        </div>
      </fieldset>
      <DataState q={q} label="findings" isEmpty={(d) => d.items.length === 0} empty={<p className="muted">No findings match. An empty list does not mean the estate is clean; check coverage.</p>}>
        {(d) => (
          <>
            <div className="table-wrap">
              <table>
                <caption>{verdict === 'ACCEPT' ? 'Authoritative findings' : 'Pending review (not authoritative)'}: {d.total}</caption>
                <thead><tr><th scope="col">Severity</th><th scope="col">Title</th><th scope="col">Project</th><th scope="col">Assets</th><th scope="col">Lifecycle</th><th scope="col">Run</th></tr></thead>
                <tbody>{d.items.map((f) => (
                  <tr key={f.run_id + f.finding_id}>
                    <td><Badge d={display(SEVERITY_DISPLAY, f.severity)} /></td>
                    <td><Link to={`/findings/${f.run_id}/${f.finding_id}`}>{f.title}</Link></td>
                    <td>{f.project_name}</td><td>{f.affected_assets.join(', ')}</td><td>{f.lifecycle}</td>
                    <td><Link to={`/assessments/${f.run_id}`}>{f.run_id.slice(0, 8)}</Link></td>
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

export function FindingDetail() {
  const { runId = '', findingId = '' } = useParams()
  const q = useFinding(runId, findingId)
  return (
    <DataState q={q} label="finding">
      {(d) => {
        const f = d.finding
        const age = (iso: string) => (Date.now() - new Date(iso).getTime()) / 3600_000
        return (
          <>
            <PageHeader title={f.title} lead={<>Finding <code>{f.finding_id}</code> in run <Link to={`/assessments/${runId}`}>{runId.slice(0, 8)}</Link></>}>
              <CopyButton value={f.finding_id} label="finding id" />
            </PageHeader>
            <p className="row">
              <Badge d={display(SEVERITY_DISPLAY, f.severity)} title={`severity source: ${f.severity_source}`} />
              <Badge d={display(OUTCOME_DISPLAY as never, f.outcome)} />
              <Badge d={display(VERDICT_DISPLAY, d.assurance_verdict)} />
              <span className="chip">lifecycle {f.lifecycle}</span>
              <span className="chip">confidence {f.confidence}</span>
              <span className="chip">business risk: {d.risk_explanation.business_risk ?? 'not rated'}</span>
            </p>
            {!d.authoritative ? <Banner tone="warn" role="alert" title="Not authoritative">Independent assurance has not accepted this finding, so it is excluded from the report dataset.</Banner> : null}
            <div className="split split--2">
              <div>
                <section className="panel" aria-labelledby="ev">
                  <h2 id="ev">Evidence</h2>
                  <dl className="kv">
                    <dt>Affected assets</dt><dd>{f.affected_assets.join(', ')}</dd>
                    <dt>First / last observed</dt><dd>{fmtTime(f.first_observed)} / {fmtTime(f.last_observed)}</dd>
                  </dl>
                  {d.evidence.map((e) => (
                    <dl className="kv" key={e.evidence_ref}>
                      <dt>Reference</dt><dd><code>{e.evidence_ref}</code></dd>
                      <dt>Source / tool</dt><dd>{e.source} / {e.tool_version}</dd>
                      <dt>Collected</dt><dd>{fmtTime(e.collected_at)} {age(e.collected_at) > 24 ? <Badge d={{ icon: '⌛', label: 'Stale (over 24h)', tone: 'warn' }} /> : <Badge d={{ icon: '✓', label: 'Fresh', tone: 'ok' }} />}</dd>
                      <dt>Integrity hash</dt><dd><ShortHash value={e.content_hash} /> ({e.size_bytes} bytes, {e.media_type})</dd>
                      <dt>Sensitive data</dt><dd>{e.redacted ? 'Secrets were redacted before storage' : 'No redaction needed'}</dd>
                    </dl>
                  ))}
                  <h3>Observed versus expected (sanitized)</h3>
                  {d.observation ? (
                    <dl className="kv">
                      <dt>Rule</dt><dd><code>{d.observation.rule_id}</code></dd>
                      <dt>Observed</dt><dd><code>{JSON.stringify(d.observation.observed_value)}</code></dd>
                      <dt>Expected</dt><dd><code>{JSON.stringify(d.observation.expected_value)}</code></dd>
                    </dl>
                  ) : <p className="muted">No matching observation could be resolved.</p>}
                </section>
                <section className="panel" aria-labelledby="rk">
                  <h2 id="rk">Risk explanation</h2>
                  <h3>Deterministic factors</h3>
                  <dl className="kv">
                    <dt>Severity</dt><dd>{d.risk_explanation.deterministic.severity} from <code>{d.risk_explanation.deterministic.severity_source}</code></dd>
                    <dt>Confidence</dt><dd>{d.risk_explanation.deterministic.confidence}</dd>
                  </dl>
                  <h3>Risk rubric</h3>
                  <RiskPanel risk={d.risk_explanation.risk} />
                  <h3>Scenarios that include this finding</h3>
                  {d.risk_explanation.scenarios.length ? <ul>{d.risk_explanation.scenarios.map((s) => <li key={s.scenario_id}>{s.title} ({s.tier ?? 'not rated'}); see <Link to={`/assessments/${runId}/analysis`}>the run's analysis</Link></li>)}</ul> : <p className="muted">None.</p>}
                  <h3>Inferred links</h3>
                  <p>{d.risk_explanation.inferred_links.length ? d.risk_explanation.inferred_links.join(', ') : 'None. Nothing here is inferred.'}</p>
                  <h3>Assumptions</h3>
                  <ul>{d.risk_explanation.assumptions.map((a) => <li key={a}>{a}</li>)}</ul>
                  <h3>AI narrative</h3>
                  <p className="muted">{d.risk_explanation.ai_narrative ?? 'Not shown here. Any AI-written summary is attached to a scenario or recommendation, labelled, and only after validation; with AI disabled none exists.'}</p>
                </section>
              </div>
              <div>
                <section className="panel" aria-labelledby="cm">
                  <h2 id="cm">Control mapping</h2>
                  <table><caption>Mapped controls and their approval state</caption>
                    <thead><tr><th scope="col">Framework</th><th scope="col">Control</th><th scope="col">Mapping</th></tr></thead>
                    <tbody>{(f.control_mappings ?? []).map((m, i) => (
                      <tr key={i}><td>{m.framework} {m.version}</td><td><code>{m.control_id}</code></td>
                        <td>{m.mapping_status === 'APPROVED' ? <Badge d={{ icon: '✓', label: 'Approved', tone: 'ok' }} /> : <Badge d={{ icon: '?', label: 'Needs policy-owner review', tone: 'warn' }} />}</td></tr>))}</tbody>
                  </table>
                  <p className="hint">Policy: <code>{f.policy_version}</code></p>
                </section>
                <section className="panel" aria-labelledby="as">
                  <h2 id="as">Independent assurance</h2>
                  {d.assurance ? (
                    <dl className="kv">
                      <dt>Verdict</dt><dd>{d.assurance.verdict}</dd>
                      <dt>Defects</dt><dd>{d.assurance.defect_codes.length ? d.assurance.defect_codes.join(', ') : 'none'}</dd>
                      <dt>Validator</dt><dd>v{d.assurance.validation_version} at {fmtTime(d.assurance.validated_at)}</dd>
                    </dl>
                  ) : <p className="muted">Not yet assessed.</p>}
                </section>
                <section className="panel" aria-labelledby="ra">
                  <h2 id="ra">Review actions</h2>
                  <p className="muted">Recording decisions (confirm, reject, exception request) is planned for a later milestone. Nothing on this page changes data.</p>
                </section>
              </div>
            </div>
          </>
        )
      }}
    </DataState>
  )
}

export function ControlCoverage() {
  const runs = useRuns({ limit: 50 })
  const [sel, setSel] = useState('')
  return (
    <>
      <PageHeader title="Control Coverage" lead="Control outcomes per run. Unknown and not-assessed are separate from pass." />
      <DataState q={runs} label="runs" isEmpty={(d) => d.items.length === 0} empty={<p className="muted">No runs yet.</p>}>
        {(d) => {
          const finished = d.items.filter((r) => ['REPORT_READY', 'PARTIAL', 'CLOSED'].includes(r.state))
          const runId = sel || finished[0]?.run_id || ''
          return (
            <>
              <label htmlFor="cr">Run</label>
              <select id="cr" value={runId} onChange={(e) => setSel(e.target.value)}>
                {d.items.map((r) => <option key={r.run_id} value={r.run_id}>{r.run_id.slice(0, 8)} · {r.project_name} · {r.state}</option>)}
              </select>
              {runId ? <div style={{ marginTop: '1rem' }}><ControlsTable runId={runId} /></div> : <p className="muted">No finished run yet.</p>}
            </>
          )
        }}
      </DataState>
    </>
  )
}
