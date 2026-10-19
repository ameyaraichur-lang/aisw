// Shared views for the analysis layer. Rules the UI enforces visually:
//  * a risk tier is shown only when the rubric inputs were complete; otherwise "Not rated" with the reason
//  * model-written text is always labelled and always sits beside the deterministic description
//  * a recommendation is a draft for planning: there is no "execute" or "apply" control anywhere
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Badge } from './ui'
import type { Narrative, Recommendation, RiskInfo, Scenario } from '../api/types'
import { describePorts } from '../lib/format'
import { RECOMMENDATION_STATUS_DISPLAY, SEVERITY_DISPLAY, VERDICT_DISPLAY, display } from '../lib/status'

export function TierBadge({ tier, provisional }: { tier: string | null; provisional?: string }) {
  if (tier) return <span className="chip" title="Business-risk tier from the versioned rubric">Risk tier {tier}</span>
  return (
    <span className="chip" title="Owner-supplied asset criticality is missing, so no business-risk tier is produced">
      Not rated{provisional ? ` (severity-only indication ${provisional})` : ''}
    </span>
  )
}

export function RiskPanel({ risk }: { risk: RiskInfo | null }) {
  if (!risk) return <p className="muted">No risk assessment was recorded for this finding.</p>
  return (
    <>
      <dl className="kv">
        <dt>Rubric</dt>
        <dd>
          <code>risk-rubric {risk.rubric_version}</code>
          {risk.rubric_signoff !== 'APPROVED' ? ' (sample rubric awaiting policy-owner approval: treat tiers as indicative)' : null}
        </dd>
        <dt>Business-risk tier</dt>
        <dd>{risk.tier ?? 'Not rated: the inputs are incomplete, so no tier is invented.'}</dd>
        <dt>Severity-only indication</dt><dd>{risk.provisional_tier} (not business risk)</dd>
        <dt>Inputs</dt>
        <dd>
          severity {risk.factors.severity}; criticality {risk.factors.criticality ?? 'unknown'}; exposure {risk.factors.exposure.toLowerCase()};
          {' '}evidence {risk.factors.evidence_fresh ? 'fresh' : 'stale'}; {risk.factors.corroborating_sources} source(s)
        </dd>
        <dt>Calculation</dt><dd>{risk.rationale}</dd>
      </dl>
      {risk.missing_evidence.length ? (
        <>
          <h4>Missing evidence</h4>
          <ul>{risk.missing_evidence.map((m) => <li key={m}>{m}</li>)}</ul>
        </>
      ) : null}
    </>
  )
}

export function NarrativeBlock({ n }: { n: Narrative | null }) {
  if (!n) return null
  return (
    <aside className="panel panel--nested" aria-label="AI-written summary">
      <p className="hint">
        <strong>AI-written summary.</strong> Checked against the recorded evidence (model <code>{n.model_id}</code>, prompt <code>{n.prompt_version}</code>). It explains; it does not decide.
      </p>
      <p>{n.summary}</p>
      <ul>{n.claims.map((c, i) => <li key={i}>{c.text}</li>)}</ul>
      {n.open_questions.length ? <><h4>Open questions</h4><ul>{n.open_questions.map((q) => <li key={q}>{q}</li>)}</ul></> : null}
    </aside>
  )
}

function List({ title, items, empty }: { title: string; items: string[]; empty?: string }) {
  return (
    <>
      <h4>{title}</h4>
      {items.length ? <ul>{items.map((x) => <li key={x}>{x}</li>)}</ul> : <p className="muted">{empty ?? 'None'}</p>}
    </>
  )
}

const EDGE_LABEL: Record<string, string> = { OBSERVED: 'observed', CONFIGURED: 'configured', INFERRED: 'inferred' }

export function ChainView({ s, runId }: { s: Scenario; runId: string }) {
  const inferred = s.chain.some((c) => c.basis === 'INFERRED')
  return (
    <>
      <h4>Evidence chain</h4>
      <p className="hint">
        Solid links are recorded evidence{inferred ? '; dashed links are inferred and must be validated before they are relied on' : '; nothing in this chain is inferred'}.
      </p>
      {s.path?.length ? (
        <>
          <h4>Route from the internet</h4>
          <ol className="chain" aria-label={`Route to ${s.asset_id}`} data-testid="scenario-path">
            <li><div className="chain__node chain__node--asset"><span className="muted">Origin</span><br />internet</div></li>
            {s.path.map((e) => (
              <li key={e.edge_id}>
                <span className="chain__edge">{EDGE_LABEL[e.basis] ?? e.basis.toLowerCase()}</span>
                <div className="chain__node">
                  <div><Link to={`/assets?q=${encodeURIComponent(e.dst)}`}>{e.dst}</Link></div>
                  <div className="muted">{describePorts(e.ports)} via <code>{e.via}</code>{e.note ? `: ${e.note}` : ''}</div>
                </div>
              </li>
            ))}
          </ol>
        </>
      ) : null}
      <ol className="chain" aria-label={`Evidence chain for ${s.title}`} data-testid="scenario-chain">
        <li><div className="chain__node chain__node--asset"><span className="muted">Asset</span><br /><Link to={`/assets?q=${encodeURIComponent(s.asset_id)}`}>{s.asset_id}</Link></div></li>
        {s.chain.map((c) => (
          <li key={c.finding_id}>
            <span className={c.basis === 'INFERRED' ? 'chain__edge chain__edge--inferred' : 'chain__edge'}>{EDGE_LABEL[c.basis] ?? c.basis.toLowerCase()}</span>
            <div className="chain__node">
              {c.severity ? <Badge d={display(SEVERITY_DISPLAY, c.severity)} /> : null}
              <div><Link to={`/findings/${runId}/${c.finding_id}`}>{c.title ?? c.finding_id}</Link></div>
              <div className="muted">evidence <code>{c.evidence_ref.slice(0, 18)}</code>{c.note ? `: ${c.note}` : ''}</div>
            </div>
          </li>
        ))}
      </ol>
    </>
  )
}

export function ScenarioCard({ s, runId }: { s: Scenario; runId: string }) {
  const id = `sc-${s.scenario_id}`
  return (
    <section className="panel" aria-labelledby={id}>
      <h3 id={id}>{s.title}</h3>
      <p className="row">
        <TierBadge tier={s.tier} />
        <Badge d={display(VERDICT_DISPLAY, s.assurance_verdict ?? 'NEEDS_REVIEW')} />
        <span className="chip">confidence {s.confidence}</span>
        <span className="chip">asset {s.asset_id}</span>
      </p>
      <ChainView s={s} runId={runId} />
      <List title="Assumptions" items={s.assumptions} />
      <List title="Missing evidence" items={s.missing_evidence} empty="None recorded" />
      <List title="Validation steps" items={s.validation_steps} />
      <NarrativeBlock n={s.narrative} />
    </section>
  )
}

export function RecommendationBody({ r }: { r: Recommendation }) {
  return (
    <>
      <dl className="kv">
        <dt>Pattern</dt><dd><code>{r.catalog_ref}</code> (sample pattern: replace with your approved architecture)</dd>
        <dt>Target state</dt><dd>{r.target_pattern}</dd>
        <dt>Current state</dt><dd>{r.current_state}</dd>
        <dt>Proposed action</dt><dd>{r.action}</dd>
        <dt>Effort</dt><dd>{r.effort.value ?? 'Unknown: only the owner can estimate this'}</dd>
        <dt>Findings</dt><dd>{r.finding_refs.map((f) => <code key={f}>{f} </code>)}</dd>
        <dt>Affected assets</dt><dd>{r.affected_assets.join(', ') || 'none'}</dd>
      </dl>
      <List title="Alternatives" items={r.alternatives} />
      <List title="Prerequisites" items={r.dependencies} />
      <List title="Questions for the owner" items={r.owner_questions} />
      <List title="Validation steps" items={r.validation_steps} />
      <dl className="kv">
        <dt>Rollback</dt><dd>{r.rollback}</dd>
        <dt>Acceptance test</dt><dd>{r.acceptance_test}</dd>
      </dl>
      <List title="Assumptions" items={r.assumptions} />
      <NarrativeBlock n={r.narrative} />
    </>
  )
}

export function RecommendationHeader({ r, children }: { r: Recommendation; children?: ReactNode }) {
  return (
    <p className="row">
      <Badge d={display(RECOMMENDATION_STATUS_DISPLAY, r.status)} />
      <TierBadge tier={r.risk_tier} />
      <Badge d={display(VERDICT_DISPLAY, r.assurance_verdict ?? 'NEEDS_REVIEW')} />
      {children}
    </p>
  )
}
