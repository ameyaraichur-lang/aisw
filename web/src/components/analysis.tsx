// Shared views for the analysis layer. Rules the UI enforces visually:
//  * a risk tier is shown only when the rubric inputs were complete; otherwise "Not rated" with the reason
//  * model-written text is always labelled and always sits beside the deterministic description
//  * a recommendation is a draft for planning: there is no "execute" or "apply" control anywhere
import type { ReactNode } from 'react'
import { Badge } from './ui'
import type { Narrative, Recommendation, RiskInfo, Scenario } from '../api/types'
import { RECOMMENDATION_STATUS_DISPLAY, VERDICT_DISPLAY, display } from '../lib/status'

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
        <dt>Rubric</dt><dd><code>risk-rubric {risk.rubric_version}</code></dd>
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

export function ScenarioCard({ s }: { s: Scenario }) {
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
      <h4>Evidence chain (observed only)</h4>
      <ol>{s.chain.map((c) => <li key={c.finding_id}>finding <code>{c.finding_id}</code> from evidence <code>{c.evidence_ref}</code> ({c.basis.toLowerCase()}){c.note ? `: ${c.note}` : ''}</li>)}</ol>
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
