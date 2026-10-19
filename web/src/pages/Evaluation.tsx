import { Link, useSearchParams } from 'react-router-dom'
import { useAnswerKeys, useEvaluationTrend, useScorecard } from '../api/hooks'
import type { Metric, TrendRow } from '../api/types'
import { Badge, CopyButton, DataState, PageHeader } from '../components/ui'
import { fmtTime } from '../lib/format'
import { METRIC_DISPLAY, display } from '../lib/status'

const TREND_COLUMNS: { key: string; label: string; count?: boolean }[] = [
  { key: 'asset_reconciliation', label: 'Reconciliation' },
  { key: 'status_coverage', label: 'Status coverage' },
  { key: 'detection_recall', label: 'Recall' },
  { key: 'detection_precision', label: 'Precision' },
  { key: 'finding_traceability', label: 'Traceability' },
  { key: 'unsupported_compliance_claims', label: 'Compliance claims', count: true },
  { key: 'reproducibility', label: 'Reproducible' },
]

const pct = (v: number | null | undefined) => (v === null || v === undefined ? '–' : `${Math.round(v * 1000) / 10}%`)

function TrendCell({ row, col }: { row: TrendRow; col: (typeof TREND_COLUMNS)[number] }) {
  const m = row.metrics[col.key]
  if (!m) return <td>–</td>
  const d = display(METRIC_DISPLAY, m.status)
  return <td><span aria-hidden="true">{d.icon}</span> {col.count ? (m.value ?? '–') : pct(m.value)}<span className="sr-only"> ({d.label})</span></td>
}

type Missed = { rule_id: string; asset_id: string; reason: string }
type FalsePositive = { rule_id: string; asset_id: string; finding_id: string }

function MetricDetail({ m }: { m: Metric }) {
  const d = m.detail as Record<string, unknown>
  const missed = (d.missed as Missed[] | undefined) ?? []
  const fps = (d.false_positive as FalsePositive[] | undefined) ?? []
  const agreement = d.answer_key_agreement as { agree: number; of: number; disagree: string[] } | undefined
  const listed = (d.unaccounted ?? d.without_status ?? d.untraceable ?? d.violations ?? d.phrases) as string[] | undefined
  return (
    <>
      {agreement ? <p className="hint">Answer key agrees on {agreement.agree} of {agreement.of} assets{agreement.disagree.length ? `; differs on ${agreement.disagree.join(', ')}` : ''}.</p> : null}
      {missed.length ? <ul className="hint list-plain" aria-label="Known issues not detected">{missed.map((x) => <li key={x.rule_id + x.asset_id}><code>{x.rule_id}</code> on <code>{x.asset_id}</code>: {x.reason}</li>)}</ul> : null}
      {fps.length ? <ul className="hint list-plain" aria-label="False positives">{fps.map((x) => <li key={x.finding_id}>False positive: <code>{x.rule_id}</code> on <code>{x.asset_id}</code></li>)}</ul> : null}
      {listed?.length ? <p className="hint">{listed.join('; ')}</p> : null}
      {typeof d.reason === 'string' ? <p className="hint"><code>{d.reason}</code></p> : null}
      {typeof d.compared_with === 'string' ? <p className="hint">Compared with run <Link to={`/assessments/${d.compared_with}`}><code>{d.compared_with.slice(0, 8)}</code></Link></p> : null}
    </>
  )
}

function ScorecardPanel({ runId }: { runId: string }) {
  const q = useScorecard(runId)
  return (
    <section className="panel" aria-labelledby="ev-card">
      <h2 id="ev-card">Scorecard for run <Link to={`/assessments/${runId}`}><code>{runId.slice(0, 8)}</code></Link></h2>
      <DataState q={q} label="scorecard">
        {(c) => (
          <>
            <p className="hint">
              {c.answer_key ? <>Scored against answer key <code>{c.answer_key.key_id}</code>. {c.answer_key.note}</> : 'No answer key matches this run, so recall and precision are not measured.'}
              {' '}Policy <code>{c.policy_version}</code>{c.fixture_set ? <>, fixture set <code>{c.fixture_set}</code></> : null}.
            </p>
            <p role="status" data-testid="scorecard-summary">{c.summary.MET} met, {c.summary.NOT_MET} not met, {c.summary.MEASURED} measured, {c.summary.NOT_MEASURED} not measured</p>
            <table data-testid="scorecard">
              <caption>Each result is computed from what the run recorded</caption>
              <thead><tr><th scope="col">Metric</th><th scope="col">Target</th><th scope="col">Result</th><th scope="col">Status</th></tr></thead>
              <tbody>{c.metrics.map((m) => (
                <tr key={m.metric}>
                  <th scope="row">{m.label}</th>
                  <td>{m.target}</td>
                  <td>{m.display}<MetricDetail m={m} /></td>
                  <td><Badge d={display(METRIC_DISPLAY, m.status)} /></td>
                </tr>
              ))}</tbody>
            </table>
          </>
        )}
      </DataState>
    </section>
  )
}

function AnswerKeys() {
  const q = useAnswerKeys()
  return (
    <DataState q={q} label="answer keys" isEmpty={(d) => d.length === 0} empty={<p className="muted">No answer keys are packaged.</p>}>
      {(keys) => (
        <ul className="list-plain">{keys.map((k) => (
          <li key={k.key_id}>
            <strong><code>{k.key_id}</code></strong>: {k.note} {k.known_issues} known issues and {k.known_clean} known-clean checks over {k.cmdb_expected_assets.length} CMDB assets.
            <p className="hint">To score a run: register an <code>asset_group</code> inventory entry with this CMDB list as its expected assets, approve a manifest with policy <code>{k.policy_version}</code>, and launch with fixture set <code>{k.fixture_set}</code>.</p>
            <CopyButton value={k.cmdb_expected_assets.join(' ')} label={`Copy the ${k.key_id} CMDB list`} />
          </li>
        ))}</ul>
      )}
    </DataState>
  )
}

export function EvaluationLab() {
  const [params, setParams] = useSearchParams()
  const fixture = params.get('fixture') ?? ''
  const trend = useEvaluationTrend(fixture || undefined)
  const selected = params.get('run') ?? trend.data?.[0]?.run_id
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params)
    if (v) next.set(k, v)
    else next.delete(k)
    if (k === 'fixture') next.delete('run')
    setParams(next)
  }
  return (
    <>
      <PageHeader title="Evaluation Lab" lead="Each reported run scored against the evaluation targets. Fixture estates are synthetic; the validator catch-rate is measured offline on the labelled set (tools/eval_targets.py records both)." />
      <section className="panel" aria-labelledby="ev-keys">
        <h2 id="ev-keys">Answer keys</h2>
        <AnswerKeys />
      </section>
      <section className="panel" aria-labelledby="ev-trend">
        <h2 id="ev-trend">Recent runs</h2>
        <label htmlFor="ev-fx">Fixture set</label>
        <select id="ev-fx" value={fixture} onChange={(e) => set('fixture', e.target.value)}>
          <option value="">All reported runs</option>
          <option value="maple-trust">maple-trust</option>
          <option value="baseline-ok">baseline-ok</option>
          <option value="baseline-partial">baseline-partial</option>
        </select>
        <DataState q={trend} label="evaluation runs" isEmpty={(d) => d.length === 0} empty={<p className="muted">No reported runs yet.</p>}>
          {(rows) => (
            <table data-testid="evaluation-trend">
              <caption>Newest first; reproducibility compares runs with identical inputs in this list</caption>
              <thead><tr><th scope="col">Run</th><th scope="col">When</th><th scope="col">Answer key</th>{TREND_COLUMNS.map((c) => <th key={c.key} scope="col">{c.label}</th>)}</tr></thead>
              <tbody>{rows.map((r) => (
                <tr key={r.run_id} aria-current={r.run_id === selected ? 'true' : undefined}>
                  <th scope="row"><button type="button" className="btn btn--small" onClick={() => set('run', r.run_id)} aria-label={`Show scorecard for run ${r.run_id.slice(0, 8)}`}><code>{r.run_id.slice(0, 8)}</code></button></th>
                  <td>{fmtTime(r.created_at)}</td>
                  <td>{r.answer_key ?? <span className="muted">none</span>}</td>
                  {TREND_COLUMNS.map((c) => <TrendCell key={c.key} row={r} col={c} />)}
                </tr>
              ))}</tbody>
            </table>
          )}
        </DataState>
      </section>
      {selected ? <ScorecardPanel runId={selected} /> : null}
    </>
  )
}
