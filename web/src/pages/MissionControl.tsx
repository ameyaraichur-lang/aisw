import { useQuery } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useAgents, useAssets, useOverview } from '../api/hooks'
import type { AssetRow, FindingRow, Page, RunListItem } from '../api/types'
import { useSession } from '../auth/useSession'
import { MissionScene, type SceneHandle } from '../components/mission/MissionScene'
import { useEventFeed } from '../components/mission/useEventFeed'
import { PageHeader } from '../components/ui'
import { deriveStages, describeEvent, type StageStatus } from '../lib/events'
import { fmtTime } from '../lib/format'
import { buildGroups, eventTone, pulseFor, STATUS_LABEL, truncationNotes, type NodeStatus } from '../lib/mission'
import './mission.css'

const NO_RUNS: RunListItem[] = []
const NO_ASSETS: AssetRow[] = []
const NO_FINDINGS: FindingRow[] = []
const STATUS_ORDER: NodeStatus[] = ['critical', 'high', 'medium', 'low', 'clear']
const STAGE_WORD: Record<StageStatus, string> = {
  pending: 'waiting', running: 'running', succeeded: 'done', partial: 'partial', failed: 'failed', cancelled: 'cancelled',
}
const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false

function useClock(): string {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  return now.toISOString().slice(11, 19)
}

function Gauge({ value, total, label }: { value: number; total: number; label: string }) {
  const pct = total ? value / total : 0
  const r = 42
  const c = 2 * Math.PI * r
  return (
    <figure className="mc-gauge">
      <svg viewBox="0 0 100 100" aria-hidden="true">
        <circle cx="50" cy="50" r={r} className="mc-gauge__track" />
        <circle cx="50" cy="50" r={r} className="mc-gauge__value" strokeDasharray={`${c * pct} ${c}`} />
      </svg>
      <figcaption>
        <span className="mc-gauge__num">{total ? Math.round(pct * 100) : '–'}<small>{total ? '%' : ''}</small></span>
        <span className="mc-gauge__label">{label}</span>
      </figcaption>
    </figure>
  )
}

export function MissionControl() {
  const { can } = useSession()
  const clock = useClock()
  const ov = useOverview()
  const agents = useAgents()
  const runsQ = useQuery({
    queryKey: ['runs', { limit: 6, view: 'mission' }],
    queryFn: () => api<Page<RunListItem>>('/assessments?limit=6'),
    refetchInterval: 4000,
  })
  const assetsQ = useAssets({ limit: 200, offset: 0 })
  const canFindings = can('finding:read')
  const findingsQ = useQuery({
    queryKey: ['findings', { verdict: 'ACCEPT', limit: 200, view: 'mission' }],
    queryFn: () => api<Page<FindingRow>>('/findings?verdict=ACCEPT&limit=200'),
    enabled: canFindings,
  })
  const runs = runsQ.data?.items ?? NO_RUNS
  const assets = assetsQ.data?.items ?? NO_ASSETS
  const findings = (canFindings ? findingsQ.data?.items : undefined) ?? NO_FINDINGS
  const groups = useMemo(() => buildGroups(assets, findings), [assets, findings])
  const notes = truncationNotes(
    { shown: assets.length, total: assetsQ.data?.total ?? assets.length },
    canFindings && findingsQ.data ? { shown: findings.length, total: findingsQ.data.total } : null,
  )
  const { feed, byRun, live } = useEventFeed(runs)

  const scene = useRef<SceneHandle>(null)
  const seen = useRef<Set<string> | null>(null)
  const [fresh, setFresh] = useState<Set<string>>(new Set())
  useEffect(() => {
    if (feed.length === 0) return
    if (seen.current === null) { seen.current = new Set(feed.map((f) => f.key)); return } // history is not re-animated
    const added = feed.filter((f) => !seen.current?.has(f.key)).reverse()
    if (added.length === 0) return
    for (const f of added) seen.current.add(f.key)
    added.slice(-12).forEach((f, i) => {
      const kind = pulseFor(f.type, f.tone)
      if (kind) setTimeout(() => scene.current?.pulse(kind, f.projectId), i * 220)
    })
    setFresh(new Set(added.map((f) => f.key)))
  }, [feed])

  const latest = runs[0]
  const latestEvents = latest ? byRun.get(latest.run_id) ?? [] : []
  const stages = deriveStages(latestEvents)
  const [replay, setReplay] = useState<{ runId: string; done: number; total: number } | null>(null)
  const replayTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => () => { if (replayTimer.current) clearTimeout(replayTimer.current) }, [])
  const startReplay = () => {
    if (!latest || latestEvents.length === 0) return
    const evs = [...latestEvents].sort((a, b) => a.seq - b.seq)
    let i = 0
    const next = () => {
      if (i >= evs.length) { setReplay(null); return }
      const e = evs[i++]
      const kind = pulseFor(e.type, eventTone(e))
      if (kind) scene.current?.pulse(kind, latest.project_id)
      setReplay({ runId: latest.run_id, done: i, total: evs.length })
      replayTimer.current = setTimeout(next, 450)
    }
    next()
  }
  const motion = !reducedMotion()

  const counts = STATUS_ORDER.map((s) => [s, groups.reduce((n, g) => n + g.nodes.filter((x) => x.status === s).length, 0)] as const)
  const o = ov.data
  const ai = agents.data?.ai

  return (
    <div className="mc">
      <PageHeader title="Mission Control" lead="Live view of every tracked asset and every recorded run event. Motion in the 3D view is decorative; pulses fire only for events the platform has recorded." />
      <div className="mc-status" role="group" aria-label="System status">
        <span className="mc-dot mc-dot--ok" aria-hidden="true" /> <span>Platform online</span>
        <span className="mc-sep" aria-hidden="true">//</span>
        <span>AI {ai?.enabled ? <strong>{ai.model_id}</strong> : 'off'}{ai?.validation_enabled ? <> · validator <strong>{ai.validation_model ?? ai.model_id}</strong></> : null}</span>
        <span className="mc-sep" aria-hidden="true">//</span>
        <span>{live ? <><span className="mc-dot mc-dot--live" aria-hidden="true" /> Run in progress</> : 'Idle: no run in progress'}</span>
        <span className="spacer" />
        <span className="mc-clock" aria-hidden="true">UTC {clock}</span>
      </div>

      <div className="mc-grid">
        <section className="mc-panel mc-vitals" aria-labelledby="mc-vitals">
          <h2 id="mc-vitals" className="mc-h">Vitals</h2>
          {o ? (
            <>
              <Gauge value={o.coverage.reconciled} total={o.coverage.expected} label="coverage" />
              <p className="denominator">{o.coverage.reconciled} of {o.coverage.expected} expected assets reconciled; {o.coverage.segments_incomplete} of {o.coverage.segments_total} segment(s) incomplete</p>
              <dl className="mc-stats">
                <div><dt>Critical / high open</dt><dd className={o.findings.open_critical_high_authoritative ? 'mc-bad' : 'mc-ok'}>{o.findings.open_critical_high_authoritative}</dd></div>
                <div><dt>Runs (total)</dt><dd>{o.runs.total}</dd></div>
                <div><dt>Active runs</dt><dd>{o.active_runs.length}</dd></div>
                <div><dt>Exceptions in force</dt><dd>{o.exceptions.active}</dd></div>
              </dl>
            </>
          ) : <p role="status">Loading vitals…</p>}
          <h3 className="mc-h">Agents</h3>
          <ul className="mc-agents">
            {(agents.data?.agents ?? []).map((a) => (
              <li key={a.agent_id} title={a.purpose}>
                <span className={`mc-dot ${a.ai_active ? 'mc-dot--ai' : 'mc-dot--ok'}`} aria-hidden="true" />
                <span className="mc-agent__id">A{a.agent_id}</span> {a.name}
                {a.ai_active ? <span className="mc-tag-ai">AI</span> : null}
              </li>
            ))}
          </ul>
        </section>

        <section className="mc-panel mc-stage" aria-labelledby="mc-estate">
          <div className="mc-stage__head">
            <h2 id="mc-estate" className="mc-h">Estate</h2>
            <ul className="mc-legend" aria-label="Legend">
              {counts.map(([s, n]) => <li key={s}><span className={`mc-swatch mc-swatch--${s}`} aria-hidden="true" />{STATUS_LABEL[s]}: {n}</li>)}
            </ul>
            {motion ? (
              <button type="button" className="btn btn--small" onClick={startReplay} disabled={!latestEvents.length || !!replay}>
                Replay last run
              </button>
            ) : null}
          </div>
          <MissionScene ref={scene} groups={groups} />
          {notes.length ? (
            <div className="mc-notes" data-testid="mission-truncation">
              {notes.map((t) => <p key={t}>{t}</p>)}
              <p>
                <Link to="/assets">The Asset Explorer lists every asset</Link>
                {canFindings ? <>; <Link to="/findings">Findings &amp; Exposure lists every finding</Link></> : null}.
              </p>
            </div>
          ) : null}
          <p className="mc-replay" aria-live="polite">
            {replay ? `Replaying recorded events of run ${replay.runId.slice(0, 8)}: ${replay.done} of ${replay.total}` : ''}
          </p>
          <details className="mc-roster">
            <summary>Tracked assets ({groups.reduce((n, g) => n + g.nodes.length, 0)}){canFindings ? '' : ' — severity colours need the finding:read permission'}</summary>
            {groups.length === 0 ? <p>No assets yet. <Link to="/assessments/new">Run a first assessment</Link>.</p> : (
              <ul className="list-plain">
                {groups.map((g) => (
                  <li key={g.projectId}>
                    <strong>{g.projectName}</strong>
                    <ul className="mc-roster__nodes">
                      {g.nodes.map((n) => (
                        <li key={n.id}><span className={`mc-swatch mc-swatch--${n.status}`} aria-hidden="true" />{n.label} <span className="muted">({n.kind}; {STATUS_LABEL[n.status]}{n.findings ? `, ${n.findings} finding(s)` : ''})</span></li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
            )}
          </details>
        </section>

        <section className="mc-panel mc-feed" aria-labelledby="mc-feed">
          <h2 id="mc-feed" className="mc-h">Event stream</h2>
          <div role="log" aria-label="Recent run events, newest first" aria-live="polite" aria-relevant="additions">
          <ol className="mc-feed__list">
            {feed.length === 0 ? <li className="muted">No run events recorded yet.</li> : feed.map((f) => (
              <li key={f.key} className={`mc-ev mc-ev--${f.tone}${fresh.has(f.key) ? ' mc-ev--fresh' : ''}`}>
                <time dateTime={f.at} title={fmtTime(f.at)}>{fmtTime(f.at).slice(11, 19)}</time>
                <span className="mc-ev__text">{f.text}</span>
                <Link to={`/assessments/${f.runId}/timeline`} className="mc-ev__run">{f.projectName}</Link>
              </li>
            ))}
          </ol>
          </div>
        </section>
      </div>

      <section className="mc-panel mc-pipeline" aria-labelledby="mc-pipe">
        <h2 id="mc-pipe" className="mc-h">
          Pipeline {latest ? <>— <Link to={`/assessments/${latest.run_id}/timeline`}>{latest.project_name} · run {latest.run_id.slice(0, 8)}</Link></> : null}
        </h2>
        {latest ? (
          <ol className="mc-pipe">
            {stages.map((s) => (
              <li key={s.key} className={`mc-pipe__stage mc-pipe__stage--${s.status}`}>
                <span className="mc-pipe__label">{s.label}</span>
                <span className="mc-pipe__state">{STAGE_WORD[s.status]}</span>
              </li>
            ))}
          </ol>
        ) : <p>No assessment has run yet.</p>}
        {latestEvents.length ? <p className="hint">Last event: {describeEvent(latestEvents[latestEvents.length - 1])}</p> : null}
      </section>
    </div>
  )
}
