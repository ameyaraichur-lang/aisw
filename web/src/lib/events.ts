// Run-event logic: SSE parsing, cursor-based reduction (dedupe/ordering) and timeline derivation.
// Events are NOTIFICATIONS: the status snapshot endpoints stay the source of truth, and the UI
// re-reads them after every reconnect.
import type { RunEvent, TaskView } from '../api/types'

export interface SseMessage {
  id?: string
  event: string
  data: string
}

/** Incremental SSE parser. Returns complete messages and the unconsumed remainder. */
export function parseSse(buffer: string): { messages: SseMessage[]; rest: string } {
  const normalized = buffer.replace(/\r\n/g, '\n')
  const parts = normalized.split('\n\n')
  const rest = parts.pop() ?? ''
  const messages: SseMessage[] = []
  for (const block of parts) {
    if (!block.trim() || block.startsWith(':')) continue // comment / heartbeat
    const msg: SseMessage = { event: 'message', data: '' }
    const data: string[] = []
    for (const line of block.split('\n')) {
      if (line.startsWith(':')) continue
      const i = line.indexOf(':')
      const field = i === -1 ? line : line.slice(0, i)
      const value = i === -1 ? '' : line.slice(i + 1).replace(/^ /, '')
      if (field === 'id') msg.id = value
      else if (field === 'event') msg.event = value
      else if (field === 'data') data.push(value)
    }
    msg.data = data.join('\n')
    messages.push(msg)
  }
  return { messages, rest }
}

export interface EventState {
  events: RunEvent[]
  cursor: number
  seen: ReadonlySet<string>
}
export const emptyEvents: EventState = { events: [], cursor: 0, seen: new Set() }

/** Merge incoming events: duplicates (by event_id or already-passed seq) are ignored. */
export function applyEvents(state: EventState, incoming: RunEvent[]): EventState {
  const seen = new Set(state.seen)
  const events = [...state.events]
  let cursor = state.cursor
  for (const e of [...incoming].sort((a, b) => a.seq - b.seq)) {
    if (seen.has(e.event_id) || events.some((x) => x.seq === e.seq)) continue
    seen.add(e.event_id)
    events.push(e)
    cursor = Math.max(cursor, e.seq)
  }
  events.sort((a, b) => a.seq - b.seq)
  return { events, cursor, seen }
}

export type StageStatus = 'pending' | 'running' | 'succeeded' | 'partial' | 'failed' | 'cancelled'
export interface Stage {
  key: string
  label: string
  status: StageStatus
  startedAt: string | null
  endedAt: string | null
  detail: string
  warnings: number
  errors: number
}

const STAGES = [
  ['authorization', 'Authorization'],
  ['collection', 'Collection (adapters)'],
  ['normalization', 'Evidence normalization'],
  ['policy', 'Policy evaluation'],
  ['assurance', 'Assurance'],
  ['report', 'Report review'],
] as const

const num = (v: unknown): number => (typeof v === 'number' ? v : 0)
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : [])

/** Derive stage rows purely from persisted events (no invented progress). */
export function deriveStages(events: RunEvent[]): Stage[] {
  const at = (type: string, pred: (e: RunEvent) => boolean = () => true) =>
    events.filter((e) => e.type === type && pred(e))
  const phase = (to: string) => at('phase.changed', (e) => e.payload.to === to)[0]
  const st: Record<string, Stage> = Object.fromEntries(
    STAGES.map(([key, label]) => [
      key,
      { key, label, status: 'pending', startedAt: null, endedAt: null, detail: '', warnings: 0, errors: 0 } as Stage,
    ]),
  )

  const accepted = at('assessment.accepted')[0]
  const preflight = at('preflight.completed')[0]
  if (accepted) {
    st.authorization.startedAt = accepted.occurred_at
    st.authorization.status = preflight ? 'succeeded' : 'running'
    st.authorization.endedAt = preflight?.occurred_at ?? null
    st.authorization.detail = preflight ? 'Permit issued for the approved manifest' : 'Verifying scope'
  }

  const queued = at('task.queued').length
  const started = at('task.started')
  const finished = [...at('task.completed'), ...at('task.partial'), ...at('task.failed')].sort(
    (a, b) => a.seq - b.seq,
  )
  const byId = new Map<string, RunEvent>()
  for (const e of finished) byId.set(String(e.payload.task_id), e) // last terminal event wins
  const done = [...byId.values()]
  const failed = done.filter((e) => e.type === 'task.failed').length
  const partial = done.filter((e) => e.type === 'task.partial').length
  const col = st.collection
  if (queued > 0) {
    col.status = 'running'
    col.startedAt = started[0]?.occurred_at ?? null
    col.detail = `${done.length} of ${queued} task(s) finished`
    col.warnings = done.reduce((n, e) => n + arr(e.payload.warning_codes).length, 0)
    col.errors = done.reduce((n, e) => n + arr(e.payload.error_codes).length, 0)
    if (done.length === queued) {
      col.endedAt = done.map((e) => e.occurred_at).sort().at(-1) ?? null
      const cancelled = done.filter((e) => e.payload.status === 'CANCELLED').length
      col.status =
        cancelled === queued ? 'cancelled' : failed === queued ? 'failed' : failed + partial > 0 ? 'partial' : 'succeeded'
    }
  }

  const stored = at('evidence.batch.stored')
  if (stored.length > 0) {
    const n = stored.reduce((a, e) => a + num(e.payload.observation_count), 0)
    const assets = stored.reduce((a, e) => a + num(e.payload.asset_count), 0)
    st.normalization.status = col.status === 'running' ? 'running' : 'succeeded'
    st.normalization.startedAt = stored[0].occurred_at
    st.normalization.endedAt = col.status === 'running' ? null : (stored.at(-1)?.occurred_at ?? null)
    st.normalization.detail = `${assets} asset(s), ${n} observation(s), ${stored.length} evidence batch(es)`
  }

  const toPolicy = phase('POLICY_EVALUATION')
  const toAssurance = phase('ASSURANCE')
  if (toPolicy) {
    st.policy.status = toAssurance ? 'succeeded' : 'running'
    st.policy.startedAt = toPolicy.occurred_at
    st.policy.endedAt = toAssurance?.occurred_at ?? null
    st.policy.detail = toAssurance ? 'Controls, findings and coverage computed' : 'Evaluating pinned policy pack'
  }
  const report = [...at('report.ready'), ...at('report.partial')][0]
  if (toAssurance) {
    st.assurance.status = report ? 'succeeded' : 'running'
    st.assurance.startedAt = toAssurance.occurred_at
    st.assurance.endedAt = report?.occurred_at ?? null
    st.assurance.detail = report ? 'Independent evidence checks complete' : 'Verifying evidence for each finding'
  }
  if (report) {
    st.report.status = report.type === 'report.partial' ? 'partial' : 'succeeded'
    st.report.startedAt = report.occurred_at
    st.report.detail =
      report.type === 'report.partial' ? 'Report generated with limitations: review required' : 'Report ready for review'
    const closed = at('assessment.closed')[0]
    if (closed) {
      st.report.endedAt = closed.occurred_at
      st.report.detail += '; approved and closed'
    }
  }

  const cancelled = at('assessment.cancelled')[0]
  const failedPhase = at('phase.changed', (e) => e.payload.to === 'FAILED')[0]
  const terminal = cancelled ? 'cancelled' : failedPhase ? 'failed' : null
  if (terminal) {
    const why = String((cancelled ?? failedPhase)?.payload.reason ?? '')
    for (const s of Object.values(st)) {
      if (s.status === 'running') s.status = terminal // interrupted mid-flight
      else if (s.status === 'pending') s.detail = `Not started: run ${terminal}${why ? ` (${why})` : ''}`
    }
  }
  return STAGES.map(([k]) => st[k])
}

export function describeEvent(e: RunEvent): string {
  const p = e.payload
  switch (e.type) {
    case 'assessment.accepted':
      return `Assessment accepted (requested by ${String(p.actor_ref)})`
    case 'preflight.completed':
      return `Preflight ${String(p.result)}`
    case 'phase.changed':
      return `Phase ${String(p.from)} → ${String(p.to)}${p.reason ? ` (${String(p.reason)})` : ''}`
    case 'task.queued':
      return `Task queued for ${String(p.agent_id)}`
    case 'task.started':
      return `Task started (attempt ${num(p.attempt) || 1})`
    case 'task.progress':
      return `Task: ${String(p.note ?? 'progress')}`
    case 'evidence.batch.stored':
      return `Evidence stored: ${num(p.asset_count)} asset(s), ${num(p.observation_count)} observation(s)`
    case 'task.completed':
    case 'task.partial':
    case 'task.failed':
      return `Task ${String(p.status ?? e.type.split('.')[1])}${
        arr(p.error_codes).length ? ` — ${arr(p.error_codes).join(', ')}` : ''
      }`
    case 'report.ready':
      return 'Report ready'
    case 'report.partial':
      return 'Report generated with limitations'
    case 'assessment.cancelled':
      return 'Assessment cancelled'
    case 'assessment.closed':
      return 'Assessment closed (report approved)'
    default:
      return e.type
  }
}

export function tasksFinished(tasks: TaskView[]): { done: number; total: number } {
  const open = new Set(['QUEUED', 'RUNNING'])
  return { done: tasks.filter((t) => !open.has(t.status)).length, total: tasks.length }
}
