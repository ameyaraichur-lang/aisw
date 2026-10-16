import { describe, expect, it } from 'vitest'
import type { RunEvent } from '../api/types'
import { applyEvents, deriveStages, emptyEvents, parseSse } from './events'

const ev = (seq: number, type: string, payload: Record<string, unknown> = {}): RunEvent => ({
  seq,
  event_id: `e-${seq}`,
  type,
  payload,
  occurred_at: `2026-10-15T12:00:${String(seq).padStart(2, '0')}Z`,
})

describe('parseSse', () => {
  it('parses complete frames and keeps the partial tail', () => {
    const raw = 'id: 1\nevent: a\ndata: {"x":1}\n\n: heartbeat\n\nid: 2\nevent: b\ndata: {"y"'
    const { messages, rest } = parseSse(raw)
    expect(messages).toEqual([{ id: '1', event: 'a', data: '{"x":1}' }])
    expect(rest).toBe('id: 2\nevent: b\ndata: {"y"')
    const next = parseSse(rest + ':2}\n\n')
    expect(next.messages[0]).toMatchObject({ id: '2', event: 'b', data: '{"y":2}' })
  })
  it('handles CRLF, multi-line data and frames without id', () => {
    const { messages } = parseSse('event: end\r\ndata: a\r\ndata: b\r\n\r\n')
    expect(messages).toEqual([{ event: 'end', data: 'a\nb' }])
  })
  it('ignores comments and empty blocks', () => {
    expect(parseSse(': hb\n\n\n\n').messages).toEqual([])
  })
})

describe('applyEvents', () => {
  it('orders, advances the cursor and ignores duplicates', () => {
    let s = applyEvents(emptyEvents, [ev(2, 'b'), ev(1, 'a')])
    expect(s.events.map((e) => e.seq)).toEqual([1, 2])
    expect(s.cursor).toBe(2)
    s = applyEvents(s, [ev(2, 'b'), ev(1, 'a'), ev(3, 'c')])
    expect(s.events.map((e) => e.seq)).toEqual([1, 2, 3])
    expect(s.cursor).toBe(3)
  })
  it('replay after reconnect yields the same state (idempotent)', () => {
    const all = [ev(1, 'a'), ev(2, 'b'), ev(3, 'c')]
    const once = applyEvents(emptyEvents, all)
    const twice = applyEvents(applyEvents(emptyEvents, all.slice(0, 2)), all)
    expect(twice.events).toEqual(once.events)
  })
  it('does not mutate the previous state', () => {
    const a = applyEvents(emptyEvents, [ev(1, 'a')])
    applyEvents(a, [ev(2, 'b')])
    expect(a.events).toHaveLength(1)
  })
})

describe('deriveStages', () => {
  const base = [
    ev(1, 'assessment.accepted', { actor_ref: 'alice' }),
    ev(2, 'preflight.completed', { result: 'ALLOW' }),
    ev(3, 'task.queued', { task_id: 't1', agent_id: 'fixture' }),
  ]
  const by = (events: RunEvent[]) => Object.fromEntries(deriveStages(events).map((s) => [s.key, s]))

  it('nothing is invented before it happens', () => {
    const s = by(base)
    expect(s.authorization.status).toBe('succeeded')
    expect(s.collection.status).toBe('running')
    expect(s.collection.detail).toBe('0 of 1 task(s) finished')
    expect(['normalization', 'policy', 'correlation', 'architecture', 'assurance', 'report'].map((k) => s[k].status)).toEqual([
      'pending', 'pending', 'pending', 'pending', 'pending', 'pending',
    ])
  })
  it('full successful run', () => {
    const s = by([
      ...base,
      ev(4, 'task.started', { task_id: 't1' }),
      ev(5, 'evidence.batch.stored', { asset_count: 3, observation_count: 8 }),
      ev(6, 'task.completed', { task_id: 't1', status: 'SUCCEEDED', warning_codes: [], error_codes: [] }),
      ev(7, 'phase.changed', { from: 'ASSESSMENT_DISPATCH', to: 'POLICY_EVALUATION' }),
      ev(8, 'phase.changed', { from: 'POLICY_EVALUATION', to: 'CORRELATION' }),
      ev(9, 'phase.changed', { from: 'CORRELATION', to: 'ARCHITECTURE_ANALYSIS' }),
      ev(10, 'phase.changed', { from: 'ARCHITECTURE_ANALYSIS', to: 'ASSURANCE' }),
      ev(11, 'report.ready', { report_id: 'r' }),
    ])
    expect(Object.values(s).map((x) => x.status)).toEqual(Array(8).fill('succeeded'))
    expect(s.normalization.detail).toContain('3 asset(s), 8 observation(s)')
    expect(s.architecture.detail).toContain('nothing was changed')
  })
  it('shows the analysis stages as running while they run', () => {
    const upto = [...base, ev(4, 'task.completed', { task_id: 't1', status: 'SUCCEEDED' }), ev(5, 'phase.changed', { to: 'POLICY_EVALUATION' }), ev(6, 'phase.changed', { to: 'CORRELATION' })]
    expect(by(upto).policy.status).toBe('succeeded')
    expect(by(upto).correlation.status).toBe('running')
    expect(by(upto).architecture.status).toBe('pending')
    expect(by([...upto, ev(7, 'phase.changed', { to: 'ARCHITECTURE_ANALYSIS' })]).architecture.status).toBe('running')
  })
  it('runs recorded before the analysis phases still read correctly', () => {
    const s = by([...base, ev(4, 'task.completed', { task_id: 't1', status: 'SUCCEEDED' }), ev(5, 'phase.changed', { to: 'POLICY_EVALUATION' }), ev(6, 'phase.changed', { to: 'ASSURANCE' }), ev(7, 'report.ready', {})])
    expect([s.policy.status, s.correlation.status, s.architecture.status, s.assurance.status]).toEqual(['succeeded', 'pending', 'pending', 'succeeded'])
  })
  it('partial task and partial report stay partial, never green', () => {
    const s = by([
      ...base,
      ev(6, 'task.partial', { task_id: 't1', status: 'PARTIAL', warning_codes: ['x', 'y'], error_codes: [] }),
      ev(9, 'report.partial', {}),
    ])
    expect(s.collection.status).toBe('partial')
    expect(s.collection.warnings).toBe(2)
    expect(s.report.status).toBe('partial')
  })
  it('a retry that later succeeds counts the task once', () => {
    const s = by([
      ...base,
      ev(4, 'task.failed', { task_id: 't1', status: 'FAILED', error_codes: ['E'] }),
      ev(5, 'task.completed', { task_id: 't1', status: 'SUCCEEDED' }),
    ])
    expect(s.collection.status).toBe('succeeded')
    expect(s.collection.detail).toBe('1 of 1 task(s) finished')
  })
  it('failed and cancelled runs are explained', () => {
    const failed = by([
      ...base,
      ev(4, 'task.failed', { task_id: 't1', status: 'REJECTED', error_codes: ['PERMIT_REVOKED'] }),
      ev(5, 'phase.changed', { from: 'ASSESSMENT_DISPATCH', to: 'FAILED', reason: 'ALL_TASKS_FAILED' }),
    ])
    expect(failed.collection.status).toBe('failed')
    expect(failed.policy.detail).toContain('Not started: run failed (ALL_TASKS_FAILED)')
    const cancelled = by([
      ...base,
      ev(4, 'task.failed', { task_id: 't1', status: 'CANCELLED', error_codes: ['CANCEL_REQUESTED'] }),
      ev(5, 'assessment.cancelled', { reason: 'CANCEL_REQUESTED' }),
    ])
    expect(cancelled.collection.status).toBe('cancelled')
  })
})
