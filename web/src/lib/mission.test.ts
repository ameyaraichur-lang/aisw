import { describe, expect, it } from 'vitest'
import type { AssetRow, FindingRow, RunEvent, RunListItem } from '../api/types'
import { assetLabel, buildGroups, eventTone, mergeFeed, pulseFor, truncationNotes } from './mission'

const asset = (project: string, id: string, native: Record<string, unknown> = {}): AssetRow => ({
  project_id: `p-${project}`, project_name: project, asset_id: id, asset_type: 'host', native_ids: native, attrs: {},
  environment: null, owner: null, owner_source: null, criticality: null, criticality_source: null, technology: null,
  match_confidence: 'HIGH', first_seen: '2026-10-18T00:00:00Z', last_seen: '2026-10-18T00:00:00Z', last_run_id: 'r',
})
const finding = (project: string, severity: string, assets: string[]): FindingRow => ({
  run_id: 'r', finding_id: `${severity}-${assets.join()}`, severity, lifecycle: 'OPEN', assurance_verdict: 'ACCEPT',
  title: 't', outcome: 'FAIL', affected_assets: assets, project_name: project, authoritative: true,
})
const ev = (seq: number, type: string, at: string, payload: Record<string, unknown> = {}): RunEvent => ({
  seq, event_id: `e${seq}`, type, payload, occurred_at: at,
})
const run = (id: string, project: string): RunListItem => ({
  run_id: id, project_id: `p-${project}`, project_name: project, state: 'REPORT_READY', partial: false,
  created_at: '2026-10-18T00:00:00Z', manifest_hash: 'h', policy_version: 'v', requested_by: 'sam', reason: null,
  tasks_total: 1, tasks_open: 0,
})

describe('assetLabel', () => {
  it('prefers hostname, then ip, image, url, origin', () => {
    expect(assetLabel(asset('a', 'x', { ip: '10.0.0.1', hostname: 'web-1' }))).toBe('web-1')
    expect(assetLabel(asset('a', 'x', { ip: '10.0.0.1', origin: 'https://e.com' }))).toBe('10.0.0.1')
    expect(assetLabel(asset('a', 'x', { origin: 'https://e.com' }))).toBe('https://e.com')
  })
  it('falls back to the asset id when no usable native id exists', () => {
    expect(assetLabel(asset('a', 'url-1', { hostname: '', port: 443 }))).toBe('url-1')
  })
})

describe('buildGroups', () => {
  it('groups by project, sorted by name, worst severity wins per asset', () => {
    const groups = buildGroups(
      [asset('zeta', 'h1'), asset('alpha', 'h1'), asset('alpha', 'h2')],
      [finding('alpha', 'MEDIUM', ['h1']), finding('alpha', 'CRITICAL', ['h1']), finding('alpha', 'low', ['h2'])],
    )
    expect(groups.map((g) => g.projectName)).toEqual(['alpha', 'zeta'])
    const [h1, h2] = groups[0].nodes
    expect(h1).toMatchObject({ id: 'p-alpha/h1', status: 'critical', findings: 2 })
    expect(h2).toMatchObject({ status: 'low', findings: 1 })
    expect(groups[1].nodes[0]).toMatchObject({ status: 'clear', findings: 0 })
  })
  it('does not attribute a finding to a same-id asset in another project', () => {
    const groups = buildGroups([asset('a', 'h1'), asset('b', 'h1')], [finding('a', 'HIGH', ['h1'])])
    expect(groups.find((g) => g.projectName === 'b')?.nodes[0].status).toBe('clear')
  })
  it('treats an unknown severity as low rather than clear', () => {
    expect(buildGroups([asset('a', 'h1')], [finding('a', 'INFO', ['h1'])])[0].nodes[0].status).toBe('low')
  })
})

describe('eventTone', () => {
  it('classifies outcomes', () => {
    expect(eventTone(ev(1, 'task.failed', 't'))).toBe('bad')
    expect(eventTone(ev(1, 'task.completed', 't', { status: 'SUCCEEDED' }))).toBe('ok')
    expect(eventTone(ev(1, 'task.completed', 't', { status: 'SUCCEEDED', warning_codes: ['W'] }))).toBe('warn')
    expect(eventTone(ev(1, 'task.completed', 't', { status: 'FAILED' }))).toBe('bad')
    expect(eventTone(ev(1, 'phase.changed', 't', { to: 'ASSURANCE' }))).toBe('ai')
    expect(eventTone(ev(1, 'phase.changed', 't', { to: 'COLLECTING' }))).toBe('info')
    expect(eventTone(ev(1, 'report.ready', 't'))).toBe('ok')
  })
})

describe('mergeFeed', () => {
  it('merges runs newest first, de-duplicates by event id and honours the limit', () => {
    const a = run('ra', 'alpha')
    const b = run('rb', 'beta')
    const feed = mergeFeed([
      { run: a, events: [ev(1, 'task.started', '2026-10-18T10:00:00Z'), ev(2, 'report.ready', '2026-10-18T10:05:00Z')] },
      { run: b, events: [ev(3, 'task.failed', '2026-10-18T10:03:00Z'), ev(1, 'task.started', '2026-10-18T10:00:00Z')] },
    ])
    expect(feed.map((f) => f.key)).toEqual(['e2', 'e3', 'e1'])
    expect(feed[1]).toMatchObject({ runId: 'rb', projectName: 'beta', tone: 'bad' })
    expect(feed.every((f) => f.text.length > 0)).toBe(true)
    expect(mergeFeed([{ run: a, events: [ev(1, 'x', 'a'), ev(2, 'x', 'b')] }], 1)).toHaveLength(1)
  })
})

describe('truncationNotes', () => {
  it('says nothing when everything is loaded', () => {
    expect(truncationNotes({ shown: 7, total: 7 }, { shown: 5, total: 5 })).toEqual([])
    expect(truncationNotes({ shown: 0, total: 0 }, null)).toEqual([])
  })
  it('names how many assets and findings are left out', () => {
    const [a, f] = truncationNotes({ shown: 200, total: 1234 }, { shown: 200, total: 950 })
    expect(a).toBe('Showing 200 of 1,234 tracked assets, the first by project, asset type and asset id.')
    expect(f).toMatch(/^Severity colours use the 200 most severe of 950 accepted findings/)
  })
  it('makes no claim about findings the user may not read', () => {
    expect(truncationNotes({ shown: 200, total: 300 }, null)).toHaveLength(1)
  })
})

describe('pulseFor', () => {
  it('only animates events a probe would produce', () => {
    expect(pulseFor('task.started', 'info')).toBe('probe')
    expect(pulseFor('evidence.batch.stored', 'ok')).toBe('return')
    expect(pulseFor('task.failed', 'bad')).toBe('fault')
    expect(pulseFor('report.ready', 'ok')).toBe('core')
    expect(pulseFor('exception.granted', 'info')).toBeNull()
  })
})
