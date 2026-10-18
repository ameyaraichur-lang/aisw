// Pure data shaping for Mission Control: the 3D scene and the feed only ever show recorded facts.
import type { AssetRow, FindingRow, RunEvent, RunListItem } from '../api/types'
import { describeEvent } from './events'

export type NodeStatus = 'critical' | 'high' | 'medium' | 'low' | 'clear'
export const STATUS_RANK: Record<NodeStatus, number> = { critical: 4, high: 3, medium: 2, low: 1, clear: 0 }
export const STATUS_LABEL: Record<NodeStatus, string> = {
  critical: 'Critical finding', high: 'High finding', medium: 'Medium finding', low: 'Low finding',
  clear: 'No accepted findings',
}

export interface SceneNode {
  id: string // project_id/asset_id: asset ids are only unique within a project
  label: string
  kind: string
  projectId: string
  projectName: string
  status: NodeStatus
  findings: number
}

export interface SceneGroup {
  projectId: string
  projectName: string
  nodes: SceneNode[]
}

export function assetLabel(a: Pick<AssetRow, 'asset_id' | 'native_ids'>): string {
  const n = a.native_ids
  for (const k of ['hostname', 'ip', 'image', 'url', 'origin']) {
    const v = n[k]
    if (typeof v === 'string' && v) return v
  }
  return a.asset_id
}

function severityStatus(sev: string): NodeStatus {
  const s = sev.toLowerCase()
  return s === 'critical' || s === 'high' || s === 'medium' || s === 'low' ? s : 'low'
}

/** Groups assets by project; each node takes the worst severity among accepted findings naming it. */
export function buildGroups(assets: AssetRow[], findings: FindingRow[]): SceneGroup[] {
  const worst = new Map<string, { status: NodeStatus; count: number }>() // key: project name + asset id
  for (const f of findings) {
    for (const assetId of f.affected_assets) {
      const key = `${f.project_name}\u0000${assetId}`
      const cur = worst.get(key) ?? { status: 'clear' as NodeStatus, count: 0 }
      const s = severityStatus(f.severity)
      worst.set(key, { status: STATUS_RANK[s] > STATUS_RANK[cur.status] ? s : cur.status, count: cur.count + 1 })
    }
  }
  const groups = new Map<string, SceneGroup>()
  for (const a of assets) {
    const id = `${a.project_id}/${a.asset_id}`
    const g = groups.get(a.project_id) ?? { projectId: a.project_id, projectName: a.project_name, nodes: [] }
    const w = worst.get(`${a.project_name}\u0000${a.asset_id}`)
    g.nodes.push({
      id, label: assetLabel(a), kind: a.asset_type, projectId: a.project_id, projectName: a.project_name,
      status: w?.status ?? 'clear', findings: w?.count ?? 0,
    })
    groups.set(a.project_id, g)
  }
  return [...groups.values()].sort((x, y) => x.projectName.localeCompare(y.projectName))
}

export type Tone = 'info' | 'ok' | 'warn' | 'bad' | 'ai'
export interface FeedItem {
  key: string
  runId: string
  projectId: string
  projectName: string
  at: string
  type: string
  text: string
  tone: Tone
}

export function eventTone(e: RunEvent): Tone {
  if (e.type === 'task.failed' || e.type === 'assessment.cancelled') return 'bad'
  if (e.type === 'task.partial' || e.type === 'report.partial') return 'warn'
  if (e.type === 'task.completed') {
    const p = e.payload
    if (p.status === 'FAILED') return 'bad'
    if (p.status === 'PARTIAL' || (Array.isArray(p.warning_codes) && p.warning_codes.length)) return 'warn'
    return 'ok'
  }
  if (e.type === 'evidence.batch.stored' || e.type === 'report.ready' || e.type === 'assessment.closed') return 'ok'
  if (e.type === 'phase.changed' && ['ARCHITECTURE_ANALYSIS', 'ASSURANCE'].includes(String(e.payload.to))) return 'ai'
  return 'info'
}

/** Newest first, de-duplicated by event id, each tagged with its run's project. */
export function mergeFeed(perRun: { run: RunListItem; events: RunEvent[] }[], limit = 60): FeedItem[] {
  const seen = new Set<string>()
  const out: FeedItem[] = []
  for (const { run, events } of perRun) {
    for (const e of events) {
      if (seen.has(e.event_id)) continue
      seen.add(e.event_id)
      out.push({
        key: e.event_id, runId: run.run_id, projectId: run.project_id, projectName: run.project_name,
        at: e.occurred_at, type: e.type, text: describeEvent(e), tone: eventTone(e),
      })
    }
  }
  out.sort((a, b) => (a.at === b.at ? b.key.localeCompare(a.key) : b.at.localeCompare(a.at)))
  return out.slice(0, limit)
}

export type PulseKind = 'probe' | 'return' | 'fault' | 'core'
/** How an event animates in the scene; null when it is not something a probe would do. */
export function pulseFor(type: string, tone: Tone): PulseKind | null {
  if (type === 'task.started' || type === 'task.queued') return 'probe'
  if (type === 'evidence.batch.stored') return 'return'
  if (tone === 'bad') return 'fault'
  if (type === 'report.ready' || type === 'report.partial' || type === 'phase.changed') return 'core'
  return null
}
