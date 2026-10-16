import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, ApiError } from '../api/client'
import { useManifests } from '../api/hooks'
import type { ManifestSummary } from '../api/types'
import { Badge, Banner, ConfirmDialog, DataState, PageHeader, ShortHash } from '../components/ui'
import { fmtTime } from '../lib/format'

export function Approvals() {
  const q = useManifests({ status: 'PREFLIGHTED' })
  return (
    <>
      <PageHeader title="Pending approvals" lead="A manifest must be approved by someone other than its requester before any tool can run. Approval signs the exact content hash." />
      <DataState q={q} label="manifests awaiting approval" isEmpty={(d) => d.length === 0} empty={<p className="muted">Nothing is waiting for approval.</p>}>
        {(d) => <ul className="list-plain">{d.map((m) => <li key={m.manifest_id}><ApprovalCard m={m} /></li>)}</ul>}
      </DataState>
    </>
  )
}

function ApprovalCard({ m }: { m: ManifestSummary }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [ack, setAck] = useState<string[]>([])
  const approve = useMutation({
    mutationFn: () => api(`/scope-manifests/${m.manifest_id}/approve`, { method: 'POST', body: { acknowledge_active_adapters: ack } }),
    onSuccess: () => { setOpen(false); void qc.invalidateQueries({ queryKey: ['manifests'] }) },
  })
  const needAck = m.active_profiles.length > 0
  const err = approve.error instanceof ApiError ? approve.error : null
  return (
    <section className="panel" aria-label={`Manifest ${m.project_name} v${m.version}`}>
      <h2>{m.project_name} <span className="muted">v{m.version}</span></h2>
      <dl className="kv">
        <dt>Requested by</dt><dd>{m.created_by} at {fmtTime(m.created_at)}</dd>
        <dt>Targets</dt><dd>{m.targets.join(', ')}</dd>
        <dt>Exclusions</dt><dd>{m.exclusions.length ? m.exclusions.join(', ') : 'none'}</dd>
        <dt>Adapters / profiles</dt>
        <dd>{Object.entries(m.profiles).map(([a, p]) => (
          <span key={a} className="row"><code>{a}</code> <code>{p.profile_id}</code> {p.profile_class === 'ACTIVE' ? <Badge d={{ icon: '⚠', label: 'Active check', tone: 'warn' }} /> : <Badge d={{ icon: '👁', label: 'Read-only', tone: 'ok' }} />}</span>
        ))}</dd>
        <dt>Policy pack</dt><dd><code>{m.policy_version}</code></dd>
        <dt>Limits</dt><dd>{m.quotas.max_concurrency} concurrent, {m.quotas.max_requests} requests, {m.quotas.max_duration_seconds}s; evidence kept {m.evidence_retention_days} days</dd>
        <dt>Expires</dt><dd>{fmtTime(m.expires_at)}</dd>
        <dt>Content hash</dt><dd><ShortHash value={m.canonical_hash} /> (this exact content is what you sign)</dd>
      </dl>
      {err ? <Banner tone="bad" role="alert" title={err.status === 403 ? 'You cannot approve this manifest' : 'Approval refused'}>{err.reasonCodes.join(', ') || err.message}</Banner> : null}
      <p><button type="button" className="btn btn--primary" onClick={() => { setAck([]); setOpen(true) }}>Review and approve</button></p>
      <ConfirmDialog open={open} title="Approve and sign this scope" confirmLabel="Approve and sign" busy={approve.isPending} confirmDisabled={needAck && ack.length !== m.active_profiles.length} onConfirm={() => approve.mutate()} onCancel={() => setOpen(false)}>
        <p>You are approving targets <strong>{m.targets.join(', ')}</strong> for adapters <strong>{m.adapters.join(', ')}</strong>.</p>
        {needAck ? (
          <fieldset>
            <legend>Active (intrusive) profiles need explicit acknowledgement</legend>
            {m.active_profiles.map((a) => (
              <label key={a} className="inline-check"><input type="checkbox" checked={ack.includes(a)} onChange={(e) => setAck(e.target.checked ? [...ack, a] : ack.filter((x) => x !== a))} /> I authorise the active profile of <code>{a}</code> against these exact targets</label>
            ))}
          </fieldset>
        ) : <p>All profiles are read-only.</p>}
      </ConfirmDialog>
    </section>
  )
}
