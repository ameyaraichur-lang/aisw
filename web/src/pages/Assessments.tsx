import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useManifests, useRuns } from '../api/hooks'
import { Badge, DataState, PageHeader, Pagination, ShortHash } from '../components/ui'
import { useSession } from '../auth/useSession'
import { MANIFEST_BADGE } from '../lib/status'
import { RunsTable } from './CommandCenter'

export function Assessments() {
  const { can } = useSession()
  const [offset, setOffset] = useState(0)
  const runs = useRuns({ limit: 20, offset })
  const approved = useManifests({ status: 'APPROVED' })
  return (
    <>
      <PageHeader title="Assessments" lead="Runs are launched only from an approved, signed scope manifest.">
        {can('assessment:launch') || can('manifest:create') ? <Link className="btn btn--primary" to="/assessments/new">New assessment</Link> : null}
      </PageHeader>
      <h2>Approved scopes ready to launch</h2>
      <DataState q={approved} label="approved manifests" isEmpty={(d) => d.length === 0} empty={<p className="muted">No approved scope manifest. Create one with the wizard; a different user with the approver role must approve it.</p>}>
        {(d) => (
          <ul className="list-plain">
            {d.map((m) => (
              <li key={m.manifest_id} className="row">
                <strong>{m.project_name}</strong> v{m.version} <Badge d={MANIFEST_BADGE[m.status]} /> targets: {m.targets.join(', ')} hash <ShortHash value={m.canonical_hash} />
                {can('assessment:launch') ? <Link className="btn btn--small" to={`/assessments/new?manifest=${m.manifest_id}`}>Review and launch</Link> : null}
              </li>
            ))}
          </ul>
        )}
      </DataState>
      <h2>Run history</h2>
      <DataState q={runs} label="runs" isEmpty={(d) => d.items.length === 0} empty={<p className="muted">No runs yet.</p>}>
        {(d) => (
          <>
            <RunsTable items={d.items} />
            <Pagination total={d.total} limit={20} offset={offset} onChange={setOffset} />
          </>
        )}
      </DataState>
      <p className="hint">Times are UTC.</p>
    </>
  )
}

