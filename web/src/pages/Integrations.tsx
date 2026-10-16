import { useConnectors, usePolicyPacks } from '../api/hooks'
import { Badge, DataState, PageHeader, ShortHash } from '../components/ui'

export function Integrations() {
  const c = useConnectors()
  const p = usePolicyPacks()
  return (
    <>
      <PageHeader title="Integrations & Collectors" lead="Registered adapters, what they may touch, and whether each is read-only." />
      <DataState q={c} label="connectors" isEmpty={(d) => d.length === 0} empty={<p className="muted">No adapters are registered.</p>}>
        {(d) => (
          <div className="table-wrap">
            <table>
              <caption>Adapter capability matrix</caption>
              <thead><tr><th scope="col">Adapter</th><th scope="col">Version</th><th scope="col">Domains</th><th scope="col">Target kinds</th><th scope="col">Profiles</th><th scope="col">Status</th></tr></thead>
              <tbody>
                {d.map((x) => (
                  <tr key={x.adapter_id}>
                    <td><strong>{x.adapter_id}</strong></td><td>{x.version}</td><td>{x.domains.join(', ')}</td><td>{x.target_kinds.join(', ')}</td>
                    <td><ul className="list-plain">{x.profiles.map((pr) => (
                      <li key={pr.profile_id}><code>{pr.profile_id}</code>{' '}
                        {pr.profile_class === 'READ_ONLY' ? <Badge d={{ icon: '👁', label: 'Read-only', tone: 'ok' }} /> : <Badge d={{ icon: '⚠', label: 'Active check (needs explicit approval)', tone: 'warn' }} />}
                      </li>))}</ul></td>
                    <td>
                      {x.enabled ? <Badge d={{ icon: '✓', label: 'Enabled', tone: 'ok' }} /> : <Badge d={{ icon: '✕', label: 'Disabled', tone: 'bad' }} />}{' '}
                      {x.permission_ok ? <Badge d={{ icon: '✓', label: 'Permissions verified', tone: 'ok' }} /> : <Badge d={{ icon: '✕', label: 'Permission check failed', tone: 'bad' }} />}
                      {' '}{x.read_only ? <Badge d={{ icon: '🔒', label: 'No change capability', tone: 'ok' }} /> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </DataState>
      <p className="hint">Collector heartbeats and connector permission re-validation are not implemented yet; the matrix reflects registration and the last recorded check.</p>
      <h2>Policy packs</h2>
      <DataState q={p} label="policy packs" isEmpty={(d) => d.length === 0}>
        {(d) => (
          <table><caption>Policy packs that a manifest may pin</caption>
            <thead><tr><th scope="col">Pack</th><th scope="col">Framework</th><th scope="col">Rules</th><th scope="col">Content hash</th></tr></thead>
            <tbody>{d.map((x) => <tr key={x.key}><td><code>{x.key}</code><div className="muted">{x.description}</div></td><td>{x.framework.name} {x.framework.version}</td><td>{x.rules}</td><td><ShortHash value={x.pack_hash} /></td></tr>)}</tbody>
          </table>
        )}
      </DataState>
    </>
  )
}
