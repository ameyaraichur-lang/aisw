import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { api, ApiError, newIdempotencyKey } from '../api/client'
import { useInventory, useProjects } from '../api/hooks'
import { Banner, DataState, PageHeader } from '../components/ui'
import { useSession } from '../auth/useSession'

export function Projects() {
  const { can } = useSession()
  const projects = useProjects()
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [env, setEnv] = useState('test')
  const create = useMutation({
    mutationFn: () => api('/projects', { method: 'POST', body: { name, environment: env }, headers: { 'Idempotency-Key': newIdempotencyKey() } }),
    onSuccess: () => { setName(''); void qc.invalidateQueries({ queryKey: ['projects'] }) },
  })
  const [open, setOpen] = useState<string | null>(null)
  return (
    <>
      <PageHeader title="Projects & Environments" lead="A project scopes inventory, manifests and runs for one environment." />
      {can('project:create') ? (
        <form className="stack panel" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }} aria-label="Create project">
          <h2>Create project</h2>
          <div><label htmlFor="pn">Project name</label><input id="pn" required value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div><label htmlFor="pe">Environment</label>
            <select id="pe" value={env} onChange={(e) => setEnv(e.target.value)}>
              <option value="test">test</option><option value="staging">staging</option><option value="production">production</option>
            </select></div>
          {create.isError ? <Banner tone="bad" role="alert" title="Could not create project">{(create.error as ApiError).message}</Banner> : null}
          <div><button type="submit" className="btn btn--primary" disabled={create.isPending || !name}>{create.isPending ? 'Creating…' : 'Create project'}</button></div>
        </form>
      ) : <p className="muted">Your role cannot create projects.</p>}
      <h2>Projects</h2>
      <DataState q={projects} label="projects" isEmpty={(d) => d.length === 0} empty={<p className="muted">No projects yet.</p>}>
        {(d) => (
          <div className="table-wrap">
            <table>
              <caption>Projects in your tenant</caption>
              <thead><tr><th scope="col">Name</th><th scope="col">Environment</th><th scope="col">Owner</th><th scope="col">Created by</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {d.map((p) => (
                  <tr key={p.project_id}>
                    <td>{p.name}</td><td>{p.environment}</td><td>{p.owner ?? <span className="muted">unknown</span>}</td><td>{p.created_by}</td>
                    <td><button type="button" className="btn btn--small" aria-expanded={open === p.project_id} onClick={() => setOpen(open === p.project_id ? null : p.project_id)}>{open === p.project_id ? 'Hide inventory' : 'Inventory'}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </DataState>
      {open ? <InventoryPanel projectId={open} /> : null}
    </>
  )
}

function InventoryPanel({ projectId }: { projectId: string }) {
  const { can } = useSession()
  const inv = useInventory(projectId)
  const qc = useQueryClient()
  const [kind, setKind] = useState('asset_group')
  const [selector, setSelector] = useState('')
  const [expected, setExpected] = useState('')
  const add = useMutation({
    mutationFn: () => api('/inventory', { method: 'POST', body: { project_id: projectId, kind, selector, expected_assets: expected.split(/[\s,]+/).filter(Boolean) } }),
    onSuccess: () => { setSelector(''); setExpected(''); void qc.invalidateQueries({ queryKey: ['inventory', projectId] }) },
  })
  return (
    <section className="panel" aria-label="Inventory">
      <h2>Inventory sources</h2>
      <p className="hint">Targets must resolve against this inventory before any scope can be approved. Expected assets are the reference for coverage.</p>
      <DataState q={inv} label="inventory" isEmpty={(d) => d.length === 0} empty={<p className="muted">No inventory registered for this project.</p>}>
        {(d) => (
          <table><caption>Registered inventory</caption>
            <thead><tr><th scope="col">Kind</th><th scope="col">Selector</th><th scope="col">Expected assets</th></tr></thead>
            <tbody>{d.map((e) => <tr key={e.kind + e.selector}><td>{e.kind}</td><td><code>{e.selector}</code></td><td>{e.expected_assets.length ? e.expected_assets.join(', ') : <span className="muted">none declared</span>}</td></tr>)}</tbody>
          </table>
        )}
      </DataState>
      {can('inventory:manage') ? (
        <form className="stack" onSubmit={(e) => { e.preventDefault(); add.mutate() }} aria-label="Add inventory entry">
          <h3>Add inventory entry</h3>
          <div><label htmlFor="ik">Kind</label>
            <select id="ik" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="asset_group">asset_group</option><option value="url">url</option><option value="host">host</option><option value="cidr">cidr</option>
            </select></div>
          <div><label htmlFor="is">Selector</label><input id="is" required value={selector} onChange={(e) => setSelector(e.target.value)} /></div>
          <div><label htmlFor="ie">Expected assets (comma or space separated)</label><textarea id="ie" rows={2} value={expected} onChange={(e) => setExpected(e.target.value)} /></div>
          {add.isError ? <Banner tone="bad" role="alert" title="Could not add entry">{(add.error as ApiError).message}</Banner> : null}
          <div><button type="submit" className="btn" disabled={add.isPending || !selector}>Add entry</button></div>
        </form>
      ) : null}
    </section>
  )
}
