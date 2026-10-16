import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { api, ApiError, newIdempotencyKey } from '../api/client'
import { useInventory, useProjectRoles, useProjects } from '../api/hooks'
import { Banner, DataState, PageHeader } from '../components/ui'
import { useSession } from '../auth/useSession'
import { fmtTime } from '../lib/format'

export function Projects() {
  const { can, me } = useSession()
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
              <caption>{can('project:read') && !me?.permissions.includes('project:read') ? 'Projects you hold a role on' : 'Projects in your tenant'}</caption>
              <thead><tr><th scope="col">Name</th><th scope="col">Environment</th><th scope="col">Owner</th><th scope="col">Created by</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {d.map((p) => (
                  <tr key={p.project_id}>
                    <td>{p.name}</td><td>{p.environment}</td><td>{p.owner ?? <span className="muted">unknown</span>}</td><td>{p.created_by}</td>
                    <td><button type="button" className="btn btn--small" aria-expanded={open === p.project_id} onClick={() => setOpen(open === p.project_id ? null : p.project_id)}>{open === p.project_id ? 'Hide details' : 'Inventory and roles'}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </DataState>
      {open ? <InventoryPanel projectId={open} /> : null}
      {open ? <RolesPanel projectId={open} /> : null}
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

const GRANTABLE: { role: string; label: string }[] = [
  { role: 'assessment_operator', label: 'Assessment operator (drafts scope, launches, uploads imports)' },
  { role: 'approver', label: 'Approver (approves scope, decides recommendations)' },
  { role: 'reviewer', label: 'Reviewer (triages findings, approves reports)' },
  { role: 'report_reader', label: 'Report reader (reads findings and reports)' },
]

function RolesPanel({ projectId }: { projectId: string }) {
  const { me } = useSession()
  const qc = useQueryClient()
  const roles = useProjectRoles(projectId)
  const [who, setWho] = useState('')
  const [role, setRole] = useState(GRANTABLE[0].role)
  const [reason, setReason] = useState('')
  const manage = !!me?.permissions.includes('project:members') // tenant-wide only, never via a grant
  const done = () => void qc.invalidateQueries({ queryKey: ['project-roles', projectId] })
  const grant = useMutation({
    mutationFn: () => api(`/projects/${projectId}/roles`, { method: 'POST', body: { actor_id: who.trim(), role, reason } }),
    onSuccess: () => { setWho(''); setReason('') },
    onSettled: done,
  })
  const revoke = useMutation({
    mutationFn: (grantId: string) => api(`/projects/${projectId}/roles/${grantId}/revoke`, { method: 'POST' }),
    onSettled: done,
  })
  const err = grant.error instanceof ApiError ? grant.error : null
  return (
    <section className="panel" aria-label="Project roles">
      <h2>Project roles</h2>
      <p className="hint">These roles apply to this project only, on top of anyone's tenant-wide roles. Tenant-wide duties (project admin, connector admin, auditor, policy owner) cannot be granted per project.</p>
      <DataState q={roles} label="project roles" isEmpty={(d) => d.length === 0} empty={<p className="muted">No project-only roles.</p>}>
        {(rows) => (
          <table data-testid="project-roles"><caption>Project-only roles</caption>
            <thead><tr><th scope="col">Person</th><th scope="col">Role</th><th scope="col">Reason</th><th scope="col">Granted</th>{manage ? <th scope="col"><span className="sr-only">Actions</span></th> : null}</tr></thead>
            <tbody>
              {rows.map((g) => (
                <tr key={g.grant_id}>
                  <td>{g.actor_id}</td><td>{g.role}</td><td>{g.reason}</td><td>{g.granted_by}, {fmtTime(g.granted_at)}</td>
                  {manage ? <td><button type="button" className="btn btn--small" disabled={revoke.isPending} onClick={() => revoke.mutate(g.grant_id)}>Revoke</button></td> : null}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </DataState>
      {manage ? (
        <form className="row" style={{ marginTop: '1rem' }} aria-label="Grant a project role" onSubmit={(e: FormEvent) => { e.preventDefault(); grant.mutate() }}>
          <label htmlFor="pr-who">Person (user id)</label>
          <input id="pr-who" value={who} onChange={(e) => setWho(e.target.value)} />
          <label htmlFor="pr-role">Role</label>
          <select id="pr-role" value={role} onChange={(e) => setRole(e.target.value)}>
            {GRANTABLE.map((g) => <option key={g.role} value={g.role}>{g.label}</option>)}
          </select>
          <label htmlFor="pr-why">Reason</label>
          <input id="pr-why" value={reason} maxLength={1000} onChange={(e) => setReason(e.target.value)} />
          <button type="submit" className="btn" disabled={!who.trim() || !reason.trim() || grant.isPending}>Grant role</button>
        </form>
      ) : null}
      {err ? <p className="field-error" role="alert">Grant refused: {err.message}</p> : null}
    </section>
  )
}
