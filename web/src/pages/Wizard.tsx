import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api, ApiError, newIdempotencyKey } from '../api/client'
import { useConnectors, useInventory, useManifests, usePolicyPacks, useProjects } from '../api/hooks'
import type { Connector, GateResult, InventoryEntry, ManifestSummary, PolicyPackInfo } from '../api/types'
import { useSession } from '../auth/useSession'
import { Badge, Banner, ConfirmDialog, DataState, ErrorView, PageHeader, ShortHash } from '../components/ui'
import { fmtTime } from '../lib/format'

const STEPS = ['Project', 'Scope', 'Adapters & profiles', 'Guardrails', 'Preflight', 'Review & launch'] as const

interface Form {
  projectId: string
  targets: string[] // "kind|selector"
  exclusions: { kind: string; selector: string }[]
  adapters: string[]
  profileByAdapter: Record<string, string>
  policy: string
  concurrency: number
  maxRequests: number
  maxDuration: number
  retention: number
  expiresHours: number
  ports: string
  windowStart: string
  windowEnd: string
}
const INITIAL: Form = {
  projectId: '', targets: [], exclusions: [], adapters: [], profileByAdapter: {}, policy: '',
  concurrency: 1, maxRequests: 100, maxDuration: 3600, retention: 30, expiresHours: 24,
  ports: '', windowStart: '', windowEnd: '',
}

export function Wizard() {
  const [params] = useSearchParams()
  const resume = params.get('manifest')
  const { can } = useSession()
  const [step, setStep] = useState(resume ? 5 : 0)
  const [form, setForm] = useState<Form>(INITIAL)
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }))
  const [manifestId, setManifestId] = useState<string | null>(resume)

  const projects = useProjects()
  const connectors = useConnectors()
  const packs = usePolicyPacks()
  const inv = useInventory(form.projectId || undefined)

  const policy = form.policy || packs.data?.find((p) => p.runnable)?.key || ''

  const targets = useMemo(() => form.targets.map((t) => { const [kind, ...r] = t.split('|'); return { kind, selector: r.join('|') } }), [form.targets])
  const usable = useMemo(
    () => (connectors.data ?? []).filter((c) => c.enabled && c.permission_ok && targets.some((t) => c.target_kinds.includes(t.kind))),
    [connectors.data, targets],
  )
  const valid: Record<number, string | null> = {
    0: form.projectId ? null : 'Choose a project.',
    1: targets.length ? null : 'Select at least one target from the inventory.',
    2: form.adapters.length && form.adapters.every((a) => form.profileByAdapter[a]) ? null : 'Choose an adapter and a profile for it.',
    3: policy ? null : 'Choose a policy pack.',
  }

  return (
    <>
      <PageHeader title="New assessment" lead="No tool runs until the exact scope is reviewed, approved by someone else, and you press Start." />
      <ol className="steps" aria-label="Wizard steps">
        {STEPS.map((s, i) => (
          <li key={s} aria-current={i === step ? 'step' : undefined} className={i < step ? 'done' : ''}>{i + 1}. {s}{i < step ? ' ✓' : ''}</li>
        ))}
      </ol>
      <section aria-labelledby="step-title" className="panel">
        <h2 id="step-title">{STEPS[step]}</h2>
        {step === 0 && (
          <DataState q={projects} label="projects" isEmpty={(d) => d.length === 0} empty={<p>No projects. <Link to="/projects">Create one first</Link>.</p>}>
            {(d) => (
              <div>
                <label htmlFor="proj">Project and environment</label>
                <select id="proj" value={form.projectId} onChange={(e) => setForm({ ...INITIAL, policy: form.policy, projectId: e.target.value })}>
                  <option value="">Select…</option>
                  {d.map((p) => <option key={p.project_id} value={p.project_id}>{p.name} ({p.environment})</option>)}
                </select>
                {form.projectId ? <p className="hint">Environment classification: <strong>{d.find((p) => p.project_id === form.projectId)?.environment}</strong>. Owner: {d.find((p) => p.project_id === form.projectId)?.owner ?? 'unknown (not inferred)'}.</p> : null}
              </div>
            )}
          </DataState>
        )}
        {step === 1 && <ScopeStep form={form} set={set} inv={inv} />}
        {step === 2 && <AdapterStep form={{ ...form, policy }} set={set} usable={usable} loading={connectors.isPending} packs={packs.data ?? []} />}
        {step === 3 && <GuardrailStep form={form} set={set} hasUrl={targets.some((t) => t.kind === 'url')} />}
        {step === 4 && <PreflightStep form={{ ...form, policy }} targets={targets} manifestId={manifestId} setManifestId={setManifestId} connectors={connectors.data ?? []} onReady={() => setStep(5)} />}
        {step === 5 && manifestId && <ReviewStep manifestId={manifestId} can={can('assessment:launch')} />}
        {step === 5 && !manifestId && <Banner tone="warn" title="No manifest selected">Run preflight first.</Banner>}
        {valid[step] ? <p className="field-error" role="alert">{valid[step]}</p> : null}
      </section>
      <div className="row" style={{ marginTop: '1rem' }}>
        <button type="button" className="btn" disabled={step === 0 || (!!resume && step === 5)} onClick={() => setStep(step - 1)}>Back</button>
        {step < 4 ? <button type="button" className="btn btn--primary" disabled={!!valid[step]} onClick={() => setStep(step + 1)}>Next</button> : null}
        {step === 4 && manifestId ? <button type="button" className="btn btn--primary" onClick={() => setStep(5)}>Continue to review</button> : null}
      </div>
    </>
  )
}

type SetFn = <K extends keyof Form>(k: K, v: Form[K]) => void

function ScopeStep({ form, set, inv }: { form: Form; set: SetFn; inv: ReturnType<typeof useInventory> }) {
  const [kind, setKind] = useState('url')
  const [sel, setSel] = useState('')
  return (
    <>
      <p className="hint">Targets must exist in the project's inventory; free-form or wildcard targets are refused by the gate.</p>
      <DataState q={inv} label="inventory" isEmpty={(d) => d.length === 0} empty={<Banner tone="warn" title="No inventory registered">Register inventory on the <Link to="/projects">Projects</Link> page first.</Banner>}>
        {(d: InventoryEntry[]) => (
          <fieldset>
            <legend>Targets (resolution preview)</legend>
            {d.map((e) => {
              const key = `${e.kind}|${e.selector}`
              return (
                <label key={key} className="inline-check">
                  <input type="checkbox" checked={form.targets.includes(key)} onChange={(ev) => set('targets', ev.target.checked ? [...form.targets, key] : form.targets.filter((x) => x !== key))} />
                  <span><code>{e.kind}</code> <code>{e.selector}</code> resolves to <code>{e.resolved_id}</code>; {e.expected_assets.length} expected asset(s)</span>
                </label>
              )
            })}
          </fieldset>
        )}
      </DataState>
      <fieldset>
        <legend>Exclusions (always win over targets)</legend>
        {form.exclusions.length === 0 ? <p className="muted">None.</p> : (
          <ul className="list-plain">{form.exclusions.map((x, i) => (
            <li key={i} className="row"><code>{x.kind}</code> <code>{x.selector}</code>
              <button type="button" className="btn btn--small" onClick={() => set('exclusions', form.exclusions.filter((_, j) => j !== i))} aria-label={`Remove exclusion ${x.selector}`}>Remove</button></li>))}</ul>)}
        <div className="row">
          <div><label htmlFor="xk">Kind</label><select id="xk" value={kind} onChange={(e) => setKind(e.target.value)}><option>url</option><option>host</option><option>cidr</option><option>asset_group</option></select></div>
          <div><label htmlFor="xs">Selector</label><input id="xs" value={sel} onChange={(e) => setSel(e.target.value)} /></div>
          <div><button type="button" className="btn" disabled={!sel} onClick={() => { set('exclusions', [...form.exclusions, { kind, selector: sel }]); setSel('') }}>Add exclusion</button></div>
        </div>
      </fieldset>
    </>
  )
}

function AdapterStep({ form, set, usable, loading, packs }: { form: Form; set: SetFn; usable: Connector[]; loading: boolean; packs: PolicyPackInfo[] }) {
  if (loading) return <p role="status" className="muted">Loading adapters…</p>
  return (
    <>
      {usable.length === 0 ? <Banner tone="warn" title="No compatible adapter">No enabled, permission-verified adapter supports the selected target kinds. Unavailable tools are never assumed.</Banner> : null}
      {usable.map((c) => {
        const on = form.adapters.includes(c.adapter_id)
        return (
          <fieldset key={c.adapter_id}>
            <legend>{c.adapter_id} <span className="muted">v{c.version}; domains {c.domains.join(', ')}</span></legend>
            <label className="inline-check"><input type="checkbox" checked={on} onChange={(e) => set('adapters', e.target.checked ? [...form.adapters, c.adapter_id] : form.adapters.filter((a) => a !== c.adapter_id))} /> Use this adapter</label>
            {on ? (
              <div>
                <label htmlFor={`prof-${c.adapter_id}`}>Profile</label>
                <select id={`prof-${c.adapter_id}`} value={form.profileByAdapter[c.adapter_id] ?? ''} onChange={(e) => set('profileByAdapter', { ...form.profileByAdapter, [c.adapter_id]: e.target.value })}>
                  <option value="">Select…</option>
                  {c.profiles.map((p) => <option key={p.profile_id} value={p.profile_id}>{p.profile_id} ({p.profile_class === 'READ_ONLY' ? 'read-only' : 'ACTIVE check'})</option>)}
                </select>
                {c.profiles.find((p) => p.profile_id === form.profileByAdapter[c.adapter_id])?.profile_class === 'ACTIVE' ? (
                  <Banner tone="warn" title="Active (intrusive) profile">An approver must explicitly acknowledge this profile. It is never reused for other targets.</Banner>
                ) : null}
              </div>
            ) : null}
          </fieldset>
        )
      })}
      <div>
        <label htmlFor="pack">Policy pack (pinned and hashed for this run)</label>
        <select id="pack" value={form.policy} onChange={(e) => set('policy', e.target.value)}>
          {packs.map((p) => <option key={p.key} value={p.key} disabled={!p.runnable}>{p.key}{p.runnable ? '' : ' (needs the OPA policy engine)'}</option>)}
        </select>
        <p className="hint">{packs.find((p) => p.key === form.policy)?.description}</p>
      </div>
    </>
  )
}

function GuardrailStep({ form, set, hasUrl }: { form: Form; set: SetFn; hasUrl: boolean }) {
  const num = (k: keyof Form, label: string, min: number, max: number, hint: string) => (
    <div>
      <label htmlFor={`g-${k}`}>{label}</label>
      <input id={`g-${k}`} type="number" min={min} max={max} value={form[k] as number} onChange={(e) => set(k, Number(e.target.value) as never)} />
      <p className="hint">{hint}</p>
    </div>
  )
  return (
    <div className="stack">
      {num('concurrency', 'Maximum concurrency', 1, 32, 'Defaults come from policy; the server refuses values above its hard cap.')}
      {num('maxRequests', 'Request budget', 1, 1000000, 'Upper bound on tool requests for the whole run.')}
      {num('maxDuration', 'Maximum duration (seconds)', 1, 86400, 'The run is bounded in time.')}
      {num('retention', 'Evidence retention (days)', 1, 3650, 'How long raw evidence is kept.')}
      {num('expiresHours', 'Manifest validity (hours)', 1, 168, 'After this the approval expires and a new manifest is required.')}
      {hasUrl ? (
        <div>
          <label htmlFor="ports">Approved ports for URL targets</label>
          <input id="ports" value={form.ports} placeholder="443" onChange={(e) => set('ports', e.target.value)} />
          <p className="hint">Comma separated. A URL on any other port is refused.</p>
        </div>
      ) : null}
      <fieldset>
        <legend>Maintenance window (optional)</legend>
        <div className="row">
          <div><label htmlFor="ws">Start</label><input id="ws" type="datetime-local" value={form.windowStart} onChange={(e) => set('windowStart', e.target.value)} /></div>
          <div><label htmlFor="we">End</label><input id="we" type="datetime-local" value={form.windowEnd} onChange={(e) => set('windowEnd', e.target.value)} /></div>
        </div>
      </fieldset>
    </div>
  )
}

function PreflightStep({ form, targets, manifestId, setManifestId, connectors, onReady }: { form: Form; targets: { kind: string; selector: string }[]; manifestId: string | null; setManifestId: (id: string) => void; connectors: Connector[]; onReady: () => void }) {
  const qc = useQueryClient()
  const [result, setResult] = useState<GateResult | null>(null)
  const [denied, setDenied] = useState<ApiError | null>(null)
  const profiles = Object.fromEntries(form.adapters.map((a) => {
    const cap = connectors.find((c) => c.adapter_id === a)
    const pid = form.profileByAdapter[a]
    return [a, { profile_id: pid, profile_class: cap?.profiles.find((p) => p.profile_id === pid)?.profile_class ?? 'READ_ONLY' }]
  }))
  const domains = [...new Set(form.adapters.flatMap((a) => connectors.find((c) => c.adapter_id === a)?.domains ?? []))]
  const payload = {
    project_id: form.projectId,
    targets: targets.map((t) => ({ kind: t.kind, selector: t.selector })),
    exclusions: form.exclusions,
    domains, allowed_adapters: form.adapters, profiles,
    allowed_ports: form.ports.split(/[\s,]+/).filter(Boolean).map(Number),
    windows: form.windowStart && form.windowEnd ? [{ start: new Date(form.windowStart).toISOString(), end: new Date(form.windowEnd).toISOString() }] : [],
    quotas: { max_concurrency: form.concurrency, max_requests: form.maxRequests, max_duration_seconds: form.maxDuration },
    evidence_retention_days: form.retention,
    policy_version: form.policy,
  }
  const run = useMutation({
    mutationFn: async () => {
      const body = { ...payload, expires_at: new Date(Date.now() + form.expiresHours * 3600_000).toISOString() }
      const created = await api<{ manifest: { manifest_id: string } }>('/scope-manifests', { method: 'POST', body })
      const id = created.manifest.manifest_id
      const pf = await api<GateResult>(`/scope-manifests/${id}/preflight`, { method: 'POST' })
      return { id, pf }
    },
    onMutate: () => { setDenied(null); setResult(null) },
    onSuccess: ({ id, pf }) => { setManifestId(id); setResult(pf); void qc.invalidateQueries({ queryKey: ['manifests'] }) },
    onError: (e) => { if (e instanceof ApiError) setDenied(e); },
  })
  return (
    <>
      <p>Preflight validates connector permissions, scope resolution, wildcards, exclusions, network safety and policy caps on the server. Nothing is executed.</p>
      <button type="button" className="btn btn--primary" onClick={() => run.mutate()} disabled={run.isPending}>{run.isPending ? 'Running preflight…' : manifestId ? 'Re-run preflight (creates a new version)' : 'Run preflight'}</button>
      {denied ? (
        <div role="alert" className="banner banner--bad">
          <strong>Preflight blocked</strong>
          <p>{denied.status === 403 ? 'Your role is not permitted to do this.' : 'The gate refused this scope. Nothing was stored or run.'}</p>
          <ul>{(denied.issues.length ? denied.issues : denied.reasonCodes.map((c) => ({ code: c, severity: 'BLOCKING', detail: '' }))).map((i, n) => (
            <li key={n}><Badge d={i.severity === 'BLOCKING' ? { icon: '✕', label: 'Blocking', tone: 'bad' } : { icon: '!', label: 'Warning', tone: 'warn' }} /> <code>{i.code}</code> {i.detail}</li>
          ))}</ul>
          <p>Fix the scope and run preflight again.</p>
        </div>
      ) : null}
      {result ? (
        <div className="panel" role="status">
          <h3>Preflight result: {result.decision.decision === 'APPROVAL_REQUIRED' ? 'valid, approval required' : result.decision.decision}</h3>
          <ul className="list-plain">
            <li><Badge d={{ icon: '✓', label: 'Passed', tone: 'ok' }} /> Scope resolved, no wildcard, exclusions applied, network checks passed</li>
            {result.issues.map((i, n) => <li key={n}><Badge d={i.severity === 'BLOCKING' ? { icon: '✕', label: 'Blocking', tone: 'bad' } : { icon: '!', label: 'Warning', tone: 'warn' }} /> <code>{i.code}</code> {i.detail}</li>)}
            <li><Badge d={{ icon: '◐', label: 'Required', tone: 'warn' }} /> Approval by a different user with the approver role</li>
          </ul>
          <button type="button" className="btn btn--primary" onClick={onReady}>Continue to review</button>
        </div>
      ) : null}
    </>
  )
}

function ReviewStep({ manifestId, can }: { manifestId: string; can: boolean }) {
  const nav = useNavigate()
  const qc = useQueryClient()
  const list = useManifests({})
  const m: ManifestSummary | undefined = list.data?.find((x) => x.manifest_id === manifestId)
  const [fixtureSet, setFixtureSet] = useState('baseline-ok')
  const [confirm, setConfirm] = useState(false)
  const keyRef = useRef<{ sig: string; key: string }>({ sig: '', key: newIdempotencyKey() })
  const launch = useMutation({
    mutationFn: () => {
      const body = {
        project_id: m!.project_id, scope_manifest_id: m!.manifest_id, scope_manifest_hash: m!.canonical_hash,
        assessment_profile: 'baseline-readonly-v1',
        adapter_params: m!.adapters.includes('fixture') ? { fixture: { fixture_set: fixtureSet } } : {},
      }
      const sig = JSON.stringify(body)
      if (keyRef.current.sig !== sig) keyRef.current = { sig, key: keyRef.current.sig ? newIdempotencyKey() : keyRef.current.key }
      return api<{ run_id: string }>('/assessments', { method: 'POST', body, headers: { 'Idempotency-Key': keyRef.current.key } })
    },
    onSuccess: (r) => { void qc.invalidateQueries({ queryKey: ['runs'] }); nav(`/assessments/${r.run_id}`) },
  })
  return (
    <DataState q={list} label="manifest">
      {() => {
        if (!m) return <ErrorView error={new ApiError(404, null, 'manifest')} />
        const approved = m.status === 'APPROVED'
        const err = launch.error instanceof ApiError ? launch.error : null
        return (
          <>
            <dl className="kv">
              <dt>Project</dt><dd>{m.project_name}</dd>
              <dt>Manifest</dt><dd>version {m.version}, hash <ShortHash value={m.canonical_hash} /></dd>
              <dt>Exact targets</dt><dd>{m.targets.join(', ')}</dd>
              <dt>Exclusions</dt><dd>{m.exclusions.length ? m.exclusions.join(', ') : 'none'}</dd>
              <dt>Adapters and profiles</dt>
              <dd>{Object.entries(m.profiles).map(([a, p]) => <span key={a} className="row"><code>{a}</code> <code>{p.profile_id}</code> {p.profile_class === 'ACTIVE' ? <Badge d={{ icon: '⚠', label: 'Active check', tone: 'warn' }} /> : <Badge d={{ icon: '👁', label: 'Read-only', tone: 'ok' }} />}</span>)}</dd>
              <dt>Policy pack</dt><dd><code>{m.policy_version}</code> (pinned)</dd>
              <dt>Limits</dt><dd>{m.quotas.max_concurrency} concurrent; {m.quotas.max_requests} requests; {m.quotas.max_duration_seconds}s; evidence kept {m.evidence_retention_days} days</dd>
              <dt>Expires</dt><dd>{fmtTime(m.expires_at)}</dd>
              <dt>Impact</dt><dd>{m.active_profiles.length ? 'Includes ACTIVE checks (explicitly approved).' : 'Read-only: collects configuration and inventory evidence; changes nothing.'}</dd>
              <dt>Approval</dt>
              <dd>{approved ? <span>Approved by {m.approved_by.join(', ')} <Badge d={{ icon: '✓', label: 'Approved and signed', tone: 'ok' }} /></span> : <Badge d={{ icon: '◐', label: m.status === 'PREFLIGHTED' ? 'Awaiting approval' : m.status, tone: 'warn' }} />}</dd>
            </dl>
            {m.adapters.includes('fixture') ? (
              <div style={{ marginTop: '1rem' }}>
                <label htmlFor="fx">Fixture data set (synthetic scanner replay)</label>
                <select id="fx" value={fixtureSet} onChange={(e) => setFixtureSet(e.target.value)}>
                  <option value="baseline-ok">baseline-ok: all hosts scanned</option>
                  <option value="baseline-partial">baseline-partial: one unreachable, one unsupported, one unexpected</option>
                  <option value="baseline-zero">baseline-zero: tool reports success with zero assets</option>
                  <option value="baseline-injection">baseline-injection: hostile text and a secret in tool output</option>
                </select>
              </div>
            ) : null}
            {!approved ? (
              <Banner tone="warn" title="This scope cannot start yet">
                A different user with the approver role must approve it (see <em>Pending approvals</em>). Then refresh this page.{' '}
                <button type="button" className="btn btn--small" onClick={() => void list.refetch()}>Refresh status</button>
              </Banner>
            ) : null}
            {err ? <Banner tone="bad" role="alert" title="Start refused">{err.reasonCodes.join(', ') || err.message}. No tool was run.</Banner> : null}
            {!can ? <p className="muted">Your role cannot launch assessments.</p> : null}
            <p><button type="button" className="btn btn--primary" disabled={!approved || !can || launch.isPending} onClick={() => setConfirm(true)}>Start Assessment</button></p>
            <ConfirmDialog open={confirm} title="Start this assessment?" confirmLabel="Start Assessment" busy={launch.isPending} onConfirm={() => launch.mutate()} onCancel={() => setConfirm(false)}>
              <p>This will run <strong>{m.adapters.join(', ')}</strong> against <strong>{m.targets.join(', ')}</strong> using the signed manifest <ShortHash value={m.canonical_hash} />. The server re-checks the scope before every tool call.</p>
            </ConfirmDialog>
          </>
        )
      }}
    </DataState>
  )
}
