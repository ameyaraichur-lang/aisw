import { expect, type APIRequestContext, type Page } from '@playwright/test'

export const GROUP = 'fixture-group-1'
let n = 0
const uniq = () => `${Date.now().toString(36)}${(n++).toString(36)}`

export async function api(request: APIRequestContext, user: string, method: 'get' | 'post', path: string, data?: unknown, headers: Record<string, string> = {}) {
  const res = await request[method](`/api/v1${path}`, { data, headers: { Authorization: `Bearer dev-${user}`, ...headers } })
  return res
}
export async function json<T = any>(res: Awaited<ReturnType<typeof api>>, status = 200): Promise<T> {
  expect(res.status(), await res.text()).toBe(status)
  return (await res.json()) as T
}

export async function seedProject(request: APIRequestContext, expected: string[] = ['host-1', 'host-2', 'host-3']) {
  const name = `e2e-${uniq()}`
  const p = await json(await api(request, 'alice', 'post', '/projects', { name, environment: 'test' }, { 'Idempotency-Key': uniq() }), 201)
  await json(await api(request, 'alice', 'post', '/inventory', { project_id: p.project_id, kind: 'asset_group', selector: GROUP, expected_assets: expected }), 201)
  return { projectId: p.project_id as string, name }
}

export function manifestPayload(projectId: string, over: Record<string, unknown> = {}) {
  return {
    project_id: projectId, targets: [{ kind: 'asset_group', selector: GROUP }], domains: ['host'],
    allowed_adapters: ['fixture'], profiles: { fixture: { profile_id: 'FIXTURE_BASELINE', profile_class: 'READ_ONLY' } },
    evidence_retention_days: 30, policy_version: 'fixture-baseline:1.0.0',
    expires_at: new Date(Date.now() + 86_400_000).toISOString(), ...over,
  }
}

export async function approvedManifest(request: APIRequestContext, projectId: string) {
  const created = await json(await api(request, 'alice', 'post', '/scope-manifests', manifestPayload(projectId)), 201)
  const id = created.manifest.manifest_id as string
  await json(await api(request, 'alice', 'post', `/scope-manifests/${id}/preflight`))
  return json(await api(request, 'bob', 'post', `/scope-manifests/${id}/approve`, {}))
}

export async function launch(request: APIRequestContext, projectId: string, m: { manifest_id: string; canonical_hash: string }, fixtureSet = 'baseline-ok', aiAssist = false) {
  const r = await json(
    await api(request, 'alice', 'post', '/assessments', {
      project_id: projectId, scope_manifest_id: m.manifest_id, scope_manifest_hash: m.canonical_hash,
      assessment_profile: 'baseline-readonly-v1', adapter_params: { fixture: { fixture_set: fixtureSet } }, ai_assist: aiAssist,
    }, { 'Idempotency-Key': uniq() }),
    202,
  )
  return r.run_id as string
}

export async function untilState(request: APIRequestContext, runId: string, states: string[], timeout = 40_000) {
  await expect.poll(async () => String((await (await api(request, 'alice', 'get', `/assessments/${runId}`)).json()).state), { timeout }).toMatch(new RegExp(`^(${states.join('|')})$`))
}

export const pause = (request: APIRequestContext) => request.post('http://127.0.0.1:8099/__e2e/pause')
export const resume = (request: APIRequestContext) => request.post('http://127.0.0.1:8099/__e2e/resume')

export async function signIn(page: Page, user: string) {
  await page.goto('/')
  await page.getByRole('button', { name: `Sign in as ${user}` }).click()
  await expect(page.getByLabel('Signed in user')).toContainText(user)
}
export async function signOut(page: Page) {
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible()
}

export const tab = (page: Page, name: string) =>
  page.getByRole('list', { name: 'Assessment sections' }).getByRole('link', { name, exact: true })

/** The wizard offers every compatible adapter; pick one by name. */
export const useAdapter = async (page: Page, adapter: string, profile: string) => {
  const group = page.getByRole('group', { name: new RegExp(`^${adapter}\\b`) })
  await group.getByRole('checkbox', { name: 'Use this adapter' }).check()
  await group.getByLabel('Profile', { exact: true }).selectOption(profile)
}
