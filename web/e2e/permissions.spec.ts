import { expect, test } from '@playwright/test'
import { api, approvedManifest, launch, resume, seedProject, signIn, untilState } from './helpers.ts'

test.afterEach(async ({ request }) => { await resume(request) })

test('navigation and routes reflect the role, and the server denies independently', async ({ page, request }) => {
  await signIn(page, 'carol') // report reader
  const nav = page.getByRole('navigation', { name: 'Main' })
  await expect(nav.getByRole('link', { name: 'Reports & Evidence' })).toBeVisible()
  await expect(nav.getByRole('link', { name: 'Pending approvals' })).toHaveCount(0)
  await expect(nav.getByRole('link', { name: 'Policy, Users & Audit' })).toHaveCount(0)
  for (const [path, title] of [['/audit', 'Policy, Users & Audit'], ['/approvals', 'Pending approvals'], ['/assessments/new', 'New assessment']]) {
    await page.goto(path)
    await expect(page.getByRole('heading', { name: title })).toBeVisible()
    await expect(page.getByRole('alert').filter({ hasText: 'Access denied' })).toBeVisible()
  }
  // hiding things is not the boundary: the API refuses the same requests outright
  expect((await api(request, 'carol', 'get', '/audit/events')).status()).toBe(403)
  expect((await api(request, 'carol', 'post', '/scope-manifests/00000000-0000-0000-0000-000000000000/approve', {})).status()).toBe(403)
  expect((await api(request, 'carol', 'post', '/projects', { name: 'x', environment: 'test' }, { 'Idempotency-Key': 'k' })).status()).toBe(403)
})

test('an approver cannot launch; an operator cannot read reports or approve', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  await signIn(page, 'bob')
  await page.goto(`/assessments/new?manifest=${m.manifest_id}`)
  await expect(page.getByRole('alert').filter({ hasText: 'Access denied' })).toBeVisible()
  const res = await api(request, 'bob', 'post', '/assessments', { project_id: projectId, scope_manifest_id: m.manifest_id, scope_manifest_hash: m.canonical_hash, assessment_profile: 'x' }, { 'Idempotency-Key': 'bob-1' })
  expect(res.status()).toBe(403)
  const runId = await launch(request, projectId, m)
  await untilState(request, runId, ['REPORT_READY'])
  expect((await api(request, 'alice', 'get', `/assessments/${runId}/reports`)).status()).toBe(403)
})

test('another tenant sees nothing: not found, no live updates, no data', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  const runId = await launch(request, projectId, m)
  await untilState(request, runId, ['REPORT_READY'])
  await signIn(page, 'dave') // tenant-b project admin
  await page.goto(`/assessments/${runId}/timeline`)
  await expect(page.getByRole('alert').filter({ hasText: 'Not found' }).first()).toBeVisible()
  await expect(page.getByRole('alert').filter({ hasText: 'Live updates are not permitted' })).toBeVisible()
  expect((await api(request, 'dave', 'get', `/assessments/${runId}/tasks`)).status()).toBe(404)
  await page.goto('/projects')
  await expect(page.getByText(/e2e-/)).toHaveCount(0) // tenant-a projects are invisible
})

test('expired or unknown identity returns to sign-in', async ({ page }) => {
  await page.goto('/')
  await page.evaluate(() => sessionStorage.setItem('aisw.dev.identity', 'nobody'))
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible()
})

test('double-clicking Start creates exactly one run', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  await signIn(page, 'alice')
  await page.goto(`/assessments/new?manifest=${m.manifest_id}`)
  await page.getByRole('button', { name: 'Start Assessment' }).click()
  const confirm = page.getByRole('dialog').getByRole('button', { name: 'Start Assessment' })
  await confirm.dblclick() // two clicks in quick succession
  await expect(page).toHaveURL(/\/assessments\/[0-9a-f-]+\/timeline/, { timeout: 30_000 }) // one unreproduced slow run seen under load
  const runs = await (await api(request, 'alice', 'get', `/assessments?project_id=${projectId}`)).json()
  expect(runs.total).toBe(1)
})
