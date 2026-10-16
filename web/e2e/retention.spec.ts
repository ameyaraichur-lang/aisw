import { readFileSync } from 'node:fs'
import { expect, test, type APIRequestContext } from '@playwright/test'
import { api, json, manifestPayload, seedProject, signIn, signOut, untilState } from './helpers.ts'

const E2E = 'http://127.0.0.1:8099/__e2e'
const golden = (name: string) => readFileSync(new URL(`../../backend/tests/fixtures/golden/${name}`, import.meta.url), 'utf8')

async function closedImportRun(request: APIRequestContext): Promise<string> {
  const { projectId } = await seedProject(request)
  const unique = golden('cmdb.csv').replace('team-web', `team-web-${Date.now().toString(36)}`) // evidence no other run shares
  const imp = await json(await api(request, 'alice', 'post', '/imports', { project_id: projectId, kind: 'cmdb_csv', filename: 'cmdb.csv', content: unique }), 201)
  const body = manifestPayload(projectId, {
    domains: ['inventory'], allowed_adapters: ['cmdb_import'], policy_version: 'import-baseline:1.0.0',
    profiles: { cmdb_import: { profile_id: 'CMDB_IMPORT', profile_class: 'READ_ONLY' } },
  })
  const created = await json(await api(request, 'alice', 'post', '/scope-manifests', body), 201)
  const id = created.manifest.manifest_id as string
  await json(await api(request, 'alice', 'post', `/scope-manifests/${id}/preflight`))
  const m = await json(await api(request, 'bob', 'post', `/scope-manifests/${id}/approve`, {}))
  const run = await json(await api(request, 'alice', 'post', '/assessments', {
    project_id: projectId, scope_manifest_id: m.manifest_id, scope_manifest_hash: m.canonical_hash,
    assessment_profile: 'baseline-readonly-v1', adapter_params: { cmdb_import: { import_id: imp.import_id } },
  }, { 'Idempotency-Key': `ret-${Date.now()}` }), 202)
  await untilState(request, run.run_id, ['REPORT_READY'])
  const [rep] = await json(await api(request, 'rita', 'get', `/assessments/${run.run_id}/reports`))
  await json(await api(request, 'rita', 'post', `/reports/${rep.report_id}/approve`, { report_hash: rep.report_hash }))
  await untilState(request, run.run_id, ['CLOSED'])
  return run.run_id as string
}

test('a retention manager reviews the plan, holds and releases a run, then moves it to quarantine; auditors read the log', async ({ page, request }) => {
  const runId = await closedImportRun(request)
  await request.post(`${E2E}/retention-offset/31`) // the manifest keeps evidence for 30 days
  try {
    await signIn(page, 'alice')
    await page.getByRole('navigation').getByRole('link', { name: 'Evidence Retention' }).click()
    await expect(page.getByRole('heading', { name: 'Evidence Retention', level: 1 })).toBeVisible()
    await expect(page.getByTestId('retention-schedule')).toContainText('Automatic execution is off')
    const mine = page.getByTestId('plan-items').getByRole('row').filter({ hasText: runId })
    await expect(mine.first()).toBeVisible()
    await expect(page.getByRole('button', { name: 'Move to quarantine' })).toBeDisabled() // no reason yet

    await page.getByLabel('Run id').fill(runId)
    await page.getByLabel('Reason', { exact: true }).fill('litigation hold 7')
    await page.getByRole('button', { name: 'Place hold' }).click()
    await expect(page.getByTestId('holds').getByRole('row').filter({ hasText: runId })).toContainText('litigation hold 7')
    await expect(mine).toHaveCount(0) // held evidence leaves the plan
    await page.getByTestId('holds').getByRole('row').filter({ hasText: runId }).getByRole('button', { name: 'Release hold' }).click()
    await expect(page.getByTestId('holds').getByRole('row').filter({ hasText: runId })).toHaveCount(0)
    await expect(mine.first()).toBeVisible()

    await page.getByLabel('Reason (recorded with every item)').fill('quarterly retention review')
    await page.getByRole('button', { name: 'Move to quarantine' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Move to quarantine' }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Moved to quarantine' })).toContainText('Nothing was deleted')
    await expect(mine).toHaveCount(0)

    await json(await request.post(`${E2E}/retention-check`))
    await page.reload()
    await expect(page.getByTestId('retention-checks').getByRole('row').nth(1)).toBeVisible()

    await signOut(page)
    await signIn(page, 'erin')
    await page.goto('/retention')
    await expect(page.getByText('Planning and executing retention needs the retention:manage permission.')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Place hold' })).toHaveCount(0)
    const log = page.getByTestId('retention-log').getByRole('row').filter({ hasText: 'quarterly retention review' })
    await expect(log.first()).toContainText('alice')

    await signOut(page)
    await signIn(page, 'carol')
    await expect(page.getByRole('navigation').getByRole('link', { name: 'Evidence Retention' })).toHaveCount(0)
    await page.goto('/retention')
    await expect(page.getByRole('alert').filter({ hasText: 'Access denied' })).toBeVisible()
  } finally {
    await request.post(`${E2E}/retention-offset/0`)
  }
})
