import { expect, test } from '@playwright/test'
import { GROUP, api, approvedManifest, json, launch, resume, seedProject, signIn, tab, untilState } from './helpers.ts'

test.afterEach(async ({ request }) => { await resume(request) })

test('blocked preflight explains why, stores nothing and offers no way forward', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  await signIn(page, 'alice')
  await page.goto('/assessments/new')
  await page.getByLabel('Project and environment').selectOption(projectId)
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByRole('checkbox', { name: new RegExp(GROUP) }).check()
  await page.getByLabel('Kind').selectOption('asset_group')
  await page.getByLabel('Selector').fill(GROUP) // an exclusion that swallows the target
  await page.getByRole('button', { name: 'Add exclusion' }).click()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByRole('checkbox', { name: 'Use this adapter' }).check()
  await page.getByLabel('Profile', { exact: true }).selectOption('FIXTURE_BASELINE')
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByRole('button', { name: 'Run preflight' }).click()
  const alert = page.getByRole('alert').filter({ hasText: 'Preflight blocked' })
  await expect(alert).toBeVisible()
  await expect(alert).toContainText('TARGET_EXCLUDED')
  await expect(alert).toContainText('Nothing was stored or run')
  await expect(page.getByRole('button', { name: 'Continue to review' })).toHaveCount(0)
  const stored = await json(await api(request, 'alice', 'get', `/scope-manifests?project_id=${projectId}`))
  expect(stored).toEqual([]) // the denied draft was never persisted
})

test('a target no adapter can handle is surfaced instead of assumed', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  await json(await api(request, 'alice', 'post', '/inventory', { project_id: projectId, kind: 'url', selector: 'https://example.org' }), 201)
  await signIn(page, 'alice')
  await page.goto('/assessments/new')
  await page.getByLabel('Project and environment').selectOption(projectId)
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByRole('checkbox', { name: /https:\/\/example\.org/ }).check()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page.getByText('No compatible adapter')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Next' })).toBeDisabled()
  await expect(page.getByText('Choose an adapter and a profile for it.')).toBeVisible()
})

test('partial run is loud everywhere and never shows unknown as passing', async ({ page, request }) => {
  const { projectId, name } = await seedProject(request, ['host-1', 'host-2', 'host-3', 'host-4'])
  const m = await approvedManifest(request, projectId)
  const runId = await launch(request, projectId, m, 'baseline-partial')
  await untilState(request, runId, ['PARTIAL'])

  await signIn(page, 'carol') // report reader: can see coverage, controls and the report
  await page.goto(`/assessments/${runId}/timeline`)
  await expect(page.getByRole('alert').filter({ hasText: 'Partial assessment' })).toBeVisible()
  await expect(page.getByTestId('stage-collection')).toHaveAttribute('data-status', 'partial')
  await expect(page.getByTestId('stage-report')).toHaveAttribute('data-status', 'partial')
  await expect(page.getByTestId('stage-report')).toContainText('review required')

  await tab(page, 'Coverage').click()
  await expect(page.getByText('Coverage incomplete')).toBeVisible()
  await expect(page.getByRole('cell', { name: '3 of 4' })).toBeVisible() // denominator is the expected set
  for (const gap of ['EXPECTED_ASSET_ABSENT:host-4', 'ASSET_UNREACHABLE:host-2', 'ASSET_UNSUPPORTED:host-3', 'UNEXPECTED_ASSET:host-9']) {
    await expect(page.getByText(gap, { exact: false })).toBeVisible()
  }

  await tab(page, 'Controls').click()
  const fb3 = page.getByRole('row').filter({ hasText: 'FB-3' })
  await expect(fb3).toContainText('Unknown') // one host passed, one is unknown: not a pass
  await expect(fb3).not.toContainText('Pass')

  await tab(page, 'Findings').click()
  await expect(page.getByText(/An empty list is not proof of security/)).toBeVisible()

  await tab(page, 'Report').click()
  await expect(page.getByRole('alert').filter({ hasText: 'PARTIAL ASSESSMENT' })).toBeVisible()
  await expect(page.getByText('INCOMPLETE')).toBeVisible()
  await expect(page.getByText(/coverage incomplete/).first()).toBeVisible()

  // The Command Center keeps the denominator and flags the incomplete segment
  await page.getByRole('link', { name: 'Command Center' }).click()
  await expect(page.getByText(/expected assets reconciled/)).toBeVisible()
  await expect(page.getByText('Coverage incomplete').first()).toBeVisible()
  await expect(page.getByText(/Data as of/)).toBeVisible()
  expect(name).toBeTruthy()
})

test('failed run explains itself, names the rejected task and produces no report', async ({ page, request }) => {
  const { projectId } = await seedProject(request)
  const m = await approvedManifest(request, projectId)
  // Hostile parameter text is accepted as DATA at launch and refused by the gateway at dispatch.
  const runId = await launch(request, projectId, m, 'baseline-ok; rm -rf /')
  await untilState(request, runId, ['FAILED'])
  await signIn(page, 'carol')
  await page.goto(`/assessments/${runId}/timeline`)
  await expect(page.getByRole('alert').filter({ hasText: 'Run failed' })).toContainText('No report was produced')
  await expect(page.getByTestId('stage-collection')).toHaveAttribute('data-status', 'failed')
  await expect(page.getByTestId('stage-policy')).toContainText('Not started: run failed')
  await expect(page.getByTestId('event-log')).toContainText('INVALID_PARAMS')
  await expect(page.getByRole('row').filter({ hasText: 'Rejected by gateway' })).toBeVisible()
  await tab(page, 'Report').click()
  await expect(page.getByText('No report yet')).toBeVisible()
})
