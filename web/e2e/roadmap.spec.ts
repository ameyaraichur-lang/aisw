import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { api, approvedManifest, json, launch, seedProject, signIn, untilState } from './helpers.ts'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

test('the roadmap never guesses a priority and moves decided work out of the waves', async ({ page, request }) => {
  test.setTimeout(120_000)
  const { projectId } = await seedProject(request)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok')
  await untilState(request, runId, ['REPORT_READY'])

  await signIn(page, 'carol')
  await page.getByRole('link', { name: 'Modernization Roadmap' }).click()
  await expect(page.getByRole('heading', { name: 'Modernization Roadmap', level: 1 })).toBeVisible()
  await page.getByLabel('Run', { exact: true }).selectOption({ value: runId })
  const waves = page.getByTestId('roadmap-waves')
  await expect(waves.getByRole('listitem')).toHaveCount(0) // criticality unknown: no tier, so no wave
  const unrated = page.getByRole('region', { name: /Needs owner input/ })
  await expect(unrated.getByRole('listitem')).toHaveCount(2)
  await expect(unrated.getByText('criticality is unknown', { exact: false }).first()).toBeVisible()
  await expect(unrated.getByText('Unknown: the owner must estimate it').first()).toBeVisible()
  await expect(page.getByText('Sample patterns')).toBeVisible()
  await expect(page.getByRole('button')).not.toContainText(['Apply', 'Execute'])
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])

  const recs = (await json(await api(request, 'bob', 'get', `/assessments/${runId}/recommendations`))) as { recommendation_id: string; title: string }[]
  const host = recs.find((r) => r.title.startsWith('Harden host'))!
  await json(await api(request, 'bob', 'post', `/assessments/${runId}/recommendations/${host.recommendation_id}/decision`, { decision: 'REJECT', reason: 'Host is being decommissioned' }))
  await page.reload()
  await page.getByLabel('Run', { exact: true }).selectOption({ value: runId })
  await expect(page.getByRole('region', { name: /^Rejected/ }).getByRole('listitem', { name: host.title })).toBeVisible()
  await expect(page.getByRole('region', { name: /Needs owner input/ }).getByRole('listitem')).toHaveCount(1)
})
