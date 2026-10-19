import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { approvedManifest, launch, resume, seedProject, signIn, untilState } from './helpers.ts'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
const reviewer = (request: Parameters<typeof seedProject>[0], mode: 'concur' | 'off') => request.post(`http://127.0.0.1:8099/__e2e/ai-reviewer/${mode}`)

test.afterEach(async ({ request }) => { await reviewer(request, 'off'); await resume(request) })

test('the report shows an accepted AI executive summary, labelled and accessible', async ({ page, request }) => {
  test.setTimeout(150_000)
  await reviewer(request, 'concur')
  const { projectId } = await seedProject(request)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok', true)
  await untilState(request, runId, ['REPORT_READY'])
  await reviewer(request, 'off')

  await signIn(page, 'carol')
  await page.goto(`/assessments/${runId}/report`)
  const exec = page.getByTestId('executive-summary')
  await expect(exec.getByRole('heading', { name: /Executive summary/ })).toBeVisible()
  await expect(exec.getByText('AI-written')).toBeVisible()
  await expect(exec.getByText('recorded weaknesses relate to')).toBeVisible()
  await expect(exec.getByText('the findings are authoritative')).toBeVisible()
  const axe = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  expect(axe.violations.map((v) => v.id)).toEqual([])
})
