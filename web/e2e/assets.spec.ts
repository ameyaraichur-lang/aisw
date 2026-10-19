import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { approvedManifest, launch, seedProject, signIn, signOut, untilState } from './helpers.ts'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

test('the asset explorer lists reconciled assets with sourced ownership, posture and findings', async ({ page, request }) => {
  test.setTimeout(120_000)
  const { projectId, name } = await seedProject(request)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok')
  await untilState(request, runId, ['REPORT_READY'])

  await signIn(page, 'alice')
  await page.getByRole('link', { name: 'Asset Explorer' }).click()
  await page.getByLabel('Project').selectOption({ label: name })
  const list = page.getByTestId('asset-list')
  await expect(list.getByRole('caption')).toHaveText('Assets: 3')
  await expect(list.getByRole('row', { name: /host-2/ })).toContainText('Unknown')
  await expect(page.getByTestId('asset-types')).toContainText('host')
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])

  await page.getByLabel('Search asset id or native id').fill('host-2')
  await page.getByLabel('Search asset id or native id').press('Enter')
  await expect(list.getByRole('caption')).toHaveText('Assets: 1')
  await list.getByRole('link', { name: 'host-2' }).click()

  await expect(page.getByRole('heading', { name: 'host-2', level: 1 })).toBeVisible()
  await expect(page.getByTestId('asset-posture')).toContainText(runId.slice(0, 8))
  await expect(page.getByTestId('asset-posture')).toContainText('Fail')
  await expect(page.getByTestId('asset-findings')).toContainText('Direct root login over SSH is disabled')
  await expect(page.getByText('Relationships are not modelled yet', { exact: false })).toBeVisible()
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])
  const detailUrl = page.url()
  await signOut(page)

  await signIn(page, 'paula') // project read only: posture yes, findings no
  await page.goto(detailUrl)
  await expect(page.getByTestId('asset-posture')).toBeVisible()
  await expect(page.getByText('Findings hidden')).toBeVisible()
  await expect(page.getByTestId('asset-findings')).toHaveCount(0)
})
