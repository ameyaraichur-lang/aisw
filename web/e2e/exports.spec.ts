import { readFile } from 'node:fs/promises'
import { expect, test } from '@playwright/test'
import { approvedManifest, launch, seedProject, signIn, signOut, untilState } from './helpers.ts'

test('a reviewer downloads PDF and Word exports of a draft report; a reader is told why not', async ({ page, request }) => {
  test.setTimeout(120_000)
  const { projectId } = await seedProject(request)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok')
  await untilState(request, runId, ['REPORT_READY'])

  await signIn(page, 'carol') // report reader: can read the draft, cannot distribute it
  await page.goto(`/assessments/${runId}/report`)
  await page.getByRole('button', { name: 'Download PDF' }).click()
  await expect(page.getByRole('alert').filter({ hasText: 'Not downloaded' })).toContainText('Only an approved report can be downloaded')
  await signOut(page)

  await signIn(page, 'rita') // reviewer: may approve, so may download the draft
  await page.goto(`/assessments/${runId}/report`)
  for (const [name, ext, magic] of [['Download PDF', 'pdf', '%PDF-1.4'], ['Download Word (DOCX)', 'docx', 'PK']] as const) {
    const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name }).click()])
    expect(dl.suggestedFilename()).toMatch(new RegExp(`^rep-${runId}\\.${ext}$`))
    const bytes = await readFile((await dl.path())!)
    expect(bytes.subarray(0, magic.length).toString('latin1')).toBe(magic)
  }
  await expect(page.getByText('Not downloaded')).toHaveCount(0)
})
