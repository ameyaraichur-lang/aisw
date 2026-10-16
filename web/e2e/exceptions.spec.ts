import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { api, approvedManifest, json, launch, seedProject, signIn, signOut, untilState } from './helpers.ts'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

test('a reviewer confirms a finding and requests an exception; a different approver approves it', async ({ page, request }) => {
  test.setTimeout(120_000)
  const { projectId } = await seedProject(request)
  const runId = await launch(request, projectId, await approvedManifest(request, projectId), 'baseline-ok')
  await untilState(request, runId, ['REPORT_READY'])
  const items = (await json(await api(request, 'alice', 'get', `/findings?run_id=${runId}`))).items as { finding_id: string; severity: string }[]
  const high = items.find((i) => i.severity === 'HIGH')!

  await signIn(page, 'rita')
  await page.goto(`/findings/${runId}/${high.finding_id}`)
  const panel = page.getByRole('region', { name: 'Review actions' })
  await expect(panel.getByTestId('lifecycle')).toHaveText('New')
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])
  await panel.getByRole('button', { name: 'Confirm finding' }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg.getByRole('button', { name: 'Record' })).toBeDisabled() // a reason is required
  await dlg.getByLabel(/Reason/).fill('Reproduced: PermitRootLogin yes in sshd_config')
  await dlg.getByRole('button', { name: 'Record' }).click()
  await expect(panel.getByTestId('lifecycle')).toHaveText('Confirmed')
  await expect(panel.getByTestId('review-history')).toContainText('rita confirmed')

  await panel.getByRole('button', { name: 'Request exception' }).click()
  await expect(dlg.getByLabel(/Expires at the end of/)).not.toHaveValue('')
  expect((await new AxeBuilder({ page }).withTags(TAGS).include('dialog').analyze()).violations).toEqual([])
  await dlg.getByLabel(/Reason/).fill('Legacy jump host, replaced next quarter')
  await dlg.getByRole('button', { name: 'Record' }).click()
  await expect(panel.getByTestId('lifecycle')).toHaveText('Exception requested')
  await expect(panel.getByText('Awaiting approval')).toBeVisible()
  await expect(panel.getByRole('button', { name: 'Request exception' })).toHaveCount(0)
  await signOut(page)

  const pending = (await json(await api(request, 'alice', 'get', '/exceptions?state=PENDING'))).items as { exception_id: string; source_finding_id: string }[]
  const exc = pending.find((e) => e.source_finding_id === high.finding_id)!
  await signIn(page, 'bob')
  await page.goto('/exceptions?state=PENDING')
  await expect(page.getByRole('table', { name: /Exceptions as of/ })).toBeVisible()
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])
  await page.getByRole('button', { name: `Approve exception ${exc.exception_id}` }).click()
  await page.getByRole('dialog').getByLabel(/Reason/).fill('Bastion-only access is a compensating control')
  await page.getByRole('dialog').getByRole('button', { name: 'Approve', exact: true }).click()
  await page.getByLabel('State').selectOption('ACTIVE')
  await expect(page.getByRole('button', { name: `Revoke exception ${exc.exception_id}` })).toBeVisible()
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Exceptions' })).toBeVisible()
  await signOut(page)

  await signIn(page, 'rita')
  await page.goto(`/findings/${runId}/${high.finding_id}`)
  await expect(panel.getByTestId('lifecycle')).toHaveText('Risk accepted (exception)')
  await expect(panel.getByText('In force', { exact: true }).first()).toBeVisible()
  await expect(panel.getByTestId('review-history')).toContainText('bob approved the exception')
  // the approver could never be the requester: rita has no decision controls at all
  await page.goto('/exceptions')
  await expect(page.getByRole('button', { name: /^Approve exception/ })).toHaveCount(0)
})
