import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { api, json, signIn, signOut } from './helpers.ts'

const KEY = 'CB-LOG-2|NIST-CSF|PR.PS-04'
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

test('a policy owner reviews a framework mapping; everyone else sees its state read-only', async ({ page, request }) => {
  const before = (await json(await api(request, 'carol', 'get', '/control-matrix?policy_version=config-baseline:1.0.0'))).controls
    .flatMap((c: { mappings: { key: string; status: string }[] }) => c.mappings).find((m: { key: string }) => m.key === KEY)
  const [decision, label] = before.status === 'APPROVED' ? ['Reject this mapping', 'Rejected'] : ['Approve this mapping', 'Approved']

  await signIn(page, 'paula')
  await page.goto('/controls')
  await page.getByLabel('Run', { exact: true }).selectOption('')
  await page.getByLabel('Policy pack').selectOption('config-baseline:1.0.0')
  await expect(page.getByText('Mapping catalog 1.0.0')).toBeVisible()
  await expect(page.getByRole('table', { name: /Controls in config-baseline:1.0.0/ })).toBeVisible()
  expect((await new AxeBuilder({ page }).withTags(TAGS).analyze()).violations).toEqual([])
  await page.getByRole('button', { name: new RegExp(`^Review mapping of CB-LOG-2 to NIST-CSF PR\\.PS-04`) }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg.getByText('Log records are generated and made available for continuous monitoring')).toBeVisible()
  expect((await new AxeBuilder({ page }).withTags(TAGS).include('dialog').analyze()).violations).toEqual([])
  await dlg.getByLabel(decision).check()
  await expect(dlg.getByRole('button', { name: 'Record decision' })).toBeDisabled() // a reason is required
  await dlg.getByLabel(/Reason/).fill('Retention supports continuous monitoring; checked against CSF 2.0 text')
  await dlg.getByRole('button', { name: 'Record decision' }).click()
  await expect(page.getByRole('button', { name: `Review mapping of CB-LOG-2 to NIST-CSF PR.PS-04 (${label})` })).toBeVisible()
  await signOut(page)

  await signIn(page, 'carol')
  await page.goto('/controls')
  await page.getByLabel('Run', { exact: true }).selectOption('')
  await page.getByLabel('Policy pack').selectOption('config-baseline:1.0.0')
  await expect(page.getByLabel(`PR.PS-04: ${label}`).first()).toBeVisible()
  await expect(page.getByRole('button', { name: /^Review mapping/ })).toHaveCount(0)
  await expect(page.getByText('Only a policy owner can approve or reject mappings.')).toBeVisible()
})
