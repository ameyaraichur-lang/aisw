import { expect, test } from '@playwright/test'
import { GROUP, resume, seedProject, signIn, signOut, tab, useAdapter } from './helpers.ts'

test.afterEach(async ({ request }) => { await resume(request) })

test('operator drafts, approver approves, operator launches, reviewer closes: full UI path', async ({ page, request }) => {
  const { projectId, name } = await seedProject(request)

  // 1) operator walks the six-step wizard
  await signIn(page, 'alice')
  await page.goto('/assessments/new')
  await expect(page.getByRole('heading', { name: 'New assessment' })).toBeVisible()
  await page.getByLabel('Project and environment').selectOption(projectId)
  await expect(page.getByText('Environment classification:')).toBeVisible()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByRole('checkbox', { name: new RegExp(GROUP) }).check()
  await expect(page.getByText(/resolves to/)).toContainText('3 expected asset(s)')
  await page.getByRole('button', { name: 'Next' }).click()
  await useAdapter(page, 'fixture', 'FIXTURE_BASELINE')
  // the e2e backend runs the Python engine, so Rego packs are offered but cannot be chosen
  await expect(page.locator('#pack option[value="config-baseline:1.0.0"]')).toBeDisabled()
  await expect(page.locator('#pack option[value="config-baseline:1.0.0"]')).toContainText('needs the OPA policy engine')
  await expect(page.getByLabel(/Policy pack/)).toHaveValue('fixture-baseline:1.0.0')
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page.getByLabel('Maximum concurrency')).toBeVisible()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByRole('button', { name: 'Run preflight' }).click()
  await expect(page.getByRole('heading', { name: /Preflight result: valid, approval required/ })).toBeVisible()
  await page.getByRole('button', { name: 'Continue to review' }).first().click()
  await expect(page.getByText('Awaiting approval')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Start Assessment' })).toBeDisabled() // not approved yet
  await expect(page.getByText(GROUP).first()).toBeVisible()
  await signOut(page)

  // 2) a different user approves; approval signs the exact hash
  await signIn(page, 'bob')
  await page.getByRole('link', { name: 'Pending approvals' }).click()
  await expect(page.getByRole('heading', { name })).toBeVisible()
  await page.getByRole('button', { name: 'Review and approve' }).click()
  await expect(page.getByRole('dialog')).toContainText('All profiles are read-only')
  await page.getByRole('button', { name: 'Approve and sign' }).click()
  await expect(page.getByText('Nothing is waiting for approval.')).toBeVisible()
  await signOut(page)

  // 3) operator launches from the approved manifest
  await signIn(page, 'alice')
  await page.getByRole('link', { name: 'Assessments', exact: true }).click()
  await page.getByRole('listitem').filter({ hasText: name }).getByRole('link', { name: 'Review and launch' }).click()
  await expect(page.getByText('Approved and signed')).toBeVisible()
  await page.getByRole('button', { name: 'Start Assessment' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Start Assessment' }).click()

  // 4) live timeline reaches the end driven by persisted events
  await expect(page).toHaveURL(/\/assessments\/[0-9a-f-]+\/timeline/)
  await expect(page.getByTestId('stage-report')).toHaveAttribute('data-status', 'succeeded', { timeout: 40_000 })
  for (const s of ['authorization', 'collection', 'normalization', 'policy', 'assurance']) {
    await expect(page.getByTestId(`stage-${s}`)).toHaveAttribute('data-status', 'succeeded')
  }
  await expect(page.getByTestId('stream-status')).toContainText('Stream complete')
  await expect(page.getByTestId('event-log')).toContainText('Report ready')

  // 5) coverage is complete with its denominator
  await tab(page, 'Coverage').click()
  await expect(page.getByText('Coverage complete')).toBeVisible()
  await expect(page.getByRole('cell', { name: '3 of 3' })).toBeVisible()

  // 6) findings: two authoritative findings; open the high one and inspect its evidence
  await tab(page, 'Findings').click()
  await expect(page.getByRole('table', { name: /Findings \(2\)/ })).toBeVisible()
  await expect(page.getByText('Authoritative (assurance accepted)').first()).toBeVisible()
  await page.getByRole('link', { name: 'Direct root login over SSH is disabled' }).click()
  await expect(page.getByRole('heading', { name: 'Direct root login over SSH is disabled' })).toBeVisible()
  await expect(page.getByText('fixture-scanner@1.0.0')).toBeVisible()
  await expect(page.getByText('Secrets were redacted before storage').or(page.getByText('No redaction needed'))).toBeVisible()
  await expect(page.locator('dl').filter({ hasText: 'Observed' }).getByText('"yes"')).toBeVisible()
  await expect(page.locator('dl').filter({ hasText: 'Expected' }).getByText('"no"')).toBeVisible()
  await expect(page.getByText('Pack control FB-1')).toBeVisible()
  await expect(page.getByText('Needs policy-owner review').first()).toBeVisible() // external mapping is not trusted
  await expect(page.getByText(/with AI disabled none exists/)).toBeVisible()
  await page.goBack()

  // 7) the operator role cannot read reports (server-enforced); the reviewer can and approves
  const runUrl = page.url().replace(/\/findings.*$/, '/report').replace(/\/assessments\/([0-9a-f-]+)\/?.*/, '/assessments/$1/report')
  await tab(page, 'Report').click()
  await expect(page.getByRole('alert').filter({ hasText: 'Access denied' })).toBeVisible()
  await signOut(page)
  await signIn(page, 'rita')
  await page.goto(runUrl)
  await expect(page.getByTestId('report-total')).toContainText('2')
  await expect(page.getByText('Awaiting review')).toBeVisible()
  await page.getByRole('button', { name: 'Preview HTML report' }).click()
  const frame = page.frameLocator('iframe[title="Report preview"]')
  await expect(frame.getByText('Direct root login over SSH is disabled')).toBeVisible()
  await expect(page.locator('iframe[title="Report preview"]')).toHaveAttribute('sandbox', '')
  await page.getByRole('button', { name: 'Approve report' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Approve', exact: true }).click()
  await expect(page.getByText('Approved', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Closed').first()).toBeVisible()
})
