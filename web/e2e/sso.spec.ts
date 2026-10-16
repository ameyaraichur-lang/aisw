import { expect, test } from '@playwright/test'

// Single sign-on through the BFF against the e2e server's loopback mock IdP (ADR-026).
test('sign in with SSO, session cookie is httpOnly, CSRF enforced, sign out revokes', async ({ page, context }) => {
  await page.goto('/projects')
  await page.getByRole('button', { name: 'Sign in with single sign-on' }).click()
  await expect(page.getByRole('heading', { name: 'Mock IdP' })).toBeVisible()
  await page.getByRole('link', { name: 'carol', exact: true }).click()

  await expect(page).toHaveURL(/127\.0\.0\.1:5199\/projects$/)
  await expect(page.getByText('carol', { exact: false }).first()).toBeVisible()
  const cookies = await context.cookies()
  const session = cookies.find((c) => c.name === 'aisw_session')
  expect(session?.httpOnly).toBe(true)
  expect(session?.sameSite).toBe('Lax')
  expect(await page.evaluate(() => document.cookie)).not.toContain('aisw_session')

  const me = await page.evaluate(async () => (await fetch('/api/v1/me')).json())
  expect(me.actor_id).toBe('carol')
  const noCsrf = await page.evaluate(async () =>
    (await fetch('/api/v1/auth/logout', { method: 'POST' })).status)
  expect(noCsrf).toBe(403)

  const stolen = session!.value
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByText('Signed out of the mock IdP.')).toBeVisible()

  await context.addCookies([{ ...session!, value: stolen }])
  const replay = await page.request.get('http://127.0.0.1:5199/api/v1/me')
  expect(replay.status()).toBe(401)
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Sign in with single sign-on' })).toBeVisible()
})

test('a failed SSO callback lands on the sign-in page with an explanation', async ({ page }) => {
  await page.goto('/api/v1/auth/callback?code=forged&state=forged')
  await expect(page).toHaveURL(/\/login\?error=sso_failed$/)
  await expect(page.getByRole('alert').filter({ hasText: 'Single sign-on did not complete' })).toBeVisible()
})
