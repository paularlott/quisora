// A provider's scopes are chips, as a client's own scopes are: a pasted space-separated list (as provider docs give
// it) becomes one chip per scope, a scope may contain a comma or a URL, and an invalid one stays in the input with
// the error. The request is checked on its way out; the demo store is shared, so it is not saved.
import { test, expect } from '@playwright/test'
import { axe, fmt, signIn } from './helpers.mjs'

test('provider scopes are chips', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme/providers', { waitUntil: 'load' })
  await page.getByRole('button', { name: 'New provider' }).click()
  const dlg = page.getByRole('dialog', { name: 'New sign-in provider' })
  const chips = dlg.getByRole('list', { name: 'Current scopes' }).getByRole('listitem')
  await expect(chips).toHaveText(['openid', 'profile', 'email'])
  await dlg.getByRole('button', { name: 'Remove scope profile' }).click()
  const input = page.locator('#f-scopes')
  await expect(input).toBeFocused()
  await input.fill('api://app-id/access_as_user offline_access ')
  await expect(chips).toHaveText(['openid', 'email', 'api://app-id/access_as_user', 'offline_access'])
  await input.fill('two"quote')
  await page.keyboard.press('Enter')
  await expect(page.locator('#e-scopes')).toContainText('not a valid scope')
  await expect(input).toHaveAttribute('aria-invalid', 'true')
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await input.fill('')
  // Backspace in the empty input removes the last chip
  await page.keyboard.press('Backspace')
  await expect(chips).toHaveText(['openid', 'email', 'api://app-id/access_as_user'])

  let sent = null
  await page.route('**/providers', (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    sent = route.request().postDataJSON()
    return route.fulfill({ status: 201, contentType: 'application/json', body: '{}' })
  })
  await page.locator('#f-issuer').fill('https://login.example.com')
  await page.locator('#f-client_id').fill('quisora')
  await page.locator('#f-client_secret').fill('not-a-real-secret')
  await input.fill('profile') // typed but not yet a chip: saving adds it
  await dlg.getByRole('button', { name: 'Create provider' }).click()
  await expect.poll(() => sent).not.toBeNull()
  expect(sent.scopes).toEqual(['openid', 'email', 'api://app-id/access_as_user', 'profile'])
})
