// A new secret for an API token: a confirmation first (the old secret stops working at once), then the new secret
// shown once, saying the old one no longer works. The server side is stubbed: the demo store is shared by the run.
import { test, expect } from '@playwright/test'
import { axe, fmt, signIn } from './helpers.mjs'

const item = { id: 'tok-1', name: 'Deploy script', scopes: ['api'], audience: [], created: '2026-10-01T10:00:00Z', expires: '2026-12-01T10:00:00Z', last_used: '2026-10-19T10:00:00Z' }

test('API token: make a new secret', async ({ page }) => {
  await signIn(page, 'user')
  await page.route('**/api/account/tokens', (route) => route.request().method() === 'GET'
    ? route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ items: [item], total: 1, scopes: ['api'], max_days: 0 }) })
    : route.fallback())
  let calls = 0
  await page.route('**/api/account/tokens/tok-1/regenerate', (route) => {
    calls++
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ token: 'qsr_tok-1_newsecret', item: { ...item, last_used: '0001-01-01T00:00:00Z' } }) })
  })
  await page.goto('/account')
  const btn = page.getByRole('button', { name: 'New secret for token Deploy script' })
  await btn.scrollIntoViewIfNeeded()

  // cancelling the confirmation changes nothing
  await btn.click()
  const confirm = page.getByRole('dialog', { name: 'Make a new secret?' })
  await expect(confirm).toContainText('stops working immediately')
  await page.keyboard.press('Escape')
  await expect(confirm).toBeHidden()
  await expect(btn).toBeFocused()
  expect(calls).toBe(0)

  await btn.click()
  await confirm.getByRole('button', { name: 'Make new secret' }).click()
  const secret = page.getByRole('dialog', { name: 'Your new token' })
  await expect(secret).toBeVisible()
  await expect(secret.locator('#new-token')).toHaveText('qsr_tok-1_newsecret')
  await expect(secret).toContainText('The old secret of Deploy script no longer works')
  expect(calls).toBe(1)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await secret.getByRole('button', { name: 'Done' }).click()
  await expect(secret).toBeHidden()
  await expect(btn).toBeFocused()
})
