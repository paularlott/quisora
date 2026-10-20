// The Passkeys card on the admin user page: the user's passkeys with their kind and any problem, and removing one.
// The demo server is shared by the whole run, so the removal itself is stubbed (other tests sign "pat" in by passkey).
import { test, expect } from '@playwright/test'
import { axe, fmt, signIn } from './helpers.mjs'

test('admin user page: passkeys listed and removable', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs/northwind/users', { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  await page.getByRole('link', { name: 'Pat Passkey' }).click()
  const list = page.getByRole('list', { name: 'Passkeys of this user' })
  await expect(list).toContainText('Laptop')
  await expect(list).toContainText('Device-bound passkey')
  await expect(list).toContainText('Cannot sign in') // the demo passkey was made without user verification
  await expect(list).toContainText(/Added .+, never used/)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  // the dialog explains what happens; cancelling keeps it
  const remove = list.getByRole('button', { name: 'Remove Laptop' })
  await remove.click()
  const confirm = page.getByRole('dialog', { name: 'Remove passkey?' })
  await expect(confirm).toContainText('sessions that signed in with it end')
  await page.keyboard.press('Escape')
  await expect(confirm).toBeHidden()
  await expect(remove).toBeFocused()

  // removing: the passkey goes, the heading takes focus, the sign-in summary and sessions reload
  let deleted = ''
  await page.route('**/passkeys/*', (route) => {
    if (route.request().method() !== 'DELETE') return route.fallback()
    deleted = route.request().url()
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' })
  })
  await page.route('**/passkeys', (route) => route.request().method() === 'GET'
    ? route.fulfill({ status: 200, contentType: 'application/json', body: '{"items":[],"total":0}' }) : route.fallback())
  const reloads = []
  page.on('request', (req) => { if (/\/users\/[^/]+(\/sessions)?$/.test(new URL(req.url()).pathname)) reloads.push(new URL(req.url()).pathname) })
  await remove.click()
  await confirm.getByRole('button', { name: 'Remove' }).click()
  await expect(page.getByText('Passkey "Laptop" removed.').first()).toBeVisible()
  expect(deleted).toMatch(/\/users\/[^/]+\/passkeys\/[^/]+$/)
  await expect(page.getByText('This user has no passkeys.')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeFocused()
  await expect.poll(() => reloads.some((p) => p.endsWith('/sessions'))).toBe(true)
  expect(reloads.some((p) => !p.endsWith('/sessions'))).toBe(true)
})
