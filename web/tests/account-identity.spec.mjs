// The account page's header says who you are once each: the username only where it is not the email address (a first
// super admin's often is), and the address with its verification: a link to send it where the server sends email, and
// why it cannot be sent where it does not.
import { test, expect } from '@playwright/test'
import { signIn, axe, fmt } from './helpers.mjs'

test('account header: a username that is the email address is shown once', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/o/primary/account', { waitUntil: 'load' })
  const head = page.locator('.page-head')
  await expect(head.getByText('Super admin', { exact: false }).first()).toBeVisible()
  await expect(head.getByText('admin@example.com', { exact: true }).filter({ visible: true })).toHaveCount(1) // the heading
  // the Profile card no longer repeats it
  await expect(page.locator('#profile input[type=email]')).toHaveCount(0)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('account header: an address not yet verified offers to send the link, beside its badge', async ({ page }) => {
  await signIn(page, 'user') // Alan Turing: alan@acme.example, not verified
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const head = page.locator('.page-head')
  await expect(head.getByText('alan', { exact: true })).toBeVisible() // a username of its own: shown
  await expect(head.getByText('Not verified')).toBeVisible()
  const send = head.getByRole('button', { name: 'Send verification email' })
  await expect(send).toBeVisible()
  await expect(head.getByText('cannot be verified yet')).toBeHidden()
  await send.click()
  await expect(page.getByText('Verification email sent.')).toBeVisible()
})

test('account header: where the server sends no email, it says the address cannot be verified yet', async ({ page }) => {
  await signIn(page, 'user')
  await page.route('**/api-internal/account', async (route) => {
    if (route.request().method() !== 'GET') return route.fallback()
    const res = await route.fetch()
    const body = await res.json()
    body.security = { ...body.security, mail_available: false }
    await route.fulfill({ response: res, json: body })
  })
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const head = page.locator('.page-head')
  await expect(head.getByText('This server sends no email, so the address cannot be verified yet.')).toBeVisible()
  await expect(head.getByRole('button', { name: 'Send verification email' })).toHaveCount(0)
  const r = await axe(page, { include: '.page-head' })
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})
