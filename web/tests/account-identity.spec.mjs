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

test('account: an address not yet verified shows its badge in the header, and its link is sent from the Email addresses card', async ({ page }) => {
  await signIn(page, 'user') // Alan Turing: alan@acme.example, not verified
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const head = page.locator('.page-head')
  await expect(head.getByText('alan', { exact: true })).toBeVisible() // a username of its own: shown
  await expect(head.getByText('Not verified')).toBeVisible()
  await expect(head.getByRole('button', { name: /verification/i })).toHaveCount(0) // not in the header any more
  const resend = page.locator('#emails').getByRole('button', { name: 'Resend link for alan@acme.example' })
  await expect(resend).toBeVisible()
  await resend.click()
  await expect(page.getByText('Verification link sent to alan@acme.example.')).toBeVisible()
})

test('account: one address, verified: no Email addresses card; one, not verified: the card, with its primary to verify', async ({ page }) => {
  await signIn(page, 'user')
  const stub = (verified) => page.route('**/api-internal/account', async (route) => {
    if (route.request().method() !== 'GET') return route.fallback()
    const res = await route.fetch()
    const b = await res.json()
    b.user = { ...b.user, email_verified: verified, linked_emails: [] }
    await route.fulfill({ response: res, json: b })
  })
  await stub(true)
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  await page.locator('.page-head').getByText('Verified').waitFor()
  await expect(page.locator('#emails')).toBeHidden()
  await page.unroute('**/api-internal/account')
  await stub(false)
  await page.reload({ waitUntil: 'load' })
  await expect(page.locator('#emails')).toBeVisible()
  await expect(page.locator('#emails').getByRole('button', { name: 'Resend link for alan@acme.example' })).toBeVisible()
})

test('account: where the server sends no email, the Email addresses card says addresses cannot be verified yet', async ({ page }) => {
  await signIn(page, 'user')
  // the server says whether it sends email in the page itself (data-mail on the root element): served as one without
  await page.route('**/o/acme/account', async (route) => {
    const res = await route.fetch()
    await route.fulfill({ response: res, body: (await res.text()).replace('data-mail="1"', 'data-mail="0"') })
  })
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const card = page.locator('#emails')
  await expect(card.getByText('Email is not set up on this server, so addresses cannot be verified here yet.')).toBeVisible()
  await expect(card.getByRole('button', { name: /^Resend link/ })).toHaveCount(0)
  const r = await axe(page, { include: '#emails' })
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('admin user page: the primary address not yet verified can be sent its link, from the Email addresses card', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme/users', { waitUntil: 'load' })
  await page.locator('#list-search').fill('alan')
  await page.getByRole('link', { name: 'Alan Turing' }).click()
  await page.waitForSelector('text=Profile')
  // the Email addresses card, beside the primary address
  const send = page.locator('#emails').getByRole('button', { name: 'Resend link for alan@acme.example' })
  await expect(send).toBeVisible()
  await send.click()
  await expect(page.getByText('Verification link sent to alan@acme.example.')).toBeVisible()
})
