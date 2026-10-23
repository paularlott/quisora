// The organization's "codes by email" switch needs the server to send email: without it the switch is disabled and
// says why (unless it is on already, when it can still be turned off). The demo server has email set up, so the
// tests below serve the page with its flag off to stand for a server without it.
import { test, expect } from '@playwright/test'
import { signIn, axe, fmt } from './helpers.mjs'

const openEdit = async (page, mail, settings) => {
  if (settings) {
    await page.route('**/api/orgs?*', async (r) => {
      const res = await r.fetch()
      const body = await res.json()
      for (const o of body.items || []) if (o.name === 'acme') Object.assign(o.settings, settings)
      return r.fulfill({ response: res, json: body })
    })
  }
  await page.route('**/admin/orgs', async (r) => {
    const res = await r.fetch()
    return r.fulfill({ response: res, body: (await res.text()).replace(/data-mail="[01]"/, `data-mail="${mail}"`) })
  })
  await page.goto('/admin/orgs')
  await page.waitForSelector('tbody tr')
  await page.getByRole('button', { name: 'Edit Acme Corporation' }).first().click()
  return page.getByRole('switch', { name: /Allow codes by email/ })
}

test('codes by email: on offer with email set up', async ({ page }) => {
  await signIn(page, 'super')
  const sw = await openEdit(page, '1')
  await expect(sw).toBeEnabled()
  await expect(page.locator('#n-email_codes')).toBeHidden()
})

test('codes by email: disabled, and why, without email', async ({ page }) => {
  await signIn(page, 'super')
  const sw = await openEdit(page, '0')
  await expect(sw).toBeDisabled()
  await expect(sw).not.toBeChecked()
  await expect(page.locator('#n-email_codes')).toHaveText('Unavailable: email is not set up on the server (mail.smtp_host).')
  await expect(sw).toHaveAccessibleDescription(/Unavailable: email is not set up/)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('codes by email: on already without email, it can still be turned off', async ({ page }) => {
  await signIn(page, 'super')
  const sw = await openEdit(page, '0', { email_codes: true })
  await expect(sw).toBeEnabled()
  await expect(sw).toBeChecked()
  await expect(page.locator('#n-email_codes')).toHaveText('Not in use: email is not set up on the server (mail.smtp_host).')
  await sw.click()
  await expect(sw).not.toBeChecked()
  await expect(sw).toBeDisabled() // off now, and cannot go back on
})
