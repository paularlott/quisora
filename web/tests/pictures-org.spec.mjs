// Profile pictures, the organization's setting: an organization that leaves pictures to its administrators, and the
// organization editor saving that. They change the setting of the demo organization every page of it follows, so they
// run on their own after the other tests (playwright.config.mjs, the "shared" project).
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt } from './helpers.mjs'

const API = '/api/orgs/acme'
const ACCOUNT = '/o/acme/account'

test.describe.configure({ mode: 'serial' })

test('an organization that leaves pictures to its administrators: the account page shows the picture read-only', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  const set = async (on) => {
    const o = await apiCall(page, 'GET', API)
    await apiCall(page, 'PATCH', API, { settings: { ...o.settings, pictures_by_admins: on } })
  }
  try {
    await set(true)
    await signIn(page, 'manager') // Grace has a picture
    await page.goto(ACCOUNT, { waitUntil: 'load' })
    const card = page.locator('#picture')
    await expect(card.locator('.avatar-img')).toBeVisible()
    await expect(card.getByText('administrators set pictures')).toBeVisible()
    // the picture is shown, not a control: no button, no pencil, and clicking it opens no file chooser
    await expect(card.getByRole('button')).toHaveCount(0)
    await expect(card.locator('.picture-pick-hint')).toBeHidden()
    let chose = false
    page.on('filechooser', () => { chose = true })
    await card.locator('.picture-still').click()
    await page.waitForTimeout(500)
    expect(chose).toBe(false)
    const r = await axe(page, { include: '#picture' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
  } finally {
    await signIn(page, 'super')
    await page.goto('/admin/orgs', { waitUntil: 'load' })
    await set(false)
  }
  await signIn(page, 'manager')
  await page.goto(ACCOUNT, { waitUntil: 'load' })
  await expect(page.locator('#picture').getByRole('button', { name: 'Change picture' })).toBeVisible()
})

test('the organization editor saves "Only administrators set pictures"', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  const reset = async () => { const o = await apiCall(page, 'GET', API); await apiCall(page, 'PATCH', API, { settings: { ...o.settings, pictures_by_admins: false } }) }
  try {
    await reset()
    await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
    const dlg = page.getByRole('dialog', { name: 'Edit organization' })
    const sw = dlg.getByLabel('Only administrators set pictures')
    await expect(sw).not.toBeChecked()
    await expect(dlg.getByText('People cannot change their own picture; administrators, the directory (SCIM) and sign-in providers still can.')).toBeVisible()
    await sw.check()
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg).toBeHidden()
    expect((await apiCall(page, 'GET', API)).settings.pictures_by_admins).toBe(true)
    await page.reload({ waitUntil: 'load' })
    await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
    await expect(dlg.getByLabel('Only administrators set pictures')).toBeChecked()
    await dlg.getByLabel('Only administrators set pictures').uncheck()
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg).toBeHidden()
    expect((await apiCall(page, 'GET', API)).settings.pictures_by_admins).toBe(false)
  } finally { await reset() }
})
