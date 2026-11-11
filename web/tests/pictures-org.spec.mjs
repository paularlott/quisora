// Profile pictures, the organization's setting (settings.pictures: everyone, admins or off): an organization that
// leaves pictures to its administrators, one with pictures off, and the organization editor saving each value. They
// change the setting of the demo organization every page of it follows, so they run on their own after the other tests
// (playwright.config.mjs, the "pictures-org" project), and put "everyone" back however they end.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt } from './helpers.mjs'

const API = '/api/orgs/acme'
const ACCOUNT = '/o/acme/account'

test.describe.configure({ mode: 'serial' })

// setPictures sets the demo organization's pictures setting, as a super admin (organization settings are theirs).
const setPictures = async (page, value) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  const o = await apiCall(page, 'GET', API)
  await apiCall(page, 'PATCH', API, { settings: { ...o.settings, pictures: value } })
}

test('an organization that leaves pictures to its administrators: the account page shows the picture read-only', async ({ page }) => {
  try {
    await setPictures(page, 'admins')
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
  } finally { await setPictures(page, 'everyone') }
  await signIn(page, 'manager')
  await page.goto(ACCOUNT, { waitUntil: 'load' })
  await expect(page.locator('#picture').getByRole('button', { name: 'Change picture' })).toBeVisible()
})

test('an organization with pictures off: no picture card on the account page or the user page, initials in the header', async ({ page }) => {
  try {
    await setPictures(page, 'off')
    await signIn(page, 'manager') // Grace has a picture
    await page.goto(ACCOUNT, { waitUntil: 'load' })
    await expect(page.getByRole('heading', { name: 'Profile', exact: true })).toBeVisible()
    await page.waitForTimeout(500) // the account loaded
    await expect(page.locator('#picture')).toBeHidden()
    await expect(page.getByRole('heading', { name: 'Picture', exact: true })).toHaveCount(0)
    const header = page.locator('[x-data="headerAvatar"]')
    await expect(header.locator('.avatar-img')).toBeHidden()
    await expect(header).toContainText('GH')

    await signIn(page, 'admin')
    await page.goto('/admin/orgs/acme/users', { waitUntil: 'load' })
    await page.locator('#list-search').fill('grace')
    await page.getByRole('link', { name: 'Grace Hopper' }).click()
    await page.waitForSelector('text=Profile')
    await page.waitForTimeout(500)
    await expect(page.getByRole('heading', { name: 'Picture', exact: true })).toHaveCount(0)
  } finally { await setPictures(page, 'everyone') }
  await signIn(page, 'manager')
  await page.goto(ACCOUNT, { waitUntil: 'load' })
  await expect(page.locator('#picture').getByRole('button', { name: 'Change picture' })).toBeVisible()
})

test('the organization editor saves each "Profile pictures" choice', async ({ page }) => {
  try {
    await setPictures(page, 'everyone')
    for (const [value, label] of [['admins', 'Only administrators'], ['off', 'Off'], ['everyone', 'Everyone sets their own']]) {
      await page.reload({ waitUntil: 'load' })
      await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
      const dlg = page.getByRole('dialog', { name: 'Edit organization' })
      const choice = dlg.getByLabel('Profile pictures')
      await expect(dlg.getByText('Off deletes the pictures held and stops sending them to applications.')).toBeVisible()
      await choice.selectOption({ label })
      await dlg.getByRole('button', { name: 'Save changes' }).click()
      await expect(dlg).toBeHidden()
      expect((await apiCall(page, 'GET', API)).settings.pictures).toBe(value)
      await page.reload({ waitUntil: 'load' })
      await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
      await expect(dlg.getByLabel('Profile pictures')).toHaveValue(value)
      await dlg.getByRole('button', { name: 'Cancel' }).click()
      await expect(dlg).toBeHidden()
    }
  } finally { await setPictures(page, 'everyone') }
})
