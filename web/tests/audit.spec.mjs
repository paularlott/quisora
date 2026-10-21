// The audit log: a wide search, the time window, a Filters panel (action, outcome, and on every organization's page
// the organization) and a refresh button on one line; the active filters as chips below, each removable.
import { test, expect } from '@playwright/test'
import { signIn, axe, fmt } from './helpers.mjs'

const rows = (page) => page.locator('table.table tbody tr')
const col = (page, n) => page.locator(`table.table tbody tr td:nth-child(${n})`).allTextContents()
const chips = (page) => page.getByRole('group', { name: 'Active filters' })

test('audit log: the Filters panel, chips that remove one filter, and Clear all', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme/audit', { waitUntil: 'load' })
  await expect(rows(page).first()).toBeVisible()
  const all = await page.locator('.pager').textContent()
  expect(all).toMatch(/Showing 1–\d+ of \d+/) // the pager's own range (not the filters')
  const button = page.getByRole('button', { name: /^Filters/ })

  // search, time, Filters and refresh share one line
  const top = async (loc) => (await loc.boundingBox()).y
  expect(Math.abs((await top(page.locator('#list-search'))) - (await top(button)))).toBeLessThan(8)
  await expect(chips(page)).toBeHidden()

  // the panel opens on the action field; a kind of action (user.*) narrows the list
  await button.click()
  await expect(button).toHaveAttribute('aria-expanded', 'true')
  const action = page.getByRole('combobox', { name: 'Action' })
  await expect(action).toBeFocused()
  await action.fill('user')
  await page.getByRole('option', { name: /^user\.\*/ }).click()
  await expect.poll(async () => { const a = await col(page, 3); return a.length > 0 && a.every((x) => x.startsWith('user.')) }).toBe(true)
  await page.getByLabel('Outcome').selectOption('success')
  await expect(button).toContainText('2')

  // Escape closes the panel and returns to its button; the chips show what is applied
  await page.keyboard.press('Escape')
  await expect(page.locator('#filter-panel')).toBeHidden()
  await expect(button).toBeFocused()
  await expect(chips(page)).toContainText('Action: user.*')
  await expect(chips(page)).toContainText('Succeeded')

  // a chip removes its own filter
  await page.getByRole('button', { name: 'Remove filter: action user.*' }).click()
  await expect(chips(page)).not.toContainText('Action')
  await expect(button).toContainText('1')

  // a custom range is set in a dialog and shows as a chip; one in the future matches nothing
  await page.getByLabel('Time', { exact: true }).selectOption('custom')
  const dlg = page.getByRole('dialog', { name: 'Custom range' })
  // the times default to the whole day: from the start of the first, to the last second of the last
  await expect(dlg.getByLabel('Start time')).toHaveValue('00:00:00')
  await expect(dlg.getByLabel('End time')).toHaveValue('23:59:59')
  // an end before the start is refused in the dialog
  await dlg.getByLabel('From').fill('2099-01-02')
  await dlg.getByLabel('To').fill('2099-01-01')
  await dlg.getByRole('button', { name: 'Apply' }).click()
  await expect(dlg.getByText('The end must not be before the start.')).toBeVisible()
  await dlg.getByLabel('To').fill('')
  await dlg.getByLabel('From').fill('2099-01-01')
  await dlg.getByRole('button', { name: 'Apply' }).click()
  await expect(dlg).toBeHidden()
  await expect(rows(page)).toHaveCount(0)
  await expect(chips(page)).toContainText('now')
  // reopened, it shows the range as set
  await page.getByRole('button', { name: 'Change the custom range' }).click()
  await expect(dlg.getByLabel('From')).toHaveValue('2099-01-01')
  await expect(dlg.getByLabel('Start time')).toHaveValue('00:00:00')
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  // the shortest windows: everything the demo recorded at start-up is within the last 30 minutes, and shows as a chip
  await chips(page).getByRole('button', { name: 'Clear all' }).click()
  await page.getByLabel('Time', { exact: true }).selectOption('30m')
  await expect(chips(page)).toContainText('Last 30 minutes')
  await expect(page.locator('.pager')).toHaveText(all)
  await page.getByLabel('Time', { exact: true }).selectOption('15m')
  await expect(chips(page)).toContainText('Last 15 minutes')

  // one day, today: today's events are all in it (the end's whole day is included)
  const today = new Date()
  const iso = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`
  await chips(page).getByRole('button', { name: 'Clear all' }).click()
  await page.getByLabel('Time', { exact: true }).selectOption('custom')
  await dlg.getByLabel('From').fill(iso)
  await dlg.getByLabel('To').fill(iso)
  await dlg.getByRole('button', { name: 'Apply' }).click()
  await expect(page.locator('.pager')).toHaveText(all)

  await chips(page).getByRole('button', { name: 'Clear all' }).click()
  await expect(chips(page)).toBeHidden()
  await expect(page.locator('.pager')).toHaveText(all)

  // a custom range dialog cancelled without a range goes back to the window chosen before
  await page.getByLabel('Time', { exact: true }).selectOption('7d')
  await page.getByLabel('Time', { exact: true }).selectOption('custom')
  await expect(dlg).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByLabel('Time', { exact: true })).toHaveValue('7d')
})

test('audit log of every organization: the organization is searched as you type, shows as a chip, and clears', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/audit', { waitUntil: 'load' })
  await expect(rows(page).first()).toBeVisible()
  const all = await page.locator('.pager').textContent()
  await page.getByRole('button', { name: /^Filters/ }).click()
  const org = page.getByRole('combobox', { name: 'Organization' })
  await org.fill('north')
  await page.getByRole('option', { name: /Northwind/ }).click()
  await expect.poll(async () => { const o = await col(page, 2); return o.length > 0 && o.every((x) => x.includes('Northwind')) }).toBe(true)
  // its clear button in the panel, then the chip outside it
  await page.getByRole('button', { name: 'Clear Organization' }).click()
  await expect(org).toHaveValue('')
  await expect(page.locator('.pager')).toHaveText(all)
  await org.fill('north')
  await page.getByRole('option', { name: /Northwind/ }).click()
  await page.mouse.click(5, 5) // outside: the panel closes
  await expect(page.locator('#filter-panel')).toBeHidden()
  await page.getByRole('button', { name: /Remove filter: organization Northwind/ }).click()
  await expect(page.locator('.pager')).toHaveText(all)
})
