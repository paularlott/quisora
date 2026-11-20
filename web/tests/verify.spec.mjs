// Caller verification (docs/CALLER-VERIFICATION.md): an agent of acme (Grace, in Customer support) verifies a caller (Alan),
// who enters the code on his own account and confirms it is him; an agent of the primary organization (the super
// admin, in Support desk) also finds people of the organizations that let it (Northwind); and the menu shows each page
// only to whom it concerns.
import { test, expect } from '@playwright/test'
import { signIn, axe, fmt } from './helpers.mjs'

const SHOTS = process.env.VERIFY_SHOTS || '' // a folder to save screenshots of the pages in, when set

async function shot(page, name) {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true })
}

test('caller verification: Grace verifies Alan, who enters her code and confirms it is him', async ({ page }) => {
  // Grace, an agent of acme: Verify a caller is in her menu; acme's people only, so she is asked only for the person
  await signIn(page, 'manager')
  await page.goto('/o/acme/account/verify-caller', { waitUntil: 'load' })
  await page.getByRole('button', { name: 'Account menu' }).click()
  await expect(page.locator('#user-menu').getByRole('link', { name: 'Verify a caller' })).toBeVisible()
  await page.keyboard.press('Escape')
  const person = page.getByRole('combobox', { name: 'Person' })
  await expect(person).toBeVisible()
  await expect(page.getByRole('combobox', { name: 'Organization' })).toBeHidden()
  await person.fill('alan')
  await page.getByRole('option', { name: /Alan Turing/ }).click()
  await page.getByLabel('Why').fill('INC-9: billing question')
  await shot(page, '1-agent-start')
  await page.getByRole('button', { name: 'Start verification' }).click()
  const current = page.locator('section[aria-labelledby="current-h"]')
  await expect(current).toContainText('Verifying Alan Turing')
  await expect(current).toContainText('Waiting')
  const code = (await page.locator('.verify-code').innerText()).replace(/\s/g, '')
  expect(code).toMatch(/^\d{6}$/)
  await shot(page, '2-agent-code')

  // Alan: Verify a call is in his menu; a wrong code is refused, the right one shows who asks
  await signIn(page, 'user')
  await page.goto('/o/acme/account/verify-call', { waitUntil: 'load' })
  await page.getByRole('button', { name: 'Account menu' }).click()
  await expect(page.locator('#user-menu').getByRole('link', { name: 'Verify a call' })).toBeVisible()
  await expect(page.locator('#user-menu').getByRole('link', { name: 'Verify a caller' })).toHaveCount(0)
  await page.keyboard.press('Escape')
  // who is verifying him now shows above the code (never the code itself)
  const entry = page.locator('section[aria-labelledby="code-h"]')
  await expect(entry).toContainText('Verifying you now')
  await expect(entry).toContainText('Grace Hopper')
  await expect(entry).toContainText('Why: INC-9: billing question')
  await expect(entry).not.toContainText(code)
  await shot(page, '3-customer-enter')
  const wrong = code === '000000' ? '111111' : '000000'
  await page.getByLabel(/Code you were given/).fill(wrong) // checked as soon as all six are in
  await expect(page.locator('.toasts')).toContainText('not right') // as code fields say it: a toast, the boxes stay put
  await page.getByLabel(/Code you were given/).fill(code)
  const ask = page.locator('section[aria-labelledby="ask-h"]')
  await expect(ask).toContainText('Grace Hopper')
  await expect(ask).toContainText('INC-9: billing question')
  await expect(ask).toContainText('Only confirm if you are on a call with Grace Hopper')
  await shot(page, '4-customer-ask')
  await ask.getByRole('button', { name: /Yes, it’s me/ }).click()
  const done = page.locator('section[aria-labelledby="done-h"]')
  await expect(done).toContainText('you are verified')
  await expect(page.locator('section[aria-labelledby="past-h"]').getByRole('row', { name: /Grace Hopper/ }).first()).toContainText('Confirmed')
  await shot(page, '5-customer-done')

  // Grace sees it confirmed among today's
  await signIn(page, 'manager')
  await page.goto('/o/acme/account/verify-caller', { waitUntil: 'load' })
  const row = page.locator('section[aria-labelledby="today-h"]').getByRole('row', { name: /Alan Turing/ }).first()
  await expect(row).toContainText('Confirmed')
  await shot(page, '6-agent-today')
})

test('caller verification: the primary organization’s agents choose the organization, among those that let them', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/o/primary/account/verify-caller', { waitUntil: 'load' })
  const org = page.getByRole('combobox', { name: 'Organization' })
  await expect(org).toBeVisible() // Northwind lets the primary organization's agents verify its people
  await expect(org).not.toHaveValue('') // their own to start with
  await org.fill('North')
  await page.getByRole('option', { name: /Northwind/ }).click()
  await page.getByRole('combobox', { name: 'Person' }).fill('pat')
  await expect(page.getByRole('option', { name: /Pat Passkey/ })).toBeVisible()
  await org.fill('Acme') // acme does not
  await expect(page.locator('#l-org').getByRole('option')).toHaveCount(0)
  await shot(page, '7-primary-agent')
})

test('caller verification pages: no accessibility violations', async ({ page }) => {
  await signIn(page, 'manager')
  await page.goto('/o/acme/account/verify-caller', { waitUntil: 'load' })
  await expect(page.getByRole('combobox', { name: 'Person' })).toBeVisible()
  let r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await signIn(page, 'user')
  await page.goto('/o/acme/account/verify-call', { waitUntil: 'load' })
  await expect(page.getByLabel(/Code you were given/)).toBeVisible()
  await expect(page.getByText('Nobody is verifying you right now.')).toBeVisible() // nobody has started one for Alan
  r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

// The organization's settings: who verifies callers (agent groups, added by search as chips) and whether the primary
// organization's agents may verify its people. Saves are stubbed, as the demo store is shared by the run.
test('organization: caller verification settings are shown, chosen by search, and saved', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs')
  await page.waitForSelector('tbody tr')
  await page.getByRole('button', { name: 'Edit Acme Corporation' }).first().click()
  const dlg = page.getByRole('dialog', { name: 'Edit organization' })
  await expect(dlg.getByRole('switch', { name: /Agents can verify callers/ })).toBeChecked() // as the demo's Acme is set up
  await expect(dlg.getByRole('list', { name: 'Agent groups' })).toContainText('Customer support')
  const byPrimary = dlg.getByRole('switch', { name: /Let the primary organization’s agents verify/ })
  await expect(byPrimary).not.toBeChecked()
  await byPrimary.check()
  const r = await axe(page, { include: '#org-dialog' })
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  let saved = null
  await page.route('**/api/orgs/acme', (route) => {
    if (route.request().method() !== 'PATCH') return route.fallback()
    saved = route.request().postDataJSON()
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'x', name: 'acme', settings: saved.settings }) })
  })
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(dlg).toBeHidden()
  expect(saved.settings.verify_callers).toBe(true)
  expect(saved.settings.verify_agent_groups).toHaveLength(1)
  expect(saved.settings.verified_by_primary).toBe(true)
})
