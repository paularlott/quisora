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
  await page.getByRole('button', { name: 'Start verification' }).click() // who placed the call is not said yet
  await expect(page.locator('#e-direction')).toContainText('Say who placed the call')
  await page.getByLabel('They called us').check()
  await expect(page.locator('#e-direction')).toBeEmpty() // answered: the message goes
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
  await expect(entry.locator('strong', { hasText: 'You called' })).toBeVisible() // the direction, in bold
  await expect(entry).not.toContainText(code)
  await shot(page, '3-customer-enter')
  const wrong = code === '000000' ? '111111' : '000000'
  await page.getByLabel(/Code you were given/).fill(wrong) // checked as soon as all six are in
  await expect(page.locator('.toasts')).toContainText('not right') // as code fields say it: a toast, the boxes stay put
  await page.getByLabel(/Code you were given/).fill(code)
  const ask = page.locator('section[aria-labelledby="ask-h"]')
  await expect(ask).toContainText('Grace Hopper')
  await expect(ask).toContainText('INC-9: billing question')
  await expect(ask).toContainText('You called Acme Corporation') // as Grace said: he called her
  await expect(ask).toContainText('If someone called you, this is not your call')
  await expect(ask).toContainText('Only confirm if you are on a call with Grace Hopper')
  await shot(page, '4-customer-ask')
  await ask.getByRole('button', { name: /Yes, it’s me/ }).click()
  const done = page.locator('section[aria-labelledby="done-h"]')
  await expect(done).toContainText('you are verified')
  const past = page.locator('section[aria-labelledby="past-h"]').getByRole('row', { name: /Grace Hopper/ }).first()
  await expect(past).toContainText('Confirmed')
  await expect(past).toContainText('You called Acme Corporation')
  await shot(page, '5-customer-done')

  // Grace sees it confirmed among today's
  await signIn(page, 'manager')
  await page.goto('/o/acme/account/verify-caller', { waitUntil: 'load' })
  const row = page.locator('section[aria-labelledby="today-h"]').getByRole('row', { name: /Alan Turing/ }).first()
  await expect(row).toContainText('Confirmed')
  await expect(row).toContainText('They called you')
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
  // nobody has started one for Alan: no code box, just what to expect
  await expect(page.getByRole('heading', { name: 'Nobody is verifying you right now' })).toBeVisible()
  await expect(page.getByLabel(/Code you were given/)).toBeHidden()
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

// A reload while the caller has the code: the page shows the verification again, with its code (kept by this browser
// until it runs out). Without it (another browser, or the storage cleared) it says so, and the list cancels it.
test('caller verification: a reload shows the waiting verification again, and the list opens or cancels it', async ({ page }) => {
  await signIn(page, 'manager')
  await page.goto('/o/acme/account/verify-caller', { waitUntil: 'load' })
  await page.getByRole('combobox', { name: 'Person' }).fill('katherine')
  await page.getByRole('option', { name: /Katherine/ }).first().click()
  await page.getByLabel('They called us').check()
  await page.getByRole('button', { name: 'Start verification' }).click()
  const codeEl = page.locator('.verify-code')
  await expect(codeEl).toBeVisible()
  const code = await codeEl.innerText()
  await page.reload({ waitUntil: 'load' })
  await expect(page.locator('section[aria-labelledby="current-h"]')).toContainText('Verifying Katherine')
  await expect(codeEl).toHaveText(code)
  // the code not kept here: the page says so; the list cancels it
  await page.evaluate(() => localStorage.clear())
  await page.reload({ waitUntil: 'load' })
  await expect(page.getByText('is not kept here')).toBeVisible()
  await expect(codeEl).toBeHidden()
  const row = page.locator('section[aria-labelledby="today-h"]').getByRole('row', { name: /Katherine/ }).first()
  await expect(row.getByRole('button', { name: /^Open/ })).toBeVisible()
  await row.getByRole('button', { name: /^Cancel/ }).click()
  await expect(row).toContainText('Cancelled')
  await expect(row.getByRole('button', { name: /^Open/ })).toBeHidden()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

// Both pages follow each other through the person's own stream (Server-Sent Events): Alan's page shows Grace's
// verification as soon as she starts it, and hers his answer as soon as he gives it, sooner than either page's slow
// fallback look (15 and 10 seconds) could.
test('caller verification: the caller’s page and the agent’s follow each other live', async ({ browser }) => {
  const { baseURL, ignoreHTTPSErrors } = test.info().project.use // a context of our own does not take the project's
  const alanCtx = await browser.newContext({ baseURL, ignoreHTTPSErrors })
  const graceCtx = await browser.newContext({ baseURL, ignoreHTTPSErrors })
  try {
    const alan = await alanCtx.newPage()
    const grace = await graceCtx.newPage()
    await signIn(alan, 'user')
    await alan.goto('/o/acme/account/verify-call', { waitUntil: 'load' })
    await expect(alan.getByRole('heading', { name: 'Nobody is verifying you right now' })).toBeVisible()
    await signIn(grace, 'manager')
    await grace.goto('/o/acme/account/verify-caller', { waitUntil: 'load' })
    await grace.getByRole('combobox', { name: 'Person' }).fill('alan')
    await grace.getByRole('option', { name: /Alan Turing/ }).click()
    await grace.getByLabel('Why').fill('INC-12: live')
    await grace.getByLabel('We called them').check()
    await grace.getByRole('button', { name: 'Start verification' }).click()
    await expect(grace.locator('.verify-code')).toHaveText(/^\d{3} \d{3}$/)
    const code = (await grace.locator('.verify-code').innerText()).replace(/\s/g, '')

    const entry = alan.locator('section[aria-labelledby="code-h"]')
    await expect(entry).toContainText('INC-12: live', { timeout: 5000 })
    await expect(entry).toContainText('Acme Corporation called you')
    await alan.getByLabel(/Code you were given/).fill(code)
    await alan.locator('section[aria-labelledby="ask-h"]').getByRole('button', { name: /Yes, it’s me/ }).click()
    await expect(alan.locator('section[aria-labelledby="done-h"]')).toContainText('you are verified')

    await expect(grace.locator('section[aria-labelledby="current-h"]')).toContainText('Confirmed', { timeout: 5000 })
  } finally {
    await alanCtx.close()
    await graceCtx.close()
  }
})

// The call_verify scope of a personal API token (a CRM verifying callers as its owner) is offered to agents only; the
// organization's overview lists its caller verification API for such CRMs.
test('caller verification: agents may make a token to verify callers from a CRM, others are not offered it', async ({ page }) => {
  await signIn(page, 'manager') // Grace, an agent
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  await page.locator('#tokens').getByRole('button', { name: 'New token' }).click()
  let dlg = page.getByRole('dialog', { name: 'New API token' })
  await expect(dlg.getByRole('checkbox', { name: /Verify callers as you/ })).toBeVisible()
  await signIn(page, 'user') // Alan, not one
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  await page.locator('#tokens').getByRole('button', { name: 'New token' }).click()
  dlg = page.getByRole('dialog', { name: 'New API token' })
  await expect(dlg.getByRole('checkbox').first()).toBeVisible()
  await expect(dlg.getByRole('checkbox', { name: /Verify callers as you/ })).toHaveCount(0)
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
  await expect(page.getByText('Caller verification API (for CRMs)')).toBeVisible()
})
