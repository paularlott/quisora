// Who may make personal API tokens for the organization's applications: the organization's setting (mode and groups,
// in the organization dialog), each application's opt-in (client dialog) and what a person who may not make them is
// shown on their account page. The demo's Acme lets everyone; saves to the organization are stubbed, as the demo store
// is shared by the run.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, uniq, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'

const openAcme = async (page) => {
  await page.goto('/admin/orgs')
  await page.waitForSelector('tbody tr')
  await page.getByRole('button', { name: 'Edit Acme Corporation' }).first().click()
  return page.getByRole('dialog', { name: 'Edit organization' })
}

test('organization: the API token setting is shown, and saved with the chosen groups', async ({ page }) => {
  await signIn(page, 'super')
  const dlg = await openAcme(page)
  const who = dlg.getByRole('combobox', { name: 'Who may make them' })
  await expect(who).toHaveValue('everyone') // as the demo's Acme is set up
  await expect(dlg.getByRole('combobox', { name: 'Groups' })).toBeHidden()

  // choose groups: chips and the search box in one field, as the tag field looks
  await who.selectOption('groups')
  const picker = dlg.getByRole('combobox', { name: 'Groups' })
  await picker.fill('Engin')
  await dlg.getByRole('option', { name: /Engineering/ }).click()
  await picker.fill('Design')
  await dlg.getByRole('option', { name: /Design/ }).click()
  const chosen = dlg.getByRole('list', { name: 'Groups that may make API tokens' })
  await expect(chosen).toContainText('Engineering')
  await expect(chosen).toContainText('Design')
  await picker.fill('Engin') // a chosen group is not offered again
  await expect(dlg.getByRole('option', { name: /Engineering/ })).toHaveCount(0)
  await picker.fill('')
  await picker.press('Backspace') // the empty box takes back the last chip
  await expect(chosen).not.toContainText('Design')
  await picker.fill('Design')
  await dlg.getByRole('option', { name: /Design/ }).click()
  await chosen.getByRole('button', { name: 'Remove Design' }).click()
  await expect(chosen).not.toContainText('Design')
  await expect(picker).toBeFocused()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  let saved = null
  await page.route('**/api/orgs/acme', (route) => {
    if (route.request().method() !== 'PATCH') return route.fallback()
    saved = route.request().postDataJSON()
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'x', name: 'acme', settings: saved.settings }) })
  })
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(dlg).toBeHidden()
  expect(saved.settings.api_tokens).toBe('groups')
  expect(saved.settings.api_token_groups).toHaveLength(1)
})

test('organization: groups are chosen once the organization exists, and none are sent for the other modes', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs')
  await page.getByRole('button', { name: 'New organization' }).click()
  const create = page.getByRole('dialog', { name: 'New organization' })
  const who = create.getByRole('combobox', { name: 'Who may make them' })
  await expect(who).toHaveValue('off') // an organization starts with nobody
  await expect(who.locator('option[value="groups"]')).toBeDisabled()
  await page.keyboard.press('Escape')

  // a saved choice of groups is dropped when another mode is chosen
  let saved = null
  await page.route('**/api/orgs/acme', (route) => {
    if (route.request().method() !== 'PATCH') return route.fallback()
    saved = route.request().postDataJSON()
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'x', name: 'acme', settings: saved.settings }) })
  })
  const dlg = await openAcme(page)
  await dlg.getByRole('combobox', { name: 'Who may make them' }).selectOption('off')
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(dlg).toBeHidden()
  expect(saved.settings).toMatchObject({ api_tokens: 'off', api_token_groups: [] })
})

test('organization overview: the API token setting is shown to its administrators', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(A)
  await expect(page.getByText('API tokens for applications')).toBeVisible()
  await expect(page.locator('dt', { hasText: 'API tokens for applications' }).locator('xpath=following-sibling::dd')).toHaveText('Everyone may make them')
})

test('client: accepting personal API tokens is a setting of the application, off until chosen, and not for public clients', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`, { waitUntil: 'load' })
  const slug = uniq('at')
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'Tokens ' + slug })
  await page.goto(`${A}/tenants/${slug}`, { waitUntil: 'load' })
  await page.getByRole('button', { name: 'New client' }).click()
  const dlg = page.getByRole('dialog', { name: 'New client' })
  const accepts = dlg.getByRole('switch', { name: /Accepts personal API tokens/ })
  await expect(accepts).not.toBeChecked()
  await page.locator('#f-token_endpoint_auth_method').selectOption('none')
  await expect(accepts).toBeHidden()
  await page.locator('#f-token_endpoint_auth_method').selectOption('client_secret_basic')
  await accepts.check()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await page.locator('#f-name').fill('Orders API')
  await page.getByLabel('Redirect URI 1', { exact: true }).fill('https://orders.example/cb')
  await dlg.getByRole('button', { name: 'Create client' }).click()
  await expect(page.getByRole('dialog', { name: 'Client created' })).toBeVisible()
  await page.keyboard.press('Escape')
  let c = (await apiCall(page, 'GET', `${API}/clients?tenant=${t.id}`)).items[0]
  expect(c.accepts_api_tokens).toBe(true)

  // editing shows it, and it can be turned off again
  await page.getByRole('button', { name: 'Edit Orders API' }).click()
  const edit = page.getByRole('dialog', { name: 'Edit client' })
  await expect(edit.getByRole('switch', { name: /Accepts personal API tokens/ })).toBeChecked()
  await edit.getByRole('switch', { name: /Accepts personal API tokens/ }).uncheck()
  await edit.getByRole('button', { name: 'Save changes' }).click()
  await expect(edit).toBeHidden()
  c = (await apiCall(page, 'GET', `${API}/clients?tenant=${t.id}`)).items[0]
  expect(c.accepts_api_tokens).toBe(false)
})

const tokens = (scopes, apps = []) => (route) => route.request().method() !== 'GET' ? route.fallback()
  : route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ items: [], total: 0, scopes, max_days: 0, apps }) })

test('account: someone who may not make api tokens is not offered them, and with no other scope has no create button', async ({ page }) => {
  await signIn(page, 'user')
  await page.route('**/api-internal/account/tokens', tokens([]))
  await page.goto('/o/acme/account')
  const card = page.locator('#tokens')
  await expect(card.getByText('You cannot make API tokens')).toBeVisible()
  await expect(card.getByRole('button', { name: 'New token' })).toBeHidden()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('account: a manager who may not make api tokens is offered the other scopes only', async ({ page }) => {
  await signIn(page, 'manager')
  await page.route('**/api-internal/account/tokens', tokens(['scim', 'admin']))
  await page.goto('/o/acme/account')
  await page.locator('#tokens').getByRole('button', { name: 'New token' }).click()
  const dlg = page.getByRole('dialog', { name: 'New API token' })
  const access = dlg.getByRole('group', { name: 'Access' })
  await expect(access.getByRole('checkbox')).toHaveCount(2)
  await expect(access.getByRole('checkbox', { name: /Your organization’s applications/ })).toHaveCount(0)
  await expect(dlg.getByRole('group', { name: 'Applications' })).toBeHidden()
  await expect(access.getByRole('checkbox', { checked: true })).toHaveCount(0) // nothing chosen for them
})

test('account: someone who may make api tokens is offered them, with the applications that accept them', async ({ page }) => {
  await signIn(page, 'user')
  await page.goto('/o/acme/account')
  await page.locator('#tokens').getByRole('button', { name: 'New token' }).click()
  const dlg = page.getByRole('dialog', { name: 'New API token' })
  await expect(dlg.getByRole('checkbox', { name: /Your organization’s applications/ })).toBeChecked()
  // the demo's Acme has two applications that accept them (the others, which have not chosen to, are not listed)
  const apps = dlg.getByRole('group', { name: 'Applications' })
  await expect(apps.getByRole('checkbox', { name: 'Customer portal' })).toBeVisible()
  await expect(apps.getByRole('checkbox', { name: 'Billing API' })).toBeVisible()
})
