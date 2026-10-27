// API token applications and scopes: an api token lists the applications it can be for and their own scopes; ticking
// applications narrows the scope list; the request carries both; editing changes them (the expiry stays). The server
// is stubbed: the demo store is shared by the run.
import { test, expect } from '@playwright/test'
import { axe, fmt, signIn } from './helpers.mjs'

const apps = [{ id: 'app-orders', name: 'Orders', scopes: ['orders:read', 'orders:write'] }, { id: 'app-billing', name: 'Billing', scopes: ['billing:read'] }]
const item = { id: 'tok-1', name: 'Reports', scopes: ['api'], audience: ['app-orders'], app_scopes: ['orders:read'],
  created: '2026-10-01T10:00:00Z', expires: '2026-12-01T10:00:00Z', last_used: '0001-01-01T00:00:00Z' }

test('API token: applications and scopes, on create and edit', async ({ page }) => {
  await signIn(page, 'user')
  await page.route('**/api-internal/account/tokens', (route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ items: [item], total: 1, scopes: ['api'], max_days: 0, apps }) })
    }
    created = route.request().postDataJSON()
    return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ token: 'qsr_new_secret', item: { ...item, id: 'tok-2' } }) })
  })
  let created = null
  let patched = null
  await page.route('**/api-internal/account/tokens/tok-1', (route) => {
    if (route.request().method() !== 'PATCH') return route.fallback()
    patched = route.request().postDataJSON()
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ item }) })
  })
  await page.goto('/o/acme/account')
  await expect(page.getByRole('row', { name: /Reports/ })).toContainText('for Orders; only orders:read')

  // create: no scopes until an application is ticked, then only that application's
  await page.getByRole('button', { name: 'New token' }).click()
  const dlg = page.getByRole('dialog', { name: 'New API token' })
  await page.locator('#f-tk_name').fill('Exports')
  const scopes = dlg.getByRole('group', { name: 'Limit to these scopes' })
  const appsBox = dlg.getByRole('group', { name: 'Applications' })
  await expect(scopes).toBeHidden()
  await appsBox.getByRole('checkbox', { name: 'Billing', exact: true }).check()
  await expect(scopes.getByRole('checkbox')).toHaveCount(1)
  await appsBox.getByRole('checkbox', { name: 'Billing', exact: true }).uncheck()
  await appsBox.getByRole('checkbox', { name: 'Orders', exact: true }).check()
  await expect(scopes.getByRole('checkbox')).toHaveCount(2)
  await expect(scopes).not.toContainText('billing:read')
  await scopes.getByRole('checkbox', { name: /orders:read/ }).check()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await dlg.getByRole('button', { name: 'Create token' }).click()
  await expect(page.getByRole('dialog', { name: 'Your new token' })).toBeVisible()
  expect(created).toMatchObject({ name: 'Exports', scopes: ['api'], audience: ['app-orders'], app_scopes: ['orders:read'] })
  await page.getByRole('dialog', { name: 'Your new token' }).getByRole('button', { name: 'Done' }).click()

  // edit: the saved choices are ticked; the Quisora scopes and the expiry are not editable
  await page.getByRole('button', { name: 'Edit token Reports' }).click()
  const edit = page.getByRole('dialog', { name: 'Edit API token' })
  await expect(edit).toBeVisible()
  await expect(page.locator('#f-tk_name')).toHaveValue('Reports')
  await expect(edit.getByRole('checkbox', { name: 'Orders', exact: true })).toBeChecked()
  await expect(edit.getByRole('checkbox', { name: /orders:read/ })).toBeChecked()
  await expect(edit.getByRole('group', { name: 'Access' })).toBeHidden()
  await expect(edit).toContainText('the expiry cannot be changed')
  // widen back to full access, and to every application
  await edit.getByRole('checkbox', { name: /orders:read/ }).uncheck()
  await edit.getByRole('checkbox', { name: 'Orders', exact: true }).uncheck()
  await edit.getByRole('button', { name: 'Save changes' }).click()
  await expect(edit).toBeHidden()
  expect(patched).toEqual({ name: 'Reports', audience: [], app_scopes: [] })
})
