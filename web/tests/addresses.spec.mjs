// The addresses an organization is shared and configured with, each to copy: its overview page, the organizations
// list, a tenant page and the dialog of a client just created.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'

// Click a copy button: it announces what it copied (in the dialog's live region when one is open); returns the clipboard.
async function copied(page, button, what) {
  await button.click()
  const open = (await page.locator('dialog[open]').count()) > 0
  await expect(page.locator(open ? 'dialog[open] [data-live=polite]' : '#live-polite')).toContainText('Copied ' + what)
  return page.evaluate(() => navigator.clipboard.readText())
}

test('org overview: sign-in page, issuer, discovery URL and SCIM base URL to copy', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await signIn(page, 'admin')
  await page.goto(A, { waitUntil: 'load' })
  const org = await apiCall(page, 'GET', API)
  const pub = new URL(page.url()).origin
  const card = page.getByRole('region', { name: 'Addresses' })
  await expect(card.locator('#addr-signin')).toHaveText(`${pub}/o/acme/login`)
  await expect(card.locator('#addr-issuer')).toHaveText(`${pub}/o/${org.id}`)
  expect(await copied(page, card.getByRole('button', { name: 'Copy Sign-in page' }), 'sign-in page address')).toBe(`${pub}/o/acme/login`)
  expect(await copied(page, card.getByRole('button', { name: 'Copy Issuer (for applications)' }), 'issuer')).toBe(`${pub}/o/${org.id}`)
  const discovery = `${pub}/o/${org.id}/.well-known/openid-configuration`
  await expect(card.locator('#addr-discovery')).toHaveText(discovery)
  expect(await copied(page, card.getByRole('button', { name: 'Copy Discovery URL (OpenID configuration)' }), 'discovery URL')).toBe(discovery)
  expect((await (await page.request.get(discovery)).json()).issuer).toBe(`${pub}/o/${org.id}`)
  await expect(card.locator('#addr-scim')).toHaveText(`${pub}/scim/v2/acme`)
  expect(await copied(page, card.getByRole('button', { name: 'Copy SCIM base URL (for provisioning tools)' }), 'SCIM base URL')).toBe(`${pub}/scim/v2/acme`)
})

test('org overview: a super admin gets the SCIM base URL too', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto(A, { waitUntil: 'load' })
  const pub = new URL(page.url()).origin
  await expect(page.getByRole('region', { name: 'Addresses' }).locator('#addr-scim')).toHaveText(`${pub}/scim/v2/acme`)
})

test('organizations list: each row copies its sign-in link', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  const pub = new URL(page.url()).origin
  const btn = page.getByRole('button', { name: 'Copy sign-in link for Acme Corporation' })
  await expect(btn).toBeVisible()
  // the row's icon buttons (copy, edit, delete) sit in one line, the copy button no lower than the others
  const tops = await page.getByRole('row', { name: /Acme Corporation/ }).first().locator('td.actions .btn:visible')
    .evaluateAll((bs) => bs.map((b) => Math.round(b.getBoundingClientRect().top)))
  expect(tops.length).toBeGreaterThan(1)
  expect(new Set(tops).size, `button tops ${tops}`).toBe(1)
  expect(await copied(page, btn, 'sign-in link')).toBe(`${pub}/o/acme/login`)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('client dialog: a confidential client shows client ID, issuer, discovery URL and secret; a public one no secret', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/customers/clients`, { waitUntil: 'load' })
  const org = await apiCall(page, 'GET', API)
  const pub = new URL(page.url()).origin
  const dlg = page.getByRole('dialog', { name: 'Client created' })
  const create = async (name, method) => {
    await page.getByRole('button', { name: 'New client' }).click()
    await page.locator('#f-name').fill(name)
    if (method) await page.locator('#f-token_endpoint_auth_method').selectOption(method)
    await page.getByLabel('Redirect URI 1', { exact: true }).fill('https://addr.example/cb')
    await page.getByRole('button', { name: 'Create client' }).click()
    await expect(dlg).toBeVisible()
  }
  await create('Addr confidential')
  const id = (await dlg.locator('#client-id').innerText()).trim()
  expect((await apiCall(page, 'GET', `${API}/clients/${id}`)).name).toBe('Addr confidential')
  await expect(dlg.locator('#client-issuer')).toHaveText(`${pub}/o/${org.id}`)
  expect((await dlg.locator('#client-secret').innerText()).trim()).toMatch(/^qsrs_/)
  await expect(dlg.getByText('The secret is shown once')).toBeVisible()
  expect(await copied(page, dlg.getByRole('button', { name: 'Copy client ID' }), 'client ID')).toBe(id)
  expect(await copied(page, dlg.getByRole('button', { name: 'Copy issuer' }), 'issuer')).toBe(`${pub}/o/${org.id}`)
  const discovery = `${pub}/o/${org.id}/.well-known/openid-configuration`
  await expect(dlg.locator('#client-discovery')).toHaveText(discovery)
  expect(await copied(page, dlg.getByRole('button', { name: 'Copy discovery URL' }), 'discovery URL')).toBe(discovery)
  const secret = (await dlg.locator('#client-secret').innerText()).trim()
  expect(await copied(page, dlg.getByRole('button', { name: 'Copy client secret' }), 'client secret')).toBe(secret)
  await dlg.getByRole('button', { name: 'I have stored it' }).click()
  await expect(dlg).toBeHidden()

  await create('Addr public', 'none')
  await expect(dlg.locator('#client-id')).not.toBeEmpty()
  await expect(dlg.locator('#client-issuer')).toHaveText(`${pub}/o/${org.id}`)
  await expect(dlg.getByRole('button', { name: 'Copy client secret' })).toBeHidden()
  await expect(dlg.getByText('The secret is shown once')).toBeHidden()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await dlg.getByRole('button', { name: 'Done' }).click()
  await expect(dlg).toBeHidden()
})

test('tenant page: the issuer URL and the discovery URL to copy, named beside the tenant ID', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/staff`, { waitUntil: 'load' })
  const org = await apiCall(page, 'GET', API)
  const pub = new URL(page.url()).origin
  const head = page.locator('.page-head')
  await expect(head.getByRole('button', { name: 'Copy issuer URL' })).toHaveAttribute('title', 'Copy issuer URL')
  expect(await copied(page, head.getByRole('button', { name: 'Copy issuer URL' }), 'issuer URL')).toBe(`${pub}/o/${org.id}`)
  expect(await copied(page, head.getByRole('button', { name: 'Copy discovery URL' }), 'discovery URL'))
    .toBe(`${pub}/o/${org.id}/.well-known/openid-configuration`)
})
