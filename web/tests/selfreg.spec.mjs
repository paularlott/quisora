// Self-registered apps on the tenant page: the sign-in rules dialog turns them on and lists the tenant's resources
// (saved for real, on a tenant of the test's own); the card lists the apps users allowed and revokes one (stubbed:
// no AI client signs in during the run).
import { test, expect } from '@playwright/test'
import { apiCall, axe, fmt, signIn, uniq } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'

test('tenant: self-registered apps setting, resources and the apps card', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`, { waitUntil: 'load' })
  const slug = uniq('sr')
  const resource = `https://${slug}.example.com/mcp`
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'Self reg ' + slug })

  const app = { client_id: 'dyn-abc', name: 'Claude', metadata_document: false, redirect_uris: ['http://127.0.0.1:33418/callback'],
    created: '2026-10-20T10:00:00Z', last_used: '2026-10-20T11:00:00Z', users: 2 }
  let listed = [app]
  let revoked = ''
  await page.route((u) => u.pathname === `${API}/self-registered`, (route) => route.fulfill({ // a page of them: ?offset=…&limit=… status: 200, contentType: 'application/json',
    body: JSON.stringify({ items: listed, total: listed.length }) }))
  await page.route(`**${API}/self-registered/*`, (route) => {
    if (route.request().method() !== 'DELETE') return route.fallback()
    revoked = decodeURIComponent(route.request().url().split('/').pop())
    listed = []
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' })
  })

  await page.goto(`${A}/tenants/${slug}`, { waitUntil: 'load' })
  await expect(page.getByRole('heading', { name: 'Sign-in rules' })).toBeVisible()
  // the tenant's id, for the API, is on the page with a copy button
  await expect(page.locator('#tenant-id')).toHaveText(t.id)
  await expect(page.getByRole('button', { name: 'Copy tenant ID' })).toBeVisible()
  expect((await apiCall(page, 'GET', `${API}/tenants/${slug}`)).id).toBe(t.id) // the API takes the name too
  await expect(page.getByRole('region', { name: 'Sign-in rules' }).locator('.kv')).toContainText('Self-registered apps')
  await expect(page.getByRole('region', { name: 'Sign-in rules' }).locator('.kv')).toContainText('Not allowed')
  // the card shows while the tenant has authorized apps, even with the switch off
  const card = page.getByRole('region', { name: 'Self-registered apps', exact: true })
  await expect(card).toContainText('Claude')
  await expect(card).toContainText('127.0.0.1:33418')
  await expect(card).toContainText('2 users')

  // turn them on and list a resource
  await page.getByRole('button', { name: 'Edit sign-in rules' }).click()
  const dlg = page.getByRole('dialog')
  await dlg.getByRole('switch', { name: 'Allow self-registered apps' }).check()
  await dlg.getByRole('button', { name: 'Add resource' }).click()
  await dlg.getByLabel('Resource 1', { exact: true }).fill(resource)
  let r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await dlg.getByRole('button', { name: 'Save' }).click()
  await expect(dlg).toBeHidden()
  const saved = await apiCall(page, 'GET', `${API}/tenants/${t.id}`)
  expect(saved.settings.self_registration).toBe(true)
  expect(saved.resources).toEqual([resource])
  await expect(page.getByRole('region', { name: 'Sign-in rules' }).locator('.kv')).toContainText('For ' + resource)

  // a resource another tenant owns is refused at the field
  const other = await apiCall(page, 'POST', `${API}/tenants`, { name: uniq('sr2'), display_name: 'Other' })
  const res = await page.evaluate(async ([api, id, resource]) => {
    const csrf = document.querySelector('meta[name="csrf-token"]').content
    const x = await fetch(`${api}/tenants/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, Accept: 'application/json' }, body: JSON.stringify({ resources: [resource] }) })
    return [x.status, await x.json()]
  }, [API, other.id, resource])
  expect(res[0]).toBe(409)
  expect(res[1].field).toBe('resources')

  // revoke from the card
  await card.getByRole('button', { name: 'Revoke Claude' }).click()
  const confirm = page.getByRole('dialog', { name: 'Revoke app?' })
  await expect(confirm).toContainText('Every user')
  await confirm.getByRole('button', { name: 'Revoke' }).click()
  await expect(page.getByText('Claude revoked.').first()).toBeVisible()
  expect(revoked).toBe('dyn-abc')
  await expect(card).toContainText('No self-registered app has been allowed yet.')
  r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})
