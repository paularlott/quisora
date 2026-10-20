// Client dialog with several list-editor rows: a new client with a server-reported row error, and an edit dialog of a
// client that has several redirect URIs, post-logout URIs and custom scopes. Each page makes its own tenant through the
// admin API so the shared demo data (and the other pages' tables) stay untouched.
import { apiCall, uniq } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/v1/orgs/acme'

async function ownTenant(p) {
  const slug = uniq('cl')
  const t = await apiCall(p, 'POST', `${API}/tenants`, { name: slug, display_name: 'Client rows ' + slug })
  return { slug, id: t.id }
}

async function gotoTenant(p, slug) {
  await p.goto(new URL(`${A}/tenants/${slug}`, p.url()).href, { waitUntil: "load" })
  await p.waitForTimeout(300)
}

export const CLIENT_PAGES = [
  { name: 'tenant-access-dialog', path: `${A}/tenants/staff`, as: 'admin', dialog: true, steps: [
    async (p) => {
      const t = await ownTenant(p)
      const alan = (await apiCall(p, 'GET', `${API}/users?q=alan`)).items[0]
      await apiCall(p, 'POST', `${API}/tenants/${t.id}/access`, { subject_type: 'user', subject_id: alan.id, roles: ['editor'], tags: ['team:blue'], expires: '2099-01-01' })
      await apiCall(p, 'POST', `${API}/clients`, { name: 'Portal', tenant_id: t.id, redirect_uris: ['https://portal.example/cb'] })
      await gotoTenant(p, t.slug)
    },
    async (p) => {
      await p.getByRole('button', { name: 'Add access' }).click()
      await p.locator('#f-acc_subject').fill('a')
      await p.locator('#acc-picks [role=option]').first().waitFor()
      await p.keyboard.press('ArrowDown')
      await p.getByRole('switch', { name: /All of this tenant's applications/ }).uncheck()
      await p.locator('#f-roles').fill('bad role!')
      await p.keyboard.press('Enter')
      await p.waitForTimeout(400)
    }] },
  { name: 'tenant-client-new-rows', path: `${A}/tenants/staff`, as: 'admin', dialog: true, steps: [
    async (p) => { const t = await ownTenant(p); await gotoTenant(p, t.slug) },
    async (p) => {
      await p.getByRole('button', { name: 'New client' }).click()
      await p.locator('#f-name').fill('Row demo')
      await p.getByLabel('Redirect URI 1', { exact: true }).fill('https://app.example.com/callback')
      await p.getByRole('button', { name: 'Add URI' }).first().click()
      await p.getByLabel('Redirect URI 2', { exact: true }).fill('http://nope.example.com/cb')
      await p.keyboard.press('Enter')
      await p.getByLabel('Redirect URI 3', { exact: true }).fill('com.example.app:/callback')
      await p.getByRole('button', { name: 'Add URI' }).nth(1).click()
      await p.getByLabel('Post-logout redirect URI 1', { exact: true }).fill('https://app.example.com/signed-out')
      await p.locator('#f-custom_scopes').fill('orders:read billing.write ')
      await p.getByRole('button', { name: 'Create client' }).click()
      await p.locator('#f-redirect_uris .field-error:not(:empty)').first().waitFor()
      await p.waitForTimeout(450)
    }] },
  { name: 'tenant-client-edit-rows', path: `${A}/tenants/staff`, as: 'admin', dialog: true, steps: [
    async (p) => {
      const t = await ownTenant(p)
      await apiCall(p, 'POST', `${API}/clients`, { name: 'Many rows', tenant_id: t.id,
        redirect_uris: ['https://app.example.com/callback', 'https://staging.example.com/callback', 'http://localhost:3000/callback', 'com.example.app:/callback'],
        post_logout_redirect_uris: ['https://app.example.com/signed-out', 'https://staging.example.com/signed-out'],
        backchannel_logout_uri: 'https://app.example.com/backchannel', scopes: ['openid', 'profile', 'groups', 'orders:read', 'billing.write'] })
      await gotoTenant(p, t.slug)
      await p.waitForSelector('tbody tr')
      await p.getByRole('button', { name: 'Edit Many rows' }).click()
      await p.waitForTimeout(450)
      await p.locator("#f-custom_scopes").scrollIntoViewIfNeeded()
      await p.locator("#f-custom_scopes").evaluate((el) => el.scrollIntoView({ block: "end" }))
      await p.waitForTimeout(250)
    }] },
]
