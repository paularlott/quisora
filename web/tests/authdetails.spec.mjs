// Authorization details (RFC 9396): the client dialog's types and its own tokens' details, and the access dialog's
// details; a text that is not a JSON array is refused before anything is sent, the server's errors show on the field.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, uniq, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'
const TOPICS = 'https://example.com/topics'

async function freshTenant(page) {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`, { waitUntil: 'load' })
  const slug = uniq('ad')
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'Details ' + slug, settings: { members_only: true } })
  const portal = await apiCall(page, 'POST', `${API}/clients`, { name: 'Portal', tenant_id: t.id, redirect_uris: ['https://portal.example/cb'] })
  await page.goto(`${A}/tenants/${slug}`, { waitUntil: 'load' })
  await page.getByRole('button', { name: 'Add access' }).waitFor()
  return { slug, id: t.id, portal }
}

test('client dialog: authorization details types, and its own tokens’ details with client credentials', async ({ page }) => {
  const t = await freshTenant(page)
  await page.goto(`${A}/tenants/${t.slug}/clients`, { waitUntil: 'load' })
  await page.getByRole('button', { name: 'Edit Portal' }).click()
  const dlg = page.getByRole('dialog', { name: 'Edit client' })
  await expect(dlg).toBeVisible()
  const details = page.locator('#f-authorization_details')
  // only for an application that acts as itself
  await expect(details).toBeHidden()
  await dlg.getByRole('button', { name: 'Add type' }).click()
  await dlg.getByRole('textbox', { name: 'Authorization details type 1' }).fill(TOPICS)
  await dlg.getByRole('checkbox', { name: /^Client credentials/ }).check()
  await expect(details).toBeVisible()
  // not a JSON array: refused here, nothing sent
  await details.fill('{"type": "x"}')
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.locator('#e-authorization_details')).toContainText('JSON array')
  await expect(details).toHaveAttribute('aria-invalid', 'true')
  // the server's own check (an unknown placeholder) shows on the same field
  await details.fill(`[{"type": "${TOPICS}", "topics": [{"match": "{{user}}"}]}]`)
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.locator('#e-authorization_details')).toContainText('placeholder')
  let r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await details.fill(`[{"type": "${TOPICS}", "actions": ["publish"], "topics": [{"match": "https://chat.example/{{sub}}"}]}]`)
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(dlg).toBeHidden()
  const saved = await apiCall(page, 'GET', `${API}/clients/${t.portal.id}`)
  expect(saved.authorization_details_types).toEqual([TOPICS])
  expect(saved.authorization_details).toEqual([{ type: TOPICS, actions: ['publish'], topics: [{ match: 'https://chat.example/{{sub}}' }] }])
  // edit shows them again
  await page.getByRole('button', { name: 'Edit Portal' }).click()
  await expect(dlg.getByRole('textbox', { name: 'Authorization details type 1' })).toHaveValue(TOPICS)
  await expect(details).toHaveValue(/"publish"/)
})

test('access dialog: authorization details round-trip, a bad text is refused on the field', async ({ page }) => {
  const t = await freshTenant(page)
  const alan = (await apiCall(page, 'GET', `${API}/users?q=alan`)).items.find((u) => u.username === 'alan')
  await apiCall(page, 'POST', `${API}/tenants/${t.id}/access`, { subject_type: 'user', subject_id: alan.id,
    authorization_details: [{ type: TOPICS, actions: ['subscribe'], topics: [{ match: 'https://chat.example/users/{{sub}}' }] }] })
  await page.reload({ waitUntil: 'load' })
  await page.getByRole('button', { name: 'Edit access for Alan Turing' }).click()
  const dlg = page.getByRole('dialog', { name: 'Edit access' })
  await expect(dlg).toBeVisible()
  const details = dlg.getByRole('textbox', { name: 'Authorization details' })
  await expect(details).toHaveValue(/users\/\{\{sub\}\}/)
  await details.fill('not json')
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.locator('#e-authorization_details')).toContainText('JSON array')
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  // emptied: removed
  await details.fill('')
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(dlg).toBeHidden()
  const list = await apiCall(page, 'GET', `${API}/tenants/${t.id}/access`)
  expect(list.items[0].authorization_details).toBeUndefined()
})
