// The client dialog's list editors (redirect URIs, post-logout redirect URIs, custom scopes) and standard scope
// checkboxes: keyboard use, row errors, a11y in this theme (axe), and the JSON that is saved.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, uniq, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/v1/orgs/acme'

async function freshTenant(page) {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`, { waitUntil: 'load' })
  const slug = uniq('lf')
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'List ' + slug })
  await page.goto(`${A}/tenants/${slug}`, { waitUntil: 'load' })
  await page.getByRole('button', { name: 'New client' }).waitFor()
  return { slug, id: t.id }
}

const row = (page, item, n) => page.getByLabel(`${item} ${n}`, { exact: true })

test('list editor: add with the button and Enter, remove with the delete button, focus moves sensibly, save', async ({ page }) => {
  const t = await freshTenant(page)
  await page.getByRole('button', { name: 'New client' }).click()
  const dlg = page.getByRole('dialog', { name: 'New client' })
  await page.locator('#f-name').fill('Keys')
  // an empty list shows one empty row; its delete button is named by position
  await expect(dlg.getByRole('textbox', { name: /^Redirect URI \d/ })).toHaveCount(1)
  await expect(dlg.getByRole('button', { name: 'Remove row 1' }).first()).toBeVisible()
  await row(page, 'Redirect URI', 1).fill('https://one.example/cb')
  await expect(dlg.getByRole('button', { name: 'Remove https://one.example/cb' })).toBeVisible()
  // Enter adds a row below and focuses it (and does not submit the form)
  await page.keyboard.press('Enter')
  await expect(row(page, 'Redirect URI', 2)).toBeFocused()
  await expect(dlg).toBeVisible()
  await row(page, 'Redirect URI', 2).fill('https://two.example/cb')
  // the Add button appends at the end and focuses the new row
  await dlg.getByRole('button', { name: 'Add URI' }).first().focus()
  await page.keyboard.press('Enter')
  await expect(row(page, 'Redirect URI', 3)).toBeFocused()
  await row(page, 'Redirect URI', 3).fill('https://three.example/cb')
  // Enter in the middle row inserts below it, before row 3
  await row(page, 'Redirect URI', 2).focus()
  await page.keyboard.press('Enter')
  await expect(row(page, 'Redirect URI', 3)).toBeFocused()
  await expect(row(page, 'Redirect URI', 3)).toHaveValue('')
  await expect(row(page, 'Redirect URI', 4)).toHaveValue('https://three.example/cb')
  // removing the empty row focuses the previous row
  await dlg.getByRole('button', { name: 'Remove row 3' }).click()
  await expect(row(page, 'Redirect URI', 2)).toBeFocused()
  // removing the first row focuses what is now the first row
  await dlg.getByRole('button', { name: 'Remove https://one.example/cb' }).click()
  await expect(row(page, 'Redirect URI', 1)).toBeFocused()
  await expect(row(page, 'Redirect URI', 1)).toHaveValue('https://two.example/cb')
  // post-logout URIs and custom scopes are optional: they start with no rows, just their Add buttons
  await expect(dlg.getByRole('textbox', { name: /^Post-logout redirect URI \d/ })).toHaveCount(0)
  await expect(dlg.getByRole('textbox', { name: /^Scope \d/ })).toHaveCount(0)
  const addLogout = dlg.getByRole('button', { name: 'Add URI' }).nth(1)
  await addLogout.click()
  await expect(row(page, 'Post-logout redirect URI', 1)).toBeFocused()
  await row(page, 'Post-logout redirect URI', 1).fill('https://one.example/bye')
  // removing the only row leaves none and moves focus to the Add button
  await dlg.getByRole('button', { name: 'Remove https://one.example/bye' }).click()
  await expect(dlg.getByRole('textbox', { name: /^Post-logout redirect URI \d/ })).toHaveCount(0)
  await expect(addLogout).toBeFocused()
  // custom scopes, an empty row is ignored; standard scopes are checkboxes with descriptions
  await expect(dlg.getByText("The user’s group names and tags")).toBeVisible()
  await dlg.getByRole('checkbox', { name: /^groups/ }).check()
  await dlg.getByRole('button', { name: 'Add scope' }).click()
  await row(page, 'Scope', 1).fill('orders:read')
  await dlg.getByRole('button', { name: 'Add scope' }).click()
  await dlg.getByRole('button', { name: 'Create client' }).click()
  await expect(page.getByRole('dialog', { name: 'Client created' })).toBeVisible()
  await page.keyboard.press('Escape')
  const saved = (await apiCall(page, 'GET', `${API}/clients?tenant=${t.id}`)).items[0]
  expect(saved.redirect_uris).toEqual(['https://two.example/cb', 'https://three.example/cb'])
  expect(saved.post_logout_redirect_uris).toEqual([])
  expect(saved.scopes).toEqual(['openid', 'profile', 'email', 'groups', 'orders:read'])
})

test('list editor: a server error lands on its row, and a standard scope is refused in the custom list', async ({ page }) => {
  await freshTenant(page)
  await page.getByRole('button', { name: 'New client' }).click()
  const dlg = page.getByRole('dialog', { name: 'New client' })
  await page.locator('#f-name').fill('Errors')
  await row(page, 'Redirect URI', 1).fill('https://ok.example/cb')
  await page.keyboard.press('Enter')
  await row(page, 'Redirect URI', 2).fill('http://bad.example/cb')
  await dlg.getByRole('button', { name: 'Create client' }).click()
  const bad = row(page, 'Redirect URI', 2)
  await expect(bad).toHaveAttribute('aria-invalid', 'true')
  await expect(bad).toBeFocused()
  const err = await bad.getAttribute('aria-describedby')
  await expect(page.locator('#' + err)).toContainText('http://bad.example/cb must be')
  await expect(row(page, 'Redirect URI', 1)).not.toHaveAttribute('aria-invalid', 'true')
  // editing the row clears its error
  await bad.fill('https://good.example/cb')
  await expect(bad).not.toHaveAttribute('aria-invalid', 'true')
  // a standard scope typed into the custom list is refused before anything is sent
  await dlg.getByRole('button', { name: 'Add scope' }).click()
  await row(page, 'Scope', 1).fill('email')
  await dlg.getByRole('button', { name: 'Create client' }).click()
  await expect(row(page, 'Scope', 1)).toHaveAttribute('aria-invalid', 'true')
  await expect(row(page, 'Scope', 1)).toBeFocused()
  await expect(dlg.locator('.list-field .field-error').filter({ hasText: 'standard scope' })).toBeVisible()
  await row(page, 'Scope', 1).fill('bad"scope')
  await dlg.getByRole('button', { name: 'Create client' }).click()
  await expect(dlg.locator('.list-field .field-error').filter({ hasText: 'not a valid scope' })).toBeVisible()
})

test('client dialog a11y with several rows, a row error, scope checkboxes and custom scopes (axe, this theme); edit shows saved rows', async ({ page }) => {
  const t = await freshTenant(page)
  await apiCall(page, 'POST', `${API}/clients`, { name: 'Many rows', tenant_id: t.id,
    redirect_uris: ['https://a.example/cb', 'https://b.example/cb', 'com.example.app:/callback'], post_logout_redirect_uris: ['https://a.example/bye', 'https://b.example/bye'],
    backchannel_logout_uri: 'https://a.example/back', scopes: ['openid', 'groups', 'orders:read', 'billing.write'] })
  await page.reload({ waitUntil: 'load' })
  await page.getByRole('button', { name: 'Edit Many rows' }).click()
  const dlg = page.getByRole('dialog', { name: 'Edit client' })
  await expect(dlg).toBeVisible()
  await page.waitForTimeout(450)
  await expect(dlg.getByRole('textbox', { name: /^Redirect URI \d$/ })).toHaveCount(3)
  await expect(row(page, 'Post-logout redirect URI', 2)).toHaveValue('https://b.example/bye')
  await expect(row(page, 'Scope', 2)).toHaveValue('billing.write')
  await expect(dlg.getByRole('checkbox', { name: /^openid/ })).toBeChecked()
  await expect(dlg.getByRole('checkbox', { name: /^email/ })).not.toBeChecked()
  await expect(page.locator('#f-backchannel_logout_uri')).toHaveValue('https://a.example/back')
  let r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  // a row error
  await row(page, 'Redirect URI', 2).fill('http://bad.example/cb')
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(row(page, 'Redirect URI', 2)).toHaveAttribute('aria-invalid', 'true')
  await page.waitForTimeout(300)
  r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  // fix and save; scopes round-trip
  await row(page, 'Redirect URI', 2).fill('https://b2.example/cb')
  await dlg.getByRole('checkbox', { name: /^email/ }).check()
  await dlg.getByRole('button', { name: 'Remove billing.write' }).click()
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(dlg).toBeHidden()
  const saved = (await apiCall(page, 'GET', `${API}/clients?tenant=${t.id}`)).items[0]
  expect(saved.redirect_uris).toEqual(['https://a.example/cb', 'https://b2.example/cb', 'com.example.app:/callback'])
  expect(saved.scopes).toEqual(['openid', 'email', 'groups', 'orders:read'])
  expect(saved.backchannel_logout_uri).toBe('https://a.example/back')
})

test('client dialog: client-credentials-only hides the redirect editors', async ({ page }) => {
  await freshTenant(page)
  await page.getByRole('button', { name: 'New client' }).click()
  const dlg = page.getByRole('dialog', { name: 'New client' })
  await expect(dlg.getByRole('group', { name: 'Redirect URIs', exact: true })).toBeVisible()
  await dlg.getByRole('checkbox', { name: /^Client credentials/ }).check()
  await dlg.getByRole('checkbox', { name: /^Authorization code/ }).uncheck()
  await expect(dlg.getByRole('group', { name: 'Redirect URIs', exact: true })).toBeHidden()
  await expect(dlg.getByRole('group', { name: 'Post-logout redirect URIs' })).toBeHidden()
})
