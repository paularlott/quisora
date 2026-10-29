// Service accounts page: create (the secret is shown once), edit, rotate, delete; the scopes only a super admin may give
// are not offered to an organization administrator; managers have no way in.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt, uniq } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'

// Click a copy button: it announces what it copied in the open dialog's live region; returns the clipboard.
async function copied(page, button, what) {
  await button.click()
  await expect(page.locator('dialog[open] [data-live=polite]')).toContainText('Copied ' + what)
  return page.evaluate(() => navigator.clipboard.readText())
}

const find = async (page, name) => (await apiCall(page, 'GET', `${API}/service-accounts?q=${encodeURIComponent(name)}`)).items.find((a) => a.name === name)

test('create shows client ID, token endpoint and the secret once, each to copy; then edit, rotate and delete', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await signIn(page, 'admin')
  await page.goto(`${A}/service-accounts`, { waitUntil: 'load' })
  const name = uniq('Deploy bot ')
  const dlg = page.getByRole('dialog', { name: 'Service account created' })

  // create
  await page.getByRole('button', { name: 'New service account' }).first().click()
  const form = page.getByRole('dialog', { name: 'New service account' })
  await form.getByLabel('Name', { exact: false }).first().fill(name)
  await form.getByRole('checkbox', { name: /users/ }).first().check()
  await form.getByRole('checkbox', { name: /groups/ }).check()
  await expect(form.getByRole('switch')).toBeHidden() // enabled is for editing
  let r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await form.getByRole('button', { name: 'Create service account' }).click()
  await expect(dlg).toBeVisible()
  const made = await find(page, name)
  expect(made.scopes).toEqual(['users', 'groups'])
  expect(made.token_endpoint_auth_method).toBe('client_secret_post')
  expect((await dlg.locator('#sa-id').innerText()).trim()).toBe(made.id)
  await expect(dlg.getByText('The secret is shown once')).toBeVisible()
  const secret = (await dlg.locator('#sa-secret').innerText()).trim()
  expect(secret).toMatch(/^qsrs_/)
  expect(await copied(page, dlg.getByRole('button', { name: 'Copy client ID' }), 'client ID')).toBe(made.id)
  expect(await copied(page, dlg.getByRole('button', { name: 'Copy token endpoint' }), 'token endpoint')).toBe(made.token_endpoint)
  expect(await copied(page, dlg.getByRole('button', { name: 'Copy client secret' }), 'client secret')).toBe(secret)
  r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await dlg.getByRole('button', { name: 'I have stored it' }).click()
  await expect(dlg).toBeHidden()

  // the list: name, scopes, authentication, status; the API never gives the secret again
  const row = page.getByRole('row', { name: new RegExp(name) })
  await expect(row).toContainText('users')
  await expect(row).toContainText('Secret (POST)')
  await expect(row).toContainText('Enabled')
  expect(JSON.stringify(await find(page, name))).not.toContain(secret)
  r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  // edit: scopes and enabled
  await page.getByRole('button', { name: 'Edit ' + name }).click()
  const edit = page.getByRole('dialog', { name: 'Edit service account' })
  await expect(edit.getByRole('checkbox', { name: /users/ }).first()).toBeChecked()
  await edit.getByRole('checkbox', { name: /groups/ }).uncheck()
  await edit.getByRole('checkbox', { name: /tenants/ }).check()
  await edit.getByRole('switch').uncheck()
  await edit.getByRole('button', { name: 'Save changes' }).click()
  await expect(edit).toBeHidden()
  await expect(row).toContainText('Disabled')
  const saved = await find(page, name)
  expect(saved.scopes).toEqual(['users', 'tenants'])
  expect(saved.enabled).toBe(false)

  // a server refusal of the scopes stays on the form
  await page.getByRole('button', { name: 'Edit ' + name }).click()
  await edit.getByRole('checkbox', { name: /users/ }).first().uncheck()
  await edit.getByRole('checkbox', { name: /tenants/ }).uncheck()
  await edit.getByRole('button', { name: 'Save changes' }).click()
  await expect(edit.locator('#e-scopes')).toContainText('at least one scope')
  await edit.getByRole('button', { name: 'Cancel' }).click()

  // rotate: confirm, then the new secret is shown once
  await page.getByRole('button', { name: 'Rotate secret of ' + name }).click()
  await page.getByRole('dialog', { name: 'Rotate secret?' }).getByRole('button', { name: 'Rotate secret', exact: true }).click()
  const fresh = page.getByRole('dialog', { name: 'New secret' })
  await expect(fresh).toBeVisible()
  const next = (await fresh.locator('#sa-secret').innerText()).trim()
  expect(next).toMatch(/^qsrs_/)
  expect(next).not.toBe(secret)
  await fresh.getByRole('button', { name: 'I have stored it' }).click()
  await expect(fresh).toBeHidden()

  // delete: confirm
  await page.getByRole('button', { name: 'Delete ' + name }).click()
  await page.getByRole('dialog', { name: 'Delete service account?' }).getByRole('button', { name: 'Delete service account' }).click()
  await expect(row).toHaveCount(0)
  expect(await find(page, name)).toBeUndefined()
})

test('a service account with a private key has no secret to show or rotate', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/service-accounts`, { waitUntil: 'load' })
  const name = uniq('Keyed bot ')
  await page.getByRole('button', { name: 'New service account' }).first().click()
  const form = page.getByRole('dialog', { name: 'New service account' })
  await form.getByLabel('Name').first().fill(name)
  await form.getByRole('checkbox', { name: /groups/ }).check()
  await expect(form.locator('#f-jwks_uri')).toBeHidden()
  await form.locator('#f-token_endpoint_auth_method').selectOption('private_key_jwt')
  await form.locator('#f-jwks_uri').fill('https://bot.example/jwks.json')
  await form.getByRole('button', { name: 'Create service account' }).click()
  const dlg = page.getByRole('dialog', { name: 'Service account created' })
  await expect(dlg.locator('#sa-id')).not.toBeEmpty()
  await expect(dlg.getByText('The secret is shown once')).toBeHidden()
  await expect(dlg.getByRole('button', { name: 'Copy client secret' })).toBeHidden()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await dlg.getByRole('button', { name: 'Done' }).click()
  await expect(page.getByRole('row', { name })).toContainText('Private key JWT')
  await expect(page.getByRole('button', { name: 'Rotate secret of ' + name })).toBeHidden()
  await apiCall(page, 'DELETE', `${API}/service-accounts/${(await find(page, name)).id}`)
})

test('only super admins are offered the import scope; the organizations scopes only on the primary organization', async ({ page }) => {
  const open = async (path) => {
    await page.goto(path, { waitUntil: 'load' })
    await page.getByRole('button', { name: 'New service account' }).first().click()
    return page.getByRole('dialog', { name: 'New service account' })
  }
  await signIn(page, 'admin')
  let form = await open(`${A}/service-accounts`)
  await expect(form.getByRole('checkbox', { name: /users/ }).first()).toBeVisible()
  await expect(form.getByRole('checkbox', { name: /scim/ })).toBeVisible()
  await expect(form.getByRole('checkbox', { name: /service_accounts/ })).toBeVisible()
  await expect(form.getByRole('checkbox', { name: /import/ })).toHaveCount(0)
  await expect(form.getByRole('checkbox', { name: /orgs:/ })).toHaveCount(0)

  await signIn(page, 'super')
  form = await open(`${A}/service-accounts`)
  await expect(form.getByRole('checkbox', { name: /import/ })).toBeVisible()
  await expect(form.getByRole('checkbox', { name: /orgs:/ })).toHaveCount(0)
  form = await open('/admin/orgs/primary/service-accounts')
  await expect(form.getByRole('checkbox', { name: /import/ })).toBeVisible()
  await expect(form.getByRole('checkbox', { name: /orgs:create/ })).toBeVisible()
  await expect(form.getByRole('checkbox', { name: /orgs:delete/ })).toBeVisible()
})

test('an account holding import cannot be changed by an organization administrator', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto(`${A}/service-accounts`, { waitUntil: 'load' })
  const name = uniq('Importer ')
  const made = await apiCall(page, 'POST', `${API}/service-accounts`, { name, scopes: ['users', 'import'] })
  await page.reload({ waitUntil: 'load' })
  await expect(page.getByRole('button', { name: 'Edit ' + name })).toBeVisible()
  await signIn(page, 'admin')
  await page.goto(`${A}/service-accounts`, { waitUntil: 'load' })
  await expect(page.getByRole('row', { name: new RegExp(name) })).toContainText('import')
  await expect(page.getByRole('button', { name: 'Edit ' + name })).toBeHidden()
  await expect(page.getByRole('button', { name: 'Rotate secret of ' + name })).toBeHidden()
  await expect(page.getByRole('button', { name: 'Delete ' + name })).toBeHidden()
  await signIn(page, 'super')
  await page.goto(`${A}/service-accounts`, { waitUntil: 'load' })
  await apiCall(page, 'DELETE', `${API}/service-accounts/${made.id}`)
})

test('managers have no service accounts link and no page', async ({ page }) => {
  await signIn(page, 'manager')
  await page.goto(`${A}/users`, { waitUntil: 'load' })
  await expect(page.getByRole('link', { name: 'Users', exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Service accounts' })).toHaveCount(0)
  expect((await page.goto(`${A}/service-accounts`, { waitUntil: 'load' })).status()).toBe(403)

  await signIn(page, 'admin')
  await page.goto(`${A}/users`, { waitUntil: 'load' })
  await expect(page.getByRole('link', { name: 'Service accounts' })).toBeVisible()
})
