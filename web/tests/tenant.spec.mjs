// The tenant page: structure, breadcrumb, dialogs on the page, keyboard behaviour.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, uniq, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'

async function fresh(page, tenantCount = 0) {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`)
  await page.waitForSelector('tbody tr')
  const slug = uniq('tn')
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'Test ' + slug })
  for (let i = 0; i < tenantCount; i++) {
    await apiCall(page, 'POST', `${API}/clients`, { name: `App ${i + 1}`, tenant_id: t.id, redirect_uris: ['https://a.example/cb'] })
  }
  await page.goto(`${A}/tenants/${slug}`)
  await page.waitForSelector('#clients-h')
  await page.waitForTimeout(300)
  return { slug, t, title: 'Test ' + slug }
}

test('structure: no Clients in the navigation; tenants list links to tenant pages; old clients URL redirects', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`)
  await page.waitForSelector('tbody tr')
  const nav = page.getByRole('navigation', { name: 'Primary' })
  await expect(nav.getByRole('link', { name: 'Tenants' })).toHaveAttribute('aria-current', 'page')
  await expect(nav.getByRole('link', { name: /^Clients/ })).toHaveCount(0)
  // help text, breadcrumb and counts make the hierarchy obvious
  await expect(page.getByText("Each tenant groups applications (clients) and decides which of the organization's sign-in methods they may use.")).toBeVisible()
  await expect(page.locator('.page-head .eyebrow')).toHaveText('Acme Corporation · Tenants')
  const crumbs = page.getByRole('navigation', { name: 'Breadcrumb' })
  await expect(crumbs.locator('ol > li')).toHaveCount(2)
  await expect(crumbs.locator('[aria-current="page"]')).toHaveText('Tenants')
  await expect(page.getByRole('row', { name: /Staff tools/ })).toContainText('3 clients')
  await expect(page.getByRole('row', { name: /Partners/ })).toContainText('0 clients')
  // open from the name link
  await page.getByRole('link', { name: 'Staff tools', exact: true }).click()
  await expect(page).toHaveURL(`${A}/tenants/staff`)
  await expect(page).toHaveTitle(/^Tenant: Staff tools/)
  // and from the client count
  await page.goBack()
  await page.waitForSelector('tbody tr')
  await page.getByRole('link', { name: /\d+ clients in Customer apps/ }).click()
  await expect(page).toHaveURL(`${A}/tenants/customers`)
  // old links keep working
  await page.goto(`${A}/clients`)
  await expect(page).toHaveURL(`${A}/tenants`)
  // unknown tenant: styled 404
  const res = await page.goto(`${A}/tenants/does-not-exist`)
  expect(res.status()).toBe(404)
  await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible()
})

test('tenant page: breadcrumb, titles, summary card and the client table', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/staff`)
  await page.waitForSelector('tbody tr')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Tenant: Staff tools')
  await expect(page.locator('.page-head .eyebrow')).toHaveText('Acme Corporation · Tenant')
  const crumbs = page.getByRole('navigation', { name: 'Breadcrumb' })
  await expect(crumbs.locator('ol > li')).toHaveCount(3)
  await expect(crumbs.locator('[aria-current="page"]')).toHaveText('Staff tools')
  await expect(crumbs.locator('li').last().locator('a')).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Sign-in rules' })).toBeVisible()
  await expect(page.locator('.kv')).toContainText('Acme SSO')
  await expect(page.locator('.kv')).toContainText('Required')
  await expect(page.getByRole('heading', { name: /^Clients/ })).toContainText('3 clients')
  await expect(page.getByText('Clients are the applications that sign users in through this tenant.', { exact: true })).toBeVisible()
  await expect(page.getByRole('row', { name: /Internal tool 2/ })).toBeVisible()
  // search and sort use the clients API with ?tenant
  await page.getByRole('searchbox', { name: 'Search clients' }).fill('tool 3')
  await expect(page.getByRole('row', { name: /Internal tool 3/ })).toBeVisible()
  await expect(page.getByRole('row', { name: /Internal tool 2/ })).toHaveCount(0)
  // an empty tenant says so, with a single "New client" button (the one in the card header)
  await page.goto(`${A}/tenants/partners`)
  await expect(page.getByRole('heading', { name: 'No clients in this tenant yet' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'New client' })).toHaveCount(1)
  // breadcrumb navigation from the keyboard
  await page.goto(`${A}/tenants/staff`)
  await page.waitForSelector('tbody tr')
  const tenantsLink = crumbs.getByRole('link', { name: 'Tenants' })
  await tenantsLink.focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(`${A}/tenants`)
  await page.goBack()
  await crumbs.getByRole('link', { name: /Acme Corporation/ }).focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(`${A}/users`)
})

test('breadcrumb links are in the tab order before the page content', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/staff`)
  await page.waitForSelector('tbody tr')
  const seen = []
  await page.locator('a.skip-link').focus()
  for (let i = 0; i < 30; i++) {
    await page.keyboard.press('Tab')
    seen.push(await page.evaluate(() => { const e = document.activeElement; return e.id || (e.getAttribute('aria-label') || e.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 40) }))
  }
  const crumbOrg = seen.findIndex((s) => /Acme Corporation/.test(s))
  const crumbTenants = seen.lastIndexOf('Tenants') // the nav link comes first, the breadcrumb link after it
  const live = seen.indexOf('live-toggle')
  const edit = seen.findIndex((s) => /Edit sign-in rules/.test(s))
  const search = seen.indexOf('list-search')
  const msg = seen.join(' | ')
  expect(crumbOrg, msg).toBeGreaterThan(-1)
  expect(crumbTenants, msg).toBeGreaterThan(crumbOrg)
  expect(live, msg).toBeGreaterThan(-1)
  expect(live, msg).toBeLessThan(crumbOrg) // in the header, before the page
  expect(edit, msg).toBeGreaterThan(crumbTenants)
  expect(search, msg).toBeGreaterThan(edit)
})

test('client dialogs on the tenant page: keyboard, focus return, secret shown once, delete confirm', async ({ page }) => {
  const { t } = await fresh(page, 1)
  // New client: Enter opens it focused on Name; Tab stays inside; Esc returns focus to the button
  const newBtn = page.getByRole('button', { name: 'New client' })
  await newBtn.focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'New client' })
  await expect(dlg).toBeVisible()
  await expect(page.locator('#f-name')).toBeFocused()
  await expect(page.locator('#f-tenant_id')).toBeHidden() // the tenant is preset, not a choice
  for (let i = 0; i < 40; i++) {
    await page.keyboard.press('Tab')
    expect(await page.evaluate(() => !!document.activeElement.closest('dialog[open]'))).toBe(true)
  }
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
  await expect(newBtn).toBeFocused()
  // create: the secret is shown once; closing returns focus to the button
  await newBtn.click()
  await page.locator('#f-name').fill('Made here')
  await page.getByLabel('Redirect URI 1', { exact: true }).fill('https://made.example/cb')
  await page.getByRole('button', { name: 'Create client' }).click()
  const secret = page.getByRole('dialog', { name: 'Client created' })
  await expect(secret).toBeVisible()
  expect((await secret.locator('#client-secret').innerText()).trim()).toMatch(/^qsrs_/)
  await secret.getByRole('button', { name: 'I have stored it' }).click()
  await expect(page.getByRole('row', { name: /Made here/ })).toBeVisible()
  expect((await apiCall(page, 'GET', `${API}/clients?tenant=${t.id}&q=Made`)).items[0].tenant_id).toBe(t.id)
  // rotate: confirm, then the new secret, shown once
  await page.getByRole('button', { name: 'Rotate secret of Made here' }).click()
  await page.getByRole('dialog', { name: 'Rotate client secret?' }).getByRole('button', { name: 'Rotate secret' }).click()
  const second = page.getByRole('dialog', { name: 'New client secret' })
  await expect(second).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(second).toBeHidden()
  // edit rules dialog: Esc returns focus to "Edit sign-in rules"
  const rules = page.getByRole('button', { name: 'Edit sign-in rules' })
  await rules.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog', { name: 'Edit sign-in rules' })).toBeVisible()
  await expect(page.locator('#f-display_name')).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(rules).toBeFocused()
  // delete: the confirmation names the client
  await page.getByRole('button', { name: 'Delete Made here' }).click()
  const confirm = page.getByRole('dialog', { name: 'Delete client?' })
  await expect(confirm).toContainText('Made here')
  await confirm.getByRole('button', { name: 'Delete client' }).click()
  await expect(page.getByRole('row', { name: /Made here/ })).toHaveCount(0)
  await expect(page.locator('.toasts')).toContainText('Client “Made here” deleted.')
})

test('moving a client to another tenant: it leaves this list and the move is announced politely', async ({ page }) => {
  const { t } = await fresh(page, 2)
  const other = uniq('mv')
  await apiCall(page, 'POST', `${API}/tenants`, { name: other, display_name: 'Move target ' + other })
  await page.reload()
  await page.waitForSelector('tbody tr')
  await page.getByRole('button', { name: 'Edit App 1' }).click()
  const dlg = page.getByRole('dialog', { name: 'Edit client' })
  await expect(dlg.locator('#f-tenant_id')).toBeVisible()
  await expect(dlg.locator('#f-tenant_id option:checked')).toHaveText(/^Test /)
  await dlg.locator('#f-tenant_id').selectOption({ label: 'Move target ' + other })
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByRole('row', { name: /App 1/ })).toHaveCount(0)
  await expect(page.getByRole('row', { name: /App 2/ })).toBeVisible()
  const status = page.locator('.toast-region[role=status]')
  await expect(status).toContainText('Client “App 1” moved to Move target')
  await expect(status).toContainText('left this list')
  await expect(page.locator('#clients-h .badge')).toHaveText('1 client')
  expect((await apiCall(page, 'GET', `${API}/clients?q=App 1`)).items[0].tenant_id).not.toBe(t.id)
})

test('renaming a tenant from its page moves to the new address', async ({ page }) => {
  const { slug } = await fresh(page)
  await page.getByRole('button', { name: 'Edit sign-in rules' }).click()
  await page.locator('#f-tenant_name').fill(slug + '-b')
  await page.locator('#f-display_name').fill('Renamed tenant')
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(page).toHaveURL(`${A}/tenants/${slug}-b`)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Tenant: Renamed tenant')
})

test('tenant page a11y: zero violations with the breadcrumb, switch and dialogs (axe, this theme)', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/staff`)
  await page.waitForSelector('tbody tr')
  await page.waitForTimeout(500)
  let r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await page.getByRole('button', { name: 'Edit Internal tool 1' }).click()
  await page.waitForTimeout(450)
  r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('tenant page: manager and users are refused with a styled 403', async ({ page }) => {
  await signIn(page, 'manager')
  const res = await page.goto(`${A}/tenants/staff`)
  expect(res.status()).toBe(403)
  await expect(page.getByRole('heading', { name: 'Not allowed' })).toBeVisible()
})
