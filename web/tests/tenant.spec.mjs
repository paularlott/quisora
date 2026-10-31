// The tenant page and its clients page: structure, breadcrumbs, summary cards that lead to the clients and SSH pages, the
// tenants list's Clients and SSH columns, dialogs, keyboard behaviour.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, uniq, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'

// A new tenant with tenantCount clients, opened on its page (or, with sub, on one of its pages: clients, ssh).
async function fresh(page, tenantCount = 0, sub = '') {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`)
  await page.waitForSelector('tbody tr')
  const slug = uniq('tn')
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'Test ' + slug })
  for (let i = 0; i < tenantCount; i++) {
    await apiCall(page, 'POST', `${API}/clients`, { name: `App ${i + 1}`, tenant_id: t.id, redirect_uris: ['https://a.example/cb'] })
  }
  await page.goto(`${A}/tenants/${slug}${sub}`)
  await page.waitForSelector(sub === '/ssh' ? '#ssh-h' : '#clients-h')
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
  // searched: other tests add tenants, which can push these past the first page
  const search = page.getByRole('searchbox', { name: 'Search tenants' })
  await search.fill('Partners')
  await expect(page.getByRole('row', { name: /Partners/ })).toContainText('0 clients')
  await search.fill('Staff tools')
  await expect(page.getByRole('row', { name: /Staff tools/ })).toContainText('3 clients')
  // open from the name link
  await page.getByRole('link', { name: 'Staff tools', exact: true }).click()
  await expect(page).toHaveURL(`${A}/tenants/staff`)
  await expect(page).toHaveTitle(/^Tenant: Staff tools/)
  // from the client count, to the tenant's clients page
  await page.goBack()
  await page.waitForSelector('tbody tr')
  await search.fill('Customer apps')
  await page.getByRole('link', { name: /^Clients of Customer apps: \d+ clients/ }).click()
  await expect(page).toHaveURL(`${A}/tenants/customers/clients`)
  await expect(page).toHaveTitle(/^Clients: Customer apps/)
  // and from the SSH state, to its SSH page
  await page.goBack()
  await page.waitForSelector('tbody tr')
  await search.fill('Customer apps')
  await page.getByRole('link', { name: 'SSH certificates of Customer apps: Off' }).click()
  await expect(page).toHaveURL(`${A}/tenants/customers/ssh`)
  await expect(page).toHaveTitle(/^SSH certificates: Customer apps/)
  // old links keep working
  await page.goto(`${A}/clients`)
  await expect(page).toHaveURL(`${A}/tenants`)
  // unknown tenant: styled 404
  const res = await page.goto(`${A}/tenants/does-not-exist`)
  expect(res.status()).toBe(404)
  await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible()
})

test('tenants list: the Clients and SSH columns link to the tenant\'s clients and SSH pages', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`)
  await page.waitForSelector('tbody tr')
  await expect(page.getByRole('columnheader', { name: 'Clients' })).toBeVisible()
  await expect(page.getByRole('columnheader', { name: 'SSH' })).toBeVisible()
  const search = page.getByRole('searchbox', { name: 'Search tenants' })
  // SSH is on for the demo's Servers tenant, off for the others
  await search.fill('Servers')
  const servers = page.getByRole('row', { name: /Servers/ })
  await expect(servers.getByRole('link', { name: 'SSH certificates of Servers: On' })).toHaveAttribute('href', `${A}/tenants/servers/ssh`)
  await expect(servers.getByRole('link', { name: 'SSH certificates of Servers: On' })).toContainText('On')
  await expect(servers.getByRole('link', { name: /^Clients of Servers: \d+ clients?/ })).toHaveAttribute('href', `${A}/tenants/servers/clients`)
  await search.fill('Partners')
  const partners = page.getByRole('row', { name: /Partners/ })
  await expect(partners.getByRole('link', { name: 'SSH certificates of Partners: Off' })).toHaveAttribute('href', `${A}/tenants/partners/ssh`)
  await expect(partners.getByRole('link', { name: 'SSH certificates of Partners: Off' })).toContainText('Off')
  await expect(partners.getByRole('link', { name: 'Clients of Partners: 0 clients' })).toHaveAttribute('href', `${A}/tenants/partners/clients`)
  // the name still opens the tenant itself
  await expect(partners.getByRole('link', { name: 'Partners', exact: true })).toHaveAttribute('href', `${A}/tenants/partners`)
  // turning SSH on elsewhere changes the column
  const slug = uniq('sc')
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'Column ' + slug })
  await search.fill('Column ' + slug)
  await expect(page.getByRole('link', { name: 'SSH certificates of Column ' + slug + ': Off' })).toBeVisible({ timeout: 4000 })
  await apiCall(page, 'PATCH', `${API}/tenants/${t.id}/ssh`, { enabled: true })
  await expect(page.getByRole('link', { name: 'SSH certificates of Column ' + slug + ': On' })).toBeVisible({ timeout: 4000 })
  await apiCall(page, 'PATCH', `${API}/tenants/${t.id}/ssh`, { enabled: false })
  await expect(page.getByRole('link', { name: 'SSH certificates of Column ' + slug + ': Off' })).toBeVisible({ timeout: 4000 })
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  // the SSH state opens the tenant's SSH page
  await search.fill('Partners')
  await page.getByRole('row', { name: /Partners/ }).getByRole('link', { name: 'SSH certificates of Partners: Off' }).click()
  await expect(page).toHaveURL(`${A}/tenants/partners/ssh`)
})

test('tenant page: breadcrumb, titles, summary and the cards that lead to its clients and SSH pages', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/staff`)
  await expect(page.getByRole('heading', { name: /^Clients/ })).toContainText('3 clients')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Tenant: Staff tools')
  await expect(page.locator('.page-head .eyebrow')).toHaveText('Acme Corporation · Tenant')
  const crumbs = page.getByRole('navigation', { name: 'Breadcrumb' })
  await expect(crumbs.locator('ol > li')).toHaveCount(3)
  await expect(crumbs.locator('[aria-current="page"]')).toHaveText('Staff tools')
  await expect(crumbs.locator('li').last().locator('a')).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Sign-in rules' })).toBeVisible()
  const rules = page.getByRole('region', { name: 'Sign-in rules' }).locator('.kv')
  await expect(rules).toContainText('Acme SSO')
  await expect(rules).toContainText('Required')
  // the clients and the SSH certificates are summary cards: no table, no dialogs, a link to the page that has them
  await expect(page.getByText('Clients are the applications that sign users in through this tenant.', { exact: true })).toBeVisible()
  await expect(page.getByRole('table', { name: /Clients/ })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'New client' })).toHaveCount(0)
  await expect(page.getByRole('switch', { name: 'Enable SSH certificates' })).toHaveCount(0)
  const clients = page.getByRole('region', { name: /^Clients/ })
  await expect(clients.getByRole('link', { name: 'Manage clients' })).toHaveAttribute('href', `${A}/tenants/staff/clients`)
  const ssh = page.getByRole('region', { name: /^SSH certificates/ })
  await expect(ssh).toContainText('Off')
  await expect(ssh.getByRole('link', { name: 'Manage SSH certificates' })).toHaveAttribute('href', `${A}/tenants/staff/ssh`)
  // the sign-in rules' own row for SSH says so too, and leads to the same page
  await expect(rules).toContainText('SSH certificates')
  await expect(rules.getByRole('link', { name: 'SSH certificates page' })).toHaveAttribute('href', `${A}/tenants/staff/ssh`)
  // where SSH is on the card says On, and the rules' row points at the page that manages it
  await page.goto(`${A}/tenants/servers`)
  const on = page.getByRole('region', { name: /^SSH certificates/ })
  await expect(on.getByRole('heading')).toContainText('On')
  await expect(page.getByRole('region', { name: 'Sign-in rules' }).locator('.kv')).toContainText('Manage them on the SSH certificates page')
  await expect(page.getByRole('region', { name: 'Sign-in rules' }).locator('.kv').getByRole('link', { name: 'SSH certificates page' })).toHaveAttribute('href', `${A}/tenants/servers/ssh`)
  // an empty tenant: no clients, still the link
  await page.goto(`${A}/tenants/partners`)
  await expect(page.getByRole('heading', { name: /^Clients/ })).toContainText('0 clients')
  // the links lead to the pages
  await page.goto(`${A}/tenants/staff`)
  await page.getByRole('link', { name: 'Manage clients' }).click()
  await expect(page).toHaveURL(`${A}/tenants/staff/clients`)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Clients: Staff tools')
  await page.goBack()
  await page.getByRole('link', { name: 'Manage SSH certificates' }).click()
  await expect(page).toHaveURL(`${A}/tenants/staff/ssh`)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('SSH certificates: Staff tools')
  // breadcrumb navigation from the keyboard
  await page.goto(`${A}/tenants/staff`)
  await expect(page.getByRole('heading', { name: /^Clients/ })).toContainText('3 clients')
  const tenantsLink = crumbs.getByRole('link', { name: 'Tenants' })
  await tenantsLink.focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(`${A}/tenants`)
  await page.goBack()
  await crumbs.getByRole('link', { name: /Acme Corporation/ }).focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(`${A}/users`)
})

test('clients page: breadcrumb, titles, the client table, search and the empty state', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/staff/clients`)
  await page.waitForSelector('tbody tr')
  await expect(page).toHaveTitle(/^Clients: Staff tools/)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Clients: Staff tools')
  await expect(page.locator('.page-head .eyebrow')).toHaveText('Acme Corporation · Clients')
  const crumbs = page.getByRole('navigation', { name: 'Breadcrumb' })
  await expect(crumbs.locator('ol > li')).toHaveCount(4)
  await expect(crumbs.locator('li').nth(1).getByRole('link')).toHaveAttribute('href', `${A}/tenants`)
  await expect(crumbs.locator('li').nth(2).getByRole('link', { name: 'Staff tools' })).toHaveAttribute('href', `${A}/tenants/staff`)
  await expect(crumbs.locator('[aria-current="page"]')).toHaveText('Clients')
  // what applications are configured with is named in the head
  await expect(page.locator('.page-head').getByRole('button', { name: 'Copy issuer URL' })).toBeVisible()
  await expect(page.locator('#clients-h')).toContainText('3 clients')
  await expect(page.getByText('Clients are the applications that sign users in through this tenant.', { exact: true })).toBeVisible()
  await expect(page.getByRole('row', { name: /Internal tool 2/ })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Sign-in rules' })).toHaveCount(0)
  // search and sort use the clients API with ?tenant
  await page.getByRole('searchbox', { name: 'Search clients' }).fill('tool 3')
  await expect(page.getByRole('row', { name: /Internal tool 3/ })).toBeVisible()
  await expect(page.getByRole('row', { name: /Internal tool 2/ })).toHaveCount(0)
  // an empty tenant says so, with a single "New client" button (the one in the card header)
  await page.goto(`${A}/tenants/partners/clients`)
  await expect(page.getByRole('heading', { name: 'No clients in this tenant yet' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'New client' })).toHaveCount(1)
  // the tenant crumb leads back, from the keyboard
  const back = crumbs.getByRole('link', { name: 'Partners' })
  await back.focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(`${A}/tenants/partners`)
  // unknown tenants and tenants of another organization: styled 404
  for (const path of ['/tenants/does-not-exist/clients', '/tenants/does-not-exist/ssh']) {
    const res = await page.goto(A + path)
    expect(res.status()).toBe(404)
    await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible()
  }
})

test('the clients page follows the tenant: renamed elsewhere moves the address, deleted elsewhere is said', async ({ page }) => {
  const { slug, t } = await fresh(page, 1, '/clients')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Clients: Test ' + slug)
  await apiCall(page, 'PATCH', `${API}/tenants/${t.id}`, { name: slug + '-r', display_name: 'Renamed ' + slug })
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Clients: Renamed ' + slug, { timeout: 4000 })
  await expect(page).toHaveURL(`${A}/tenants/${slug}-r/clients`)
  await expect(page).toHaveTitle(new RegExp('^Clients: Renamed ' + slug))
  await expect(page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('link', { name: 'Renamed ' + slug })).toHaveAttribute('href', `${A}/tenants/${slug}-r`)
  await expect(page.getByRole('row', { name: /App 1/ })).toBeVisible()
  await apiCall(page, 'DELETE', `${API}/clients/${(await apiCall(page, 'GET', `${API}/clients?tenant=${t.id}`)).items[0].id}`)
  await apiCall(page, 'DELETE', `${API}/tenants/${t.id}`)
  await expect(page.locator('.alert', { hasText: 'This tenant was deleted by someone else' })).toBeVisible({ timeout: 4000 })
})

test('breadcrumb links are in the tab order before the page content', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/staff/clients`)
  await page.waitForSelector('tbody tr')
  const seen = []
  await page.locator('a.skip-link').focus()
  for (let i = 0; i < 30; i++) {
    await page.keyboard.press('Tab')
    seen.push(await page.evaluate(() => { const e = document.activeElement; return e.id || (e.getAttribute('aria-label') || e.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 40) }))
  }
  const crumbOrg = seen.findIndex((s) => /Acme Corporation/.test(s))
  const crumbTenants = seen.lastIndexOf('Tenants') // the nav link comes first, the breadcrumb link after it
  const crumbTenant = seen.indexOf('Staff tools')
  const live = seen.indexOf('live-toggle')
  const create = seen.findIndex((s) => /New client/.test(s))
  const search = seen.indexOf('list-search')
  const msg = seen.join(' | ')
  expect(crumbOrg, msg).toBeGreaterThan(-1)
  expect(crumbTenants, msg).toBeGreaterThan(crumbOrg)
  expect(crumbTenant, msg).toBeGreaterThan(crumbTenants)
  expect(live, msg).toBeGreaterThan(-1)
  expect(live, msg).toBeLessThan(crumbOrg) // in the header, before the page
  expect(create, msg).toBeGreaterThan(crumbTenant)
  expect(search, msg).toBeGreaterThan(create)
})

test('client dialogs on the clients page: keyboard, focus return, secret shown once, delete confirm', async ({ page }) => {
  const { t } = await fresh(page, 1, '/clients')
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
  // the sign-in rules are edited on the tenant's page, not here
  await expect(page.getByRole('button', { name: 'Edit sign-in rules' })).toHaveCount(0)
  // delete: the confirmation names the client
  await page.getByRole('button', { name: 'Delete Made here' }).click()
  const confirm = page.getByRole('dialog', { name: 'Delete client?' })
  await expect(confirm).toContainText('Made here')
  await confirm.getByRole('button', { name: 'Delete client' }).click()
  await expect(page.getByRole('row', { name: /Made here/ })).toHaveCount(0)
  await expect(page.locator('.toasts')).toContainText('Client “Made here” deleted.')
})

test('moving a client to another tenant: it leaves this list and the move is announced politely', async ({ page }) => {
  const { t } = await fresh(page, 2, '/clients')
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

test('tenant page: the sign-in rules dialog from the keyboard, Esc returns focus to its button', async ({ page }) => {
  await fresh(page)
  const rules = page.getByRole('button', { name: 'Edit sign-in rules' })
  await rules.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog', { name: 'Edit sign-in rules' })).toBeVisible()
  await expect(page.locator('#f-display_name')).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(rules).toBeFocused()
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

test('tenant page a11y: zero violations with the breadcrumb, summary cards and dialogs (axe, this theme)', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/staff`)
  await expect(page.getByRole('heading', { name: /^Clients/ })).toContainText('3 clients')
  await page.waitForTimeout(500)
  let r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await page.getByRole('button', { name: 'Edit sign-in rules' }).click()
  await page.waitForTimeout(450)
  r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('clients page a11y: zero violations with the table and the client dialog (axe, this theme)', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/staff/clients`)
  await page.waitForSelector('tbody tr')
  await page.waitForTimeout(500)
  let r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await page.getByRole('button', { name: 'Edit Internal tool 1' }).click()
  await page.waitForTimeout(450)
  r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('tenant pages: managers are refused with a styled 403', async ({ page }) => {
  await signIn(page, 'manager')
  for (const path of ['', '/clients', '/ssh']) {
    const res = await page.goto(`${A}/tenants/staff${path}`)
    expect(res.status()).toBe(403)
    await expect(page.getByRole('heading', { name: 'Not allowed' })).toBeVisible()
  }
})

// Device sign-in on a client: off by default; ticking it shows the switch for managers and administrators (off), and
// both are saved.
test('client device sign-in', async ({ page }) => {
  await signIn(page, 'admin')
  let sent = null
  await page.route('**/api/orgs/acme/clients', async (r) => {
    if (r.request().method() !== 'POST') return r.continue()
    sent = r.request().postDataJSON()
    return r.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ ...sent, id: 'c1', secret: 's' }) })
  })
  await page.goto('/admin/orgs/acme/tenants/staff/clients')
  await page.waitForSelector('tbody tr')
  await page.getByRole('button', { name: 'New client' }).first().click()
  const device = page.getByRole('checkbox', { name: /Device sign-in/ })
  const privileged = page.getByRole('switch', { name: /Managers and administrators may approve device sign-ins/ })
  await expect(device).not.toBeChecked()
  await expect(privileged).toBeHidden()
  await device.check()
  await expect(privileged).toBeVisible()
  await expect(privileged).not.toBeChecked()
  await privileged.check()
  await page.locator('#f-name').fill('TV app')
  await page.getByRole('button', { name: 'Create client' }).click()
  await expect.poll(() => sent).not.toBeNull()
  expect(sent.grant_types).toContain('urn:ietf:params:oauth:grant-type:device_code')
  expect(sent.device_privileged_users).toBe(true)
})
