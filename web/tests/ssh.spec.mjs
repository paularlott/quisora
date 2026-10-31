// SSH certificates (the tenant's SSH page): turn the tenant's CA on, change its settings, rotate and remove CA keys,
// search, page through and revoke certificates, the certificates on a user's page, and the page's accessibility.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, uniq, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'

async function freshTenant(page) {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`, { waitUntil: 'load' })
  const slug = uniq('ssh')
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'SSH ' + slug })
  await page.goto(`${A}/tenants/${slug}/ssh`, { waitUntil: 'load' })
  const card = page.locator('section[aria-labelledby="ssh-h"]')
  await expect(card.getByRole('switch', { name: 'Enable SSH certificates' })).toBeVisible()
  return { slug, id: t.id, card }
}

test('ssh: off until enabled; enabling makes the CA key and the SSH application; settings; set-up commands', async ({ page }) => {
  const t = await freshTenant(page)
  const { card } = t
  await expect(card).toContainText('SSH certificates are off')
  await expect(card.getByRole('button', { name: 'Edit SSH settings' })).toBeHidden()
  await expect(page.getByRole('row', { name: /SSH/ })).toHaveCount(0)

  await card.getByRole('switch', { name: 'Enable SSH certificates' }).check()
  await expect(page.locator('.toasts')).toContainText('SSH certificates are on.')
  await expect(card.getByRole('switch', { name: 'Enable SSH certificates' })).toBeChecked()
  await expect(card.getByRole('heading', { name: 'CA keys' })).toBeVisible()

  const saved = await apiCall(page, 'GET', `${API}/tenants/${t.id}/ssh`)
  expect(saved.enabled).toBe(true)
  expect(saved.keys).toHaveLength(1)
  const disc = saved.endpoints.discovery
  expect(disc).toMatch(/\/o\/[^/]+\/ssh\/[^/]+$/)

  // the key: user, signing; the application is listed on the clients page
  const keys = card.getByRole('table', { name: 'SSH CA keys of this tenant' })
  await expect(keys.locator('tbody tr')).toHaveCount(1)
  await expect(keys.locator('tbody tr')).toContainText('User')
  await expect(keys.locator('tbody tr')).toContainText('Signing')
  await expect(keys.locator('tbody tr')).toContainText(saved.keys[0].fingerprint)
  await expect(card.getByRole('link', { name: 'clients page' })).toHaveAttribute('href', `${A}/tenants/${t.slug}/clients`)

  // the commands to copy carry the tenant's discovery address
  await expect(page.locator('#ssh-server-snippet')).toContainText('TrustedUserCAKeys /etc/ssh/quisora_user_ca.pub')
  await expect(page.locator('#ssh-server-snippet')).toContainText(`quisora ssh fetch ${disc}`)
  await expect(page.locator('#ssh-login-command')).toHaveText(`quisora ssh login ${disc}`)
  await expect(page.locator('#ssh-host-snippet')).toBeHidden()

  // settings: a refusal stays on its field, then a change is saved
  await card.getByRole('button', { name: 'Edit SSH settings' }).click()
  const dlg = page.getByRole('dialog', { name: 'SSH settings' })
  await expect(dlg).toBeVisible()
  await expect(page.locator('#f-ssh_cert_ttl')).toBeFocused()
  await expect(page.locator('#f-ssh_cert_ttl')).toHaveValue('480')
  await page.locator('#f-ssh_cert_ttl').fill('2')
  await dlg.getByRole('button', { name: 'Save settings' }).click()
  await expect(page.locator('#e-ssh_cert_ttl')).toContainText('between 300 seconds')
  await expect(page.locator('#f-ssh_cert_ttl')).toBeFocused()
  await expect(page.locator('#f-ssh_cert_ttl')).toHaveAttribute('aria-invalid', 'true')
  await page.locator('#f-ssh_cert_ttl').fill('120')
  await dlg.getByRole('switch', { name: 'Names of the user’s groups' }).uncheck()
  await dlg.getByRole('switch', { name: 'Application roles' }).check()
  await dlg.getByRole('switch', { name: 'Port forwarding' }).check()
  await page.locator('#f-ssh_source_addresses').fill('203.0.113.0/24\n10.0.0.1')
  // host certificates need patterns
  await dlg.getByRole('switch', { name: 'Sign host certificates' }).check()
  await dlg.getByRole('button', { name: 'Save settings' }).click()
  await expect(page.locator('#e-ssh_host_patterns')).toContainText('required when host certificates are on')
  await page.locator('#f-ssh_host_patterns').fill('*.example.com\ndb1.internal')
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await dlg.getByRole('button', { name: 'Save settings' }).click()
  await expect(dlg).toBeHidden()
  await expect(page.locator('.toasts')).toContainText('SSH settings saved.')
  await expect(card.getByRole('button', { name: 'Edit SSH settings' })).toBeFocused()

  await expect(card.locator('dl.kv')).toContainText('2 hours')
  await expect(card.locator('dl.kv')).toContainText('Username, Application roles')
  await expect(card.locator('dl.kv')).toContainText('203.0.113.0/24, 10.0.0.1')
  await expect(card.locator('dl.kv')).toContainText('On, up to 90 days')
  const after = await apiCall(page, 'GET', `${API}/tenants/${t.id}/ssh`)
  expect(after).toMatchObject({ cert_ttl: 7200, max_auth_age: 3600, principal_username: true, principal_groups: false, principal_roles: true,
    permit_port_forwarding: true, source_addresses: ['203.0.113.0/24', '10.0.0.1'], host_certs: true, host_patterns: ['*.example.com', 'db1.internal'] })
  // host certificates on: the host key exists and the host commands show
  expect(after.keys.map((k) => k.purpose).sort()).toEqual(['host', 'user'])
  await expect(page.locator('#ssh-host-snippet')).toContainText('HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub')
  await expect(page.locator('#ssh-known-hosts')).toHaveText(after.endpoints.known_hosts)
  await expect(card.getByRole('button', { name: 'Rotate host key' })).toBeVisible()

  // the SSH application is among the tenant's clients, and the tenant page says SSH is on and leads back here
  await card.getByRole('link', { name: 'clients page' }).click()
  await expect(page).toHaveURL(`${A}/tenants/${t.slug}/clients`)
  await expect(page.getByRole('row', { name: /SSH/ }).first()).toBeVisible()
  await page.goto(`${A}/tenants/${t.slug}`, { waitUntil: 'load' })
  const rules = page.getByRole('region', { name: 'Sign-in rules' }).locator('.kv')
  await expect(rules).toContainText('SSH certificates')
  await expect(rules).toContainText('Manage them on the SSH certificates page')
  await expect(page.getByRole('region', { name: /^SSH certificates/ }).getByRole('heading')).toContainText('On')
  await page.getByRole('link', { name: 'Manage SSH certificates' }).click()
  await expect(page).toHaveURL(`${A}/tenants/${t.slug}/ssh`)
})

test('ssh: rotate a CA key, remove the retired one; turn SSH off', async ({ page }) => {
  const t = await freshTenant(page)
  const { card } = t
  await card.getByRole('switch', { name: 'Enable SSH certificates' }).check()
  const keys = card.getByRole('table', { name: 'SSH CA keys of this tenant' })
  await expect(keys.locator('tbody tr')).toHaveCount(1)

  // on schedule: the successor is published and signs in seven days
  await card.getByRole('button', { name: 'Rotate user key' }).click()
  const dlg = page.getByRole('dialog', { name: 'Rotate the user CA key' })
  await expect(dlg).toBeVisible()
  await expect(dlg.getByRole('radio', { name: /In seven days/ })).toBeChecked()
  await dlg.getByRole('button', { name: 'Rotate key' }).click()
  await expect(dlg).toBeHidden()
  await expect(page.locator('.toasts')).toContainText('it starts signing in 7 days')
  await expect(keys.locator('tbody tr')).toHaveCount(2)
  await expect(keys.locator('tbody tr', { hasText: 'Next' })).toHaveCount(1)
  await expect(card.getByRole('button', { name: /^Remove user CA key/ })).toHaveCount(0) // nothing has retired

  // immediately: the new key signs at once and the old ones retire
  await card.getByRole('button', { name: 'Rotate user key' }).click()
  await expect(dlg).toBeVisible()
  await dlg.getByRole('radio', { name: /Immediately/ }).check()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await dlg.getByRole('button', { name: 'Rotate immediately' }).click()
  await expect(dlg).toBeHidden()
  await expect(page.locator('.toasts')).toContainText('it signs now')
  await expect(keys.locator('tbody tr')).toHaveCount(2)
  await expect(keys.locator('tbody tr', { hasText: 'Signing' })).toHaveCount(1)
  const retired = keys.locator('tbody tr', { hasText: 'Retired' })
  await expect(retired).toHaveCount(1)
  const before = await apiCall(page, 'GET', `${API}/tenants/${t.id}/ssh`)
  expect(before.keys.map((k) => k.state).sort()).toEqual(['active', 'retired'])

  // the signing key cannot be removed; the retired one can, after a confirmation
  await expect(keys.locator('tbody tr', { hasText: 'Signing' }).getByRole('button', { name: /^Remove/ })).toBeHidden()
  await retired.getByRole('button', { name: /^Remove user CA key/ }).click()
  const confirm = page.getByRole('dialog', { name: 'Remove this CA key?' })
  await expect(confirm).toBeVisible()
  await confirm.getByRole('button', { name: 'Cancel' }).click()
  await expect(keys.locator('tbody tr')).toHaveCount(2)
  await retired.getByRole('button', { name: /^Remove user CA key/ }).click()
  await page.getByRole('dialog', { name: 'Remove this CA key?' }).getByRole('button', { name: 'Remove key' }).click()
  await expect(page.locator('.toasts')).toContainText('CA key removed.')
  await expect(keys.locator('tbody tr')).toHaveCount(1)
  expect((await apiCall(page, 'GET', `${API}/tenants/${t.id}/ssh`)).keys).toHaveLength(1)

  // off: asks first, and keeps the keys
  const sw = card.getByRole('switch', { name: 'Enable SSH certificates' })
  await sw.uncheck()
  const off = page.getByRole('dialog', { name: 'Turn off SSH certificates?' })
  await expect(off).toContainText('Nothing is deleted')
  await expect(off).toContainText('SSH application is disabled until SSH is on again')
  await expect(off).toContainText('revokes every certificate already issued and the CA keys themselves')
  await off.getByRole('button', { name: 'Cancel' }).click()
  await expect(sw).toBeChecked()
  await sw.uncheck()
  await page.getByRole('dialog', { name: 'Turn off SSH certificates?' }).getByRole('button', { name: 'Turn off' }).click()
  await expect(page.locator('.toasts')).toContainText('SSH certificates are off.')
  await expect(sw).not.toBeChecked()
  await expect(card).toContainText('The keys are kept')
  await expect(card).toContainText('SSH application is disabled until SSH is on again')
  await expect(keys.locator('tbody tr')).toHaveCount(1)
  // kept and revoked: listed, but nothing to rotate until SSH is on again
  await expect(card).toContainText('Kept while SSH is off, and revoked')
  await expect(card.getByRole('button', { name: 'Rotate user key' })).toBeHidden()
  await sw.check()
  await expect(page.locator('.toasts')).toContainText('SSH certificates are on.')
  await expect(card.getByRole('button', { name: 'Rotate user key' })).toBeVisible()
  await expect(keys.locator('tbody tr')).toHaveCount(1)
})

test('ssh: certificates are listed with their status and revoked', async ({ page }) => {
  const t = await freshTenant(page)
  const { card } = t
  await card.getByRole('switch', { name: 'Enable SSH certificates' }).check()
  await expect(card.getByRole('heading', { name: 'Certificates' })).toBeVisible()
  await expect(card).toContainText('No active certificates.')
  await apiCall(page, 'PATCH', `${API}/tenants/${t.id}/ssh`, { host_certs: true, host_patterns: ['*.example.com'] })
  // a host certificate for a made-up key
  const pub = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3k0gS8W3o4yO8q5q0p4m8m6Q3o7Q9hS3q2bq0Wq1ZL host@example'
  const host = await apiCall(page, 'POST', `${API}/tenants/${t.id}/ssh/host-certificates`, { public_key: pub, principals: ['web1.example.com'] })
  expect(host.certificate).toMatch(/^ssh-ed25519-cert-v01@openssh.com /)

  // the list follows (live), or after a change of the filter
  const certs = card.getByRole('table', { name: 'SSH certificates issued by this tenant' })
  const row = certs.locator('tbody tr', { hasText: 'web1.example.com' })
  await expect(row).toHaveCount(1, { timeout: 8000 })
  await expect(row).toContainText('Host')
  await expect(row).toContainText('Active')
  await expect(row).toContainText(host.serial)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  // revoke: asks first
  await row.getByRole('button', { name: new RegExp('^Revoke certificate ' + host.serial) }).click()
  const dlg = page.getByRole('dialog', { name: 'Revoke certificate?' })
  await expect(dlg).toBeVisible()
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(row).toContainText('Active')
  await row.getByRole('button', { name: /^Revoke certificate/ }).click()
  await page.getByRole('dialog', { name: 'Revoke certificate?' }).getByRole('button', { name: 'Revoke' }).click()
  await expect(page.locator('.toasts')).toContainText('Certificate revoked.')
  // no longer among the active ones; found under revoked
  await expect(certs.locator('tbody tr', { hasText: 'web1.example.com' })).toHaveCount(0)
  await card.getByLabel('Show').selectOption('revoked')
  const revoked = certs.locator('tbody tr', { hasText: 'web1.example.com' })
  await expect(revoked).toHaveCount(1)
  await expect(revoked).toContainText('Revoked')
  await expect(revoked).toContainText('Revoked by')
  await expect(revoked.getByRole('button', { name: /^Revoke/ })).toBeHidden()
  const listed = await apiCall(page, 'GET', `${API}/tenants/${t.id}/ssh/certificates?status=revoked`)
  expect(listed.items).toHaveLength(1)
  expect(listed.items[0]).toMatchObject({ host: true, status: 'revoked', reason: 'revoked' })
  await card.getByLabel('Show').selectOption('all')
  await expect(certs.locator('tbody tr', { hasText: 'web1.example.com' })).toHaveCount(1)
})

const demoTenant = async (page) => (await apiCall(page, 'GET', `${API}/tenants?q=servers`)).items.find((t) => t.name === 'servers')
const demoCerts = async (page, query = '') => apiCall(page, 'GET', `${API}/tenants/${(await demoTenant(page)).id}/ssh/certificates?${query}`)
const pagerText = (page) => page.locator('.pager .muted')

test('ssh: the demo tenant with SSH on has keys, certificates and no accessibility violations', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/servers/ssh`, { waitUntil: 'load' })
  const card = page.locator('section[aria-labelledby="ssh-h"]')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('SSH certificates: Servers')
  await expect(page.locator('#ssh-server-snippet')).toBeVisible()
  await expect(card.getByRole('table', { name: 'SSH CA keys of this tenant' }).locator('tbody tr')).toHaveCount(2) // user and host
  const certs = card.getByRole('table', { name: 'SSH certificates issued by this tenant' })
  await expect(certs).toContainText('web1.acme.example')
  await expect(certs).toContainText('alan')
  await card.getByLabel('Show').selectOption('revoked')
  await expect(certs).toContainText('Revoked')
  await expect(certs).toContainText('alan')
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('ssh: the certificates are paged like the users, and searched by user, principal, fingerprint, serial and key id', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/servers/ssh`, { waitUntil: 'load' })
  const card = page.locator('section[aria-labelledby="ssh-h"]')
  const certs = card.getByRole('table', { name: 'SSH certificates issued by this tenant' })
  const rows = certs.locator('tbody tr')
  const search = card.getByRole('searchbox', { name: 'Search certificates' })

  // the demo has more active certificates than a page holds: ten to a page, the next page after them
  const active = await demoCerts(page, 'status=active&limit=100')
  expect(active.total).toBeGreaterThan(10)
  await expect(rows).toHaveCount(10)
  await expect(pagerText(page)).toHaveText(`Showing 1–10 of ${active.total}`)
  await expect(card.getByRole('button', { name: /Previous/ })).toBeDisabled()
  await card.getByRole('button', { name: /Next/ }).click()
  await expect(pagerText(page)).toHaveText(`Showing 11–${active.total} of ${active.total}`)
  await expect(rows).toHaveCount(active.total - 10)
  await expect(card.getByRole('button', { name: /Next/ })).toBeDisabled()
  await card.getByRole('button', { name: /Previous/ }).click()
  await expect(rows).toHaveCount(10)
  // a bigger page holds them all
  await card.getByLabel('Rows per page').selectOption('50')
  await expect(rows).toHaveCount(active.total)
  await expect(pagerText(page)).toHaveText(`Showing 1–${active.total} of ${active.total}`)
  await card.getByLabel('Rows per page').selectOption('10')
  // the status filter pages as well: all certificates include the revoked and the host ones
  const all = await demoCerts(page, 'status=all&limit=1')
  await card.getByLabel('Show').selectOption('all')
  await expect(pagerText(page)).toHaveText(`Showing 1–10 of ${all.total}`)
  expect(all.total).toBeGreaterThan(active.total)

  // by the user's name or username (the key ids start with the username; the name is the user's, now)
  await card.getByLabel('Show').selectOption('active')
  await search.fill('linus')
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('linus1')
  await expect(pagerText(page)).toHaveText('Showing 1–1 of 1')
  await search.fill('Torv') // Linus Torvalds: his family name
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('linus1')
  // by a principal, whole, and by a host name
  await search.fill('katherine2')
  await expect(rows).toHaveCount(1)
  await search.fill('web1.acme.example')
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('Host')
  // by the key's fingerprint (the start of it), the serial and the key id, as the API gives them
  const one = (await demoCerts(page, 'status=active&q=radia6')).items[0]
  expect(one.username).toBe('radia6')
  for (const q of [one.fingerprint.slice(0, 20), one.serial, one.key_id]) {
    await search.fill(q)
    await expect(rows).toHaveCount(1)
    await expect(rows.first()).toContainText(one.serial)
  }
  // the search narrows what the filter chose: a revoked certificate is not among the active ones
  const revoked = (await demoCerts(page, 'status=revoked')).items[0]
  await search.fill(revoked.serial)
  await expect(card.getByText(`No certificates match “${revoked.serial}”.`)).toBeVisible()
  await card.getByLabel('Show').selectOption('revoked')
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('Revoked')
  // nothing found, and clearing the search brings the list back
  await card.getByLabel('Show').selectOption('active')
  await search.fill('zzznobody')
  await expect(card.getByText('No certificates match “zzznobody”.')).toBeVisible()
  await expect(certs).toBeHidden()
  await card.getByRole('button', { name: 'Clear search' }).click()
  await expect(search).toBeFocused()
  await expect(rows).toHaveCount(10)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('ssh: a certificate revoked from the tenant\'s SSH page is revoked on the user\'s page too', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants/servers/ssh`, { waitUntil: 'load' })
  const card = page.locator('section[aria-labelledby="ssh-h"]')
  const rows = card.getByRole('table', { name: 'SSH certificates issued by this tenant' }).locator('tbody tr')
  await card.getByRole('searchbox', { name: 'Search certificates' }).fill('pia')
  await expect(rows).toHaveCount(1)
  const serial = (await demoCerts(page, 'q=pia')).items[0].serial
  await rows.first().getByRole('button', { name: new RegExp('^Revoke certificate ' + serial) }).click()
  await page.getByRole('dialog', { name: 'Revoke certificate?' }).getByRole('button', { name: 'Revoke' }).click()
  await expect(page.locator('.toasts')).toContainText('Certificate revoked.')
  await expect(rows).toHaveCount(0) // not among the active ones any longer
  const u = (await apiCall(page, 'GET', `${API}/users?q=pia`)).items.find((x) => x.username === 'pia')
  const mine = await apiCall(page, 'GET', `${API}/users/${u.id}/ssh-certificates`)
  expect(mine.items).toHaveLength(1)
  expect(mine.items[0]).toMatchObject({ status: 'revoked', reason: 'revoked', tenant: 'Servers', tenant_name: 'servers' })
})

// A user's page: the certificates of the user that have not expired, across the tenants, revocable by administrators.
const userPage = async (page, username) => {
  const u = (await apiCall(page, 'GET', `${API}/users?q=${username}`)).items.find((x) => x.username === username)
  await page.goto(`${A}/users/${u.id}`, { waitUntil: 'load' })
  await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible()
  return u
}

test('user page: the SSH certificates card lists the user\'s unexpired certificates, with their tenant, status and reason', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/users`, { waitUntil: 'load' })
  await userPage(page, 'alan')
  const card = page.getByRole('region', { name: 'SSH certificates', exact: true })
  const table = card.getByRole('table', { name: 'SSH certificates of this user that have not expired' })
  await expect(card).toBeVisible()
  await expect(table.locator('tbody tr')).toHaveCount(2) // one live, one revoked
  await expect(table.getByRole('columnheader')).toContainText(['Tenant', 'Principals', 'Expires', 'Status'])
  const live = table.locator('tbody tr', { hasText: 'Active' })
  const revoked = table.locator('tbody tr', { hasText: 'Revoked' })
  await expect(live).toHaveCount(1)
  await expect(live.getByRole('link', { name: 'Servers' })).toHaveAttribute('href', `${A}/tenants/servers/ssh`)
  await expect(live).toContainText('alan')
  await expect(live.getByRole('button', { name: /^Revoke the certificate for Servers/ })).toBeVisible()
  await expect(revoked).toContainText('Revoked by')
  await expect(revoked.getByRole('button')).toHaveCount(0) // only live ones can be revoked
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  // the tenant leads to its SSH page
  await live.getByRole('link', { name: 'Servers' }).click()
  await expect(page).toHaveURL(`${A}/tenants/servers/ssh`)
})

test('user page: the SSH certificates card is left out for a user with none, and for managers', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/users`, { waitUntil: 'load' })
  await userPage(page, 'iris') // no certificate at all
  await expect(page.getByRole('heading', { name: 'API tokens' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'SSH certificates' })).toHaveCount(0)
  // a manager sees users, not their certificates: the card is not on the page, and the API says so
  await signIn(page, 'manager')
  await page.goto(`${A}/users`, { waitUntil: 'load' })
  const u = await userPage(page, 'alan')
  await expect(page.getByRole('heading', { name: 'API tokens' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'SSH certificates' })).toHaveCount(0)
  await expect(page.getByRole('table', { name: /SSH certificates/ })).toHaveCount(0)
  await expect(page.getByText(u.username).first()).toBeVisible()
  const refused = await page.evaluate(async (url) => (await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } })).status, `${API}/users/${u.id}/ssh-certificates`)
  expect(refused).toBe(403)
})

test('user page: an administrator revokes a certificate (asked first); the list and the status follow, live', async ({ page, browser, baseURL }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/users`, { waitUntil: 'load' })
  const pam = await userPage(page, 'pam')
  const card = page.getByRole('region', { name: 'SSH certificates', exact: true })
  const table = card.getByRole('table', { name: 'SSH certificates of this user that have not expired' })
  await expect(table.locator('tbody tr')).toHaveCount(2)
  await expect(table.locator('tbody tr', { hasText: 'Active' })).toHaveCount(2)
  const first = table.locator('tbody tr').first()
  await first.getByRole('button', { name: /^Revoke the certificate for Servers/ }).click()
  const dlg = page.getByRole('dialog', { name: 'Revoke certificate?' })
  await expect(dlg).toBeVisible()
  await expect(dlg).toContainText('Revoke the certificate for Servers (pam)')
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(table.locator('tbody tr', { hasText: 'Active' })).toHaveCount(2)
  await first.getByRole('button', { name: /^Revoke the certificate for Servers/ }).click()
  await page.getByRole('dialog', { name: 'Revoke certificate?' }).getByRole('button', { name: 'Revoke certificate' }).click()
  await expect(page.locator('.toasts')).toContainText('Certificate revoked.')
  await expect(table.locator('tbody tr', { hasText: 'Active' })).toHaveCount(1)
  await expect(table.locator('tbody tr', { hasText: 'Revoked' })).toHaveCount(1)
  await expect(table.locator('tbody tr', { hasText: 'Revoked' })).toContainText('Revoked by')
  const listed = await apiCall(page, 'GET', `${API}/users/${pam.id}/ssh-certificates`)
  expect(listed.items.map((c) => c.status).sort()).toEqual(['active', 'revoked'])

  // revoked elsewhere, the other one follows without a reload
  const other = await browser.newContext({ baseURL, ignoreHTTPSErrors: true })
  const b = await other.newPage()
  try {
    await signIn(b, 'admin')
    await b.goto(`${A}/users`, { waitUntil: 'load' })
    const left = listed.items.find((c) => c.status === 'active')
    await apiCall(b, 'POST', `${API}/tenants/${left.tenant_id}/ssh/certificates/${left.id}/revoke`)
  } finally { await other.close() }
  await expect(table.locator('tbody tr', { hasText: 'Revoked' })).toHaveCount(2, { timeout: 5000 })
  await expect(table.getByRole('button')).toHaveCount(0)
  // the user's page keeps the card while the certificates have not expired
  await expect(card).toBeVisible()
})
