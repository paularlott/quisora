// The account page's SSH certificates section: tenants with the login command, the user's certificates, and getting a
// certificate from a pasted public key (after confirming it is you, with a second factor). The list comes from the demo
// (the "Servers" tenant has SSH on); getting and revoking a certificate are stubbed, as the demo store is shared by the run.
import { test, expect } from '@playwright/test'
import { axe, fmt, flatBackdrop, setTheme, signIn, WORST } from './helpers.mjs'

const PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexampleexampleexampleexampleexampleexample me@laptop'
const CERT = 'ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIexamplecertificate'
const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })
const reauthNeeded = json({ error: 'Confirm it is you with your password or a passkey first.', field: 'reauth' }, 403)

const section = (page) => page.locator('#ssh')

test('SSH certificates: tenants, command and certificates are listed; a password-only session is told what to do', async ({ page }) => {
  await signIn(page, 'user')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const s = section(page)
  await expect(s.getByRole('heading', { name: 'SSH certificates' })).toBeVisible()
  await expect(s).toContainText('Servers')
  const cmd = s.locator('code[id^="ssh-cmd-"]')
  await expect(cmd).toHaveText(/^quisora ssh login https:\/\/localhost:\d+\/o\/[^/\s]+\/ssh\/[^/\s]+$/)

  // the command is copied (the clipboard is not readable here: the button says so)
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], { origin: page.url() }).catch(() => {})
  await s.getByRole('button', { name: 'Copy the command for Servers' }).click()
  await expect(s.getByRole('button', { name: 'Copy the command for Servers' })).toContainText('Copied')

  // the certificates of the demo user: one live, one revoked
  const table = s.getByRole('table', { name: 'Your SSH certificates that have not expired' })
  await expect(table.locator('tbody tr')).toHaveCount(2)
  await expect(table).toContainText('Active')
  await expect(table).toContainText('Revoked')
  await expect(s.getByRole('button', { name: /^Revoke the certificate for Servers/ })).toHaveCount(1)

  // signed in with a password only: no certificate can be made, and it says how to
  await expect(s).toContainText('You signed in with a password only')
  await expect(s.getByRole('button', { name: 'Get a certificate' })).toBeDisabled()
})

test('SSH certificates: get a certificate (confirm, then copy and download), and revoke one', async ({ page }) => {
  await signIn(page, 'user')
  const cert = { id: 'c1', tenant_id: 't1', tenant: 'Servers', serial: '1', principals: ['alan', 'group:ops'], fingerprint: 'SHA256:x',
    valid_after: '2026-10-31T00:00:00Z', valid_before: '2099-01-01T00:00:00Z', via: 'account', status: 'active' }
  let issued = false
  let revoked = false
  const state = () => ({ mfa: true, tenants: [{ id: 't1', name: 'Servers', principals: ['alan', 'group:ops'], cert_ttl: 28800,
    url: 'https://localhost:18443/o/acme/ssh/t1', command: 'quisora ssh login https://localhost:18443/o/acme/ssh/t1' }],
  certificates: issued ? [{ ...cert, status: revoked ? 'revoked' : 'active', reason: revoked ? 'revoked' : '' }] : [] })
  await page.route('**/api-internal/account/ssh', (route) => route.fulfill(json(state())))
  let signs = 0
  let sent = null
  await page.route('**/api-internal/account/ssh/sign', (route) => {
    signs++
    if (signs === 1) return route.fulfill(reauthNeeded)
    sent = route.request().postDataJSON()
    issued = true
    return route.fulfill(json({ certificate: CERT, id: 'c1', tenant_id: 't1', serial: '1', principals: ['alan', 'group:ops'], fingerprint: 'SHA256:x',
      valid_after: cert.valid_after, valid_before: cert.valid_before }))
  })
  await page.route('**/api-internal/account/reauth', (route) => route.request().method() === 'POST' ? route.fulfill(json({ ok: true })) : route.fallback())
  await page.route('**/api-internal/account/ssh/certificates/c1/revoke', (route) => { revoked = true; return route.fulfill({ status: 204 }) })

  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const s = section(page)
  await expect(s).toContainText('You have no certificates that are still valid.')
  await expect(s.getByText('You signed in with a password only')).toBeHidden()
  const get = s.getByRole('button', { name: 'Get a certificate' })
  await get.click()
  const dlg = page.getByRole('dialog', { name: 'Get a certificate' })
  await expect(dlg).toBeVisible()
  await expect(dlg.getByLabel('Tenant')).toBeHidden() // one tenant: nothing to choose
  await expect(dlg).toContainText('cat ~/.ssh/id_ed25519.pub')
  await expect(dlg).toContainText('alan, group:ops')
  await expect(dlg.getByLabel(/Public key/)).toBeFocused()
  const r0 = await axe(page)
  expect(r0.violations.length, fmt(r0.violations)).toBe(0)

  // first it asks to confirm it is you, then goes on with the same key
  await dlg.getByLabel(/Public key/).fill(PUB + '\n')
  await dlg.getByRole('button', { name: 'Get certificate' }).click()
  const reauth = page.getByRole('dialog', { name: 'Confirm it is you' })
  await expect(reauth).toBeVisible()
  await reauth.locator('#f-ra_password').fill('stubbed')
  await page.keyboard.press('Enter')
  const done = page.getByRole('dialog', { name: 'Your certificate' })
  await expect(done).toBeVisible()
  expect(sent).toEqual({ tenant_id: 't1', public_key: PUB })
  await expect(done.locator('#ssh-cert')).toHaveText(CERT)
  await expect(done).toContainText('id_ed25519-cert.pub')
  await expect(done).toContainText('valid until')
  const r1 = await axe(page)
  expect(r1.violations.length, fmt(r1.violations)).toBe(0)

  const download = page.waitForEvent('download')
  await done.getByRole('button', { name: 'Download' }).click()
  const file = await download
  expect(file.suggestedFilename()).toBe('id_ed25519-cert.pub')
  expect(await (await import('node:fs')).promises.readFile(await file.path(), 'utf8')).toBe(CERT + '\n')
  await done.getByRole('button', { name: 'Copy' }).click()
  await expect(done.getByRole('button', { name: /Copied/ })).toBeVisible()

  await done.getByRole('button', { name: 'Done' }).click()
  await expect(done).toBeHidden()
  await expect(get).toBeFocused()
  const table = s.getByRole('table', { name: 'Your SSH certificates that have not expired' })
  await expect(table).toContainText('alan, group:ops')
  await expect(table).toContainText('Active')

  // revoking asks first
  const revoke = s.getByRole('button', { name: 'Revoke the certificate for Servers (alan, group:ops)' })
  await revoke.click()
  const confirm = page.getByRole('dialog', { name: 'Revoke certificate' })
  await expect(confirm).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(confirm).toBeHidden()
  expect(revoked).toBe(false)
  await revoke.click()
  await confirm.getByRole('button', { name: 'Revoke certificate' }).click()
  await expect(page.locator('.toasts')).toContainText('Certificate revoked.')
  await expect(table).toContainText('Revoked')
  await expect(revoke).toHaveCount(0)
})

test('SSH certificates: a refusal and a bad key are shown; several tenants are chosen from', async ({ page }) => {
  await signIn(page, 'user')
  await page.route('**/api-internal/account/ssh', (route) => route.fulfill(json({ mfa: true, certificates: [], tenants: [
    { id: 't1', name: 'Servers', principals: ['alan'], cert_ttl: 28800, url: 'https://x/o/acme/ssh/t1', command: 'quisora ssh login https://x/o/acme/ssh/t1' },
    { id: 't2', name: 'Lab', principals: ['alan', 'group:lab'], cert_ttl: 3600, url: 'https://x/o/acme/ssh/t2', command: 'quisora ssh login https://x/o/acme/ssh/t2' }] })))
  let reply = json({ error: 'Not a public key.', field: 'public_key' }, 422)
  let body = null
  await page.route('**/api-internal/account/ssh/sign', (route) => { body = route.request().postDataJSON(); return route.fulfill(reply) })
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const s = section(page)
  await expect(s.locator('code[id^="ssh-cmd-"]')).toHaveCount(2)
  await s.getByRole('button', { name: 'Get a certificate' }).click()
  const dlg = page.getByRole('dialog', { name: 'Get a certificate' })
  await dlg.getByLabel('Tenant').selectOption('t2')
  await expect(dlg).toContainText('1 hour')
  await dlg.getByLabel(/Public key/).fill('hello')
  await dlg.getByRole('button', { name: 'Get certificate' }).click()
  expect(body).toEqual({ tenant_id: 't2', public_key: 'hello' })
  await expect(dlg.locator('#e-ssh_public_key')).toHaveText('Not a public key.')
  await expect(dlg.getByLabel(/Public key/)).toBeFocused()
  await expect(dlg.getByLabel(/Public key/)).toHaveAttribute('aria-invalid', 'true')

  reply = json({ error: 'The sign-in is too old to get a certificate: sign in again.' }, 403)
  await dlg.getByRole('button', { name: 'Get certificate' }).click()
  await expect(page.locator('.toasts')).toContainText('too old')
  await expect(dlg).toBeVisible()
})

for (const theme of ['light', 'dark']) {
  test(`SSH certificates: no accessibility violations (${theme})`, async ({ page }) => {
    await setTheme(page, theme)
    await signIn(page, 'user')
    await page.goto('/o/acme/account', { waitUntil: 'load' })
    await expect(section(page)).toBeVisible()
    for (const c of WORST[theme]) {
      await flatBackdrop(page, c)
      const r = await axe(page, { include: '#ssh' })
      expect(r.violations.length, `${c}\n${fmt(r.violations)}`).toBe(0)
    }
  })
}

test('SSH certificates: hidden when no tenant has SSH for the user', async ({ page }) => {
  await signIn(page, 'user')
  await page.route('**/api-internal/account/ssh', (route) => route.fulfill(json({ mfa: false, tenants: [], certificates: [] })))
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  await expect(page.locator('#profile')).toBeVisible()
  await expect(page.locator('#ssh')).toBeHidden()
  await expect(page.getByRole('heading', { name: 'SSH certificates' })).toHaveCount(0)
})

test('SSH certificates: an administrator where the tenant gives administrators none is told why', async ({ page }) => {
  await signIn(page, 'admin') // the demo's "Servers" tenant does not allow managers and administrators
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const s = section(page)
  await expect(s.getByRole('heading', { name: 'SSH certificates' })).toBeVisible()
  await expect(s.getByRole('heading', { name: 'Where you cannot get one' })).toBeVisible()
  await expect(s).toContainText('This tenant gives no certificates to managers and administrators')
  await expect(s.getByRole('heading', { name: 'Where you can use one' })).toBeHidden()
  await expect(s.getByRole('button', { name: 'Get a certificate' })).toBeDisabled()
  const r = await axe(page, { include: '#ssh' })
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})
