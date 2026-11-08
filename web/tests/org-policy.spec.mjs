// An organization's own policy and footer: a super admin sets the shortest password, the lockout, the longest API
// token and the managers' and admins' sessions in the organization dialog (blank keeps the server's, which the help
// names), the overview shows them; an organization's footer replaces the primary organization's, which replaces the
// server's.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt } from './helpers.mjs'

const API = '/api/orgs/acme'
const POLICY = ['password_min_length', 'lockout_attempts', 'lockout_minutes', 'api_token_max_days', 'privileged_ttl', 'privileged_idle']

async function resetPolicy(page) {
  const o = await apiCall(page, 'GET', API)
  const settings = { ...o.settings }
  for (const k of POLICY) settings[k] = 0
  await apiCall(page, 'PATCH', API, { settings })
}

test.describe.configure({ mode: 'serial' })

test('a super admin sets an organization\'s password, lockout, token and session policy', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  try {
    await resetPolicy(page)
    await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
    const dlg = page.getByRole('dialog', { name: 'Edit organization' })
    await expect(dlg.locator('#h-password_min_length')).toHaveText("8 to 64. Leave empty to use the server's setting (15).")
    await expect(dlg.locator('#f-password_min_length')).toHaveValue('')

    // out of range: refused on its field
    await dlg.getByLabel('Shortest password (characters)').fill('7')
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg.locator('#e-password_min_length')).toContainText('between 8 and 64')

    await dlg.getByLabel('Shortest password (characters)').fill('20')
    await dlg.getByLabel('Attempts before locking').fill('5')
    await dlg.getByLabel('Locked for (minutes)').fill('30')
    await dlg.getByLabel('Longest lifetime (days)').fill('30')
    await dlg.getByRole('group', { name: 'Managers and admins' }).getByLabel('Lifetime (hours)').fill('2')
    await dlg.getByRole('group', { name: 'Managers and admins' }).getByLabel('Idle timeout (minutes)').fill('10')
    const r = await axe(page, { include: '#org-dialog' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg).toBeHidden()
    const s = (await apiCall(page, 'GET', API)).settings
    expect(s).toMatchObject({ password_min_length: 20, lockout_attempts: 5, lockout_minutes: 30, api_token_max_days: 30,
      privileged_ttl: 7200, privileged_idle: 600 })

    // no limit for API tokens: the days are not used
    await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
    await expect(dlg.getByLabel('Longest lifetime (days)')).toHaveValue('30')
    await dlg.getByLabel('No limit').check()
    await expect(dlg.getByLabel('Longest lifetime (days)')).toBeDisabled()
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg).toBeHidden()
    expect((await apiCall(page, 'GET', API)).settings.api_token_max_days).toBe(-1)
    await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
    await expect(page.getByText('No limit: tokens may never expire')).toBeVisible()
    await page.goto('/admin/orgs', { waitUntil: 'load' })
    await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
    await expect(dlg.getByLabel('No limit')).toBeChecked()
    await dlg.getByLabel('No limit').uncheck()
    await dlg.getByLabel('Longest lifetime (days)').fill('30')
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg).toBeHidden()

    // the overview shows them
    await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
    const card = page.getByRole('region', { name: 'Sign-in' })
    await expect(card.getByText('20 characters')).toBeVisible()
    await expect(card.getByText('After 5 failed attempts, for 30 minutes')).toBeVisible()
    await expect(card.getByText('At most 30 days')).toBeVisible()
    await expect(card.getByText('2 hours sessions, signed out when idle for 10 minutes')).toBeVisible()
  } finally {
    await resetPolicy(page)
  }
})

test('an organization\'s footer, else the primary organization\'s, else the server\'s', async ({ page, browser }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  const anon = await browser.newPage({ ignoreHTTPSErrors: true })
  const footer = (path) => anon.goto(path, { waitUntil: 'load' }).then(() => anon.locator('footer.app-footer'))
  try {
    await apiCall(page, 'PATCH', '/api/orgs/primary/branding', { footer: '' })
    await apiCall(page, 'PATCH', `${API}/branding`, { footer: '' })
    await expect(await footer('/o/acme/login')).toHaveText('Quisora demo · All data is in memory')

    await apiCall(page, 'PATCH', '/api/orgs/primary/branding', { footer: 'Run by <a href="https://example.com/it">IT</a>' })
    let f = await footer('/o/acme/login')
    await expect(f).toHaveText('Run by IT')
    await expect(f.getByRole('link', { name: 'IT' })).toHaveAttribute('href', 'https://example.com/it')

    // the organization's own, set by its administrator on the overview's branding card; markup outside the list is removed
    await signIn(page, 'admin')
    await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
    const card = page.getByRole('region', { name: 'Branding' })
    await card.getByLabel('Footer').fill('Acme <strong>Corp</strong> <img src="x" onerror="alert(1)"><a href="javascript:alert(1)">bad</a>')
    await card.getByRole('button', { name: 'Save branding' }).click()
    await expect(page.getByText('Branding saved.')).toBeVisible()
    await page.reload({ waitUntil: 'load' })
    await expect(card.getByLabel('Footer')).toHaveValue(/^Acme <strong>Corp<\/strong>/)
    f = await footer('/o/acme/login')
    await expect(f).toHaveText('Acme Corp bad')
    await expect(f.locator('strong')).toHaveText('Corp')
    await expect(f.locator('img')).toHaveCount(0)
    await expect(f.locator('a')).not.toHaveAttribute('href', /.*/)
  } finally {
    await signIn(page, 'super')
    await page.goto('/admin/orgs', { waitUntil: 'load' })
    await apiCall(page, 'PATCH', '/api/orgs/primary/branding', { footer: '' })
    await apiCall(page, 'PATCH', `${API}/branding`, { footer: '' })
    await anon.close()
  }
})
