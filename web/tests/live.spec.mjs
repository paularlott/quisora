// Live updates: two administrators in two browser contexts. What one changes appears in the other's
// lists without a reload; focus never moves; the pause switch, open dialogs and typing hold updates back; an open edit
// dialog gets a non-modal notice when its record changes.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, uniq, axe, fmt, setTheme } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/v1/orgs/acme'

// Two admin sessions, each on its own page. `a` shows `path`; `b` sits on a page that can call the API.
async function twoAdmins(browser, baseURL, path, theme) {
  const mk = async () => {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 }, baseURL })
    const page = await ctx.newPage()
    if (theme) await setTheme(page, theme)
    await signIn(page, 'admin')
    return { ctx, page }
  }
  const [a, b] = await Promise.all([mk(), mk()])
  await a.page.goto(path)
  await b.page.goto(`${A}/audit`)
  return { a: a.page, b: b.page, close: async () => { await a.ctx.close(); await b.ctx.close() } }
}

// The header's pause button: pressed = paused.
const live = (page) => page.getByRole('button', { name: 'Pause live updates' })
const expectLive = (page) => expect(live(page)).toHaveAttribute('aria-pressed', 'false')
const expectPaused = (page) => expect(live(page)).toHaveAttribute('aria-pressed', 'true')

test('users list: another admin adds a user and it appears without a reload; focus stays put', async ({ browser, baseURL }) => {
  const { a, b, close } = await twoAdmins(browser, baseURL, `${A}/users`)
  try {
    await a.waitForSelector('tbody tr')
    await expectLive(a)
    await expect(a.locator('#live-state')).toHaveText('Connected')
    const name = uniq('zzlive')
    await a.getByRole('searchbox', { name: 'Search users' }).fill(name)
    await expect(a.getByRole('heading', { name: 'Nothing matches your search' })).toBeVisible()
    await a.locator('#filter-role').focus()
    await a.evaluate(() => { window.__reloaded = true })
    await apiCall(b, 'POST', `${API}/users`, { username: name, email: `${name}@acme.example`, given_name: 'Live', family_name: 'Person' })
    await expect(a.getByRole('row', { name: new RegExp(name) })).toBeVisible({ timeout: 3500 })
    expect(await a.evaluate(() => window.__reloaded)).toBe(true) // same document: no reload
    expect(await a.evaluate(() => document.activeElement.id)).toBe('filter-role')
    await expect(a.locator('#live-polite')).toHaveText('Users list updated')
    await expect(a.getByRole('row', { name: new RegExp(name) })).toHaveClass(/row-live/)
    // delete it again: the row goes
    const u = (await apiCall(b, 'GET', `${API}/users?q=${name}`)).items[0]
    await apiCall(b, 'DELETE', `${API}/users/${u.id}`)
    await expect(a.getByRole('row', { name: new RegExp(name) })).toHaveCount(0, { timeout: 3500 })
    expect(await a.evaluate(() => document.activeElement.id)).toBe('filter-role')
  } finally { await close() }
})

test('the Live updates button pauses and resumes, works from the keyboard and is remembered', async ({ browser, baseURL }) => {
  const { a, b, close } = await twoAdmins(browser, baseURL, `${A}/users`)
  try {
    await a.waitForSelector('tbody tr')
    const name = uniq('zzpause')
    await a.getByRole('searchbox', { name: 'Search users' }).fill(name)
    await expect(a.getByRole('heading', { name: 'Nothing matches your search' })).toBeVisible()
    // toggle with the keyboard (Space on the focused button)
    await live(a).focus()
    await a.keyboard.press('Space')
    await expectPaused(a)
    await expect(a.locator('#live-state')).toHaveText('Paused')
    expect(await a.evaluate(() => localStorage.getItem('quisora-live'))).toBe('0')
    await apiCall(b, 'POST', `${API}/users`, { username: name, email: `${name}@acme.example`, given_name: "T" })
    await a.waitForTimeout(2200)
    await expect(a.getByRole('row', { name: new RegExp(name) })).toHaveCount(0)
    // resume: it catches up
    await a.keyboard.press('Space')
    await expectLive(a)
    await expect(a.getByRole('row', { name: new RegExp(name) })).toBeVisible({ timeout: 4000 })
    // remembered: a reload starts paused
    await live(a).click()
    await a.reload()
    await expectPaused(a)
    await live(a).click()
    await a.waitForSelector('tbody tr')
  } finally { await close() }
})

test('an open dialog holds the refresh back until it is closed', async ({ browser, baseURL }) => {
  const { a, b, close } = await twoAdmins(browser, baseURL, `${A}/users`)
  try {
    await a.waitForSelector('tbody tr')
    const name = uniq('zzdlg')
    await a.getByRole('searchbox', { name: 'Search users' }).fill(name)
    await expect(a.getByRole('heading', { name: 'Nothing matches your search' })).toBeVisible()
    await a.getByRole('button', { name: 'New user' }).click()
    await expect(a.getByRole('dialog', { name: 'New user' })).toBeVisible()
    await apiCall(b, 'POST', `${API}/users`, { username: name, email: `${name}@acme.example`, given_name: 'T' })
    await a.waitForTimeout(2000)
    await expect(a.locator('tbody tr', { hasText: name })).toHaveCount(0)
    expect(await a.evaluate(() => document.activeElement.id)).toBe('f-email')
    await a.keyboard.press('Escape')
    await expect(a.getByRole('row', { name: new RegExp(name) })).toBeVisible({ timeout: 4000 })
  } finally { await close() }
})

test('typing in the search box is never interrupted by a refresh', async ({ browser, baseURL }) => {
  const { a, b, close } = await twoAdmins(browser, baseURL, `${A}/users`)
  try {
    await a.waitForSelector('tbody tr')
    const name = uniq('zztype')
    await a.getByRole('searchbox', { name: 'Search users' }).fill(name)
    await expect(a.getByRole('heading', { name: 'Nothing matches your search' })).toBeVisible()
    await a.getByRole('searchbox', { name: 'Search users' }).focus()
    await a.keyboard.type(' ')
    await apiCall(b, 'POST', `${API}/users`, { username: name, email: `${name}@acme.example`, given_name: "T" })
    // keep typing for ~2 s (a space and Backspace: the trimmed query never changes, so a refresh would show the row
    // at once). Each keystroke is under 250 ms after the previous one, so the search's own debounce never fires either.
    const box = a.getByRole('searchbox', { name: 'Search users' })
    await box.focus()
    for (let i = 0; i < 8; i++) { await a.keyboard.type(' '); await a.waitForTimeout(110); await a.keyboard.press('Backspace'); await a.waitForTimeout(110) }
    await expect(a.locator('tbody tr', { hasText: name })).toHaveCount(0)
    await expect(box).toBeFocused()
    await expect(a.getByRole('row', { name: new RegExp(name) })).toBeVisible({ timeout: 5000 }) // idle again: the update lands
    await expect(box).toBeFocused()
  } finally { await close() }
})

test('edit dialog: a change by someone else shows a notice without moving focus; a deletion disables Save', async ({ browser, baseURL }) => {
  const { a, b, close } = await twoAdmins(browser, baseURL, `${A}/users`)
  try {
    await a.waitForSelector('tbody tr')
    const name = uniq('zzedit')
    const u = await apiCall(b, 'POST', `${API}/users`, { username: name, email: `${name}@acme.example`, given_name: 'Edit', family_name: 'Me' })
    await a.getByRole('searchbox', { name: 'Search users' }).fill(name)
    await expect(a.getByRole('button', { name: 'Edit Edit Me' })).toBeVisible()
    await a.getByRole('button', { name: 'Edit Edit Me' }).click()
    const dlg = a.getByRole('dialog', { name: 'Edit user' })
    await expect(dlg).toBeVisible()
    await expect(dlg.getByRole('status').filter({ hasText: /./ })).toHaveCount(0)
    await a.locator('#f-family_name').focus()
    await apiCall(b, 'PATCH', `${API}/users/${u.id}`, { family_name: 'Elsewhere' })
    const notice = dlg.locator('.edit-notice')
    await expect(notice).toContainText('This was changed by someone else — saving will show the latest version', { timeout: 3500 })
    expect(await a.evaluate(() => document.activeElement.id)).toBe('f-family_name')
    await expect(dlg).toBeVisible()
    await expect(dlg.getByRole('button', { name: 'Save changes' })).toBeEnabled()
    const r = await axe(a)
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    // deleted elsewhere: the notice says so and Save is disabled
    await apiCall(b, 'DELETE', `${API}/users/${u.id}`)
    await expect(notice).toContainText('deleted by someone else', { timeout: 3500 })
    await expect(dlg.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    expect(await a.evaluate(() => document.activeElement.id)).toBe('f-family_name')
    await a.keyboard.press('Escape')
    await expect(a.getByRole('row', { name: new RegExp(name) })).toHaveCount(0, { timeout: 4000 })
  } finally { await close() }
})

test('tenant page: clients created, moved and deleted elsewhere update the list; the tenants list follows', async ({ browser, baseURL }) => {
  const { a, b, close } = await twoAdmins(browser, baseURL, `${A}/tenants`)
  try {
    await a.waitForSelector('tbody tr')
    const tn = uniq('lt')
    const other = uniq('ot')
    await apiCall(b, 'POST', `${API}/tenants`, { name: tn, display_name: 'Live ' + tn })
    // the tenants list shows the new tenant
    await expect(a.getByRole('link', { name: 'Live ' + tn, exact: true })).toBeVisible({ timeout: 3500 })
    const t1 = (await apiCall(b, 'GET', `${API}/tenants?q=${tn}`)).items[0]
    await apiCall(b, 'POST', `${API}/tenants`, { name: other, display_name: 'Other ' + other })
    const t2 = (await apiCall(b, 'GET', `${API}/tenants?q=${other}`)).items[0]
    // open its page from the list link
    await a.getByRole('link', { name: 'Live ' + tn, exact: true }).click()
    await expect(a.getByRole('heading', { level: 1 })).toHaveText('Tenant: Live ' + tn)
    await expect(a.getByText('No clients in this tenant yet')).toBeVisible()
    const c = await apiCall(b, 'POST', `${API}/clients`, { name: 'Live client', tenant_id: t1.id, redirect_uris: ['https://l.example/cb'] })
    await expect(a.getByRole('row', { name: /Live client/ })).toBeVisible({ timeout: 3500 })
    await expect(a.locator('#clients-h .badge')).toHaveText('1 client')
    // moved to another tenant: it leaves this list
    await apiCall(b, 'PATCH', `${API}/clients/${c.id}`, { tenant_id: t2.id })
    await expect(a.getByRole('row', { name: /Live client/ })).toHaveCount(0, { timeout: 3500 })
    await expect(a.getByText('No clients in this tenant yet')).toBeVisible()
    // the tenant itself changed elsewhere: the summary follows
    await apiCall(b, 'PATCH', `${API}/tenants/${t1.id}`, { settings: { password_login: false, passkey_login: true, all_providers: true, providers: [], require_mfa: true } })
    await expect(a.locator('.kv')).toContainText('Required', { timeout: 3500 })
    // deleted elsewhere
    await apiCall(b, 'DELETE', `${API}/tenants/${t1.id}`)
    await expect(a.locator('.alert', { hasText: 'This tenant was deleted by someone else' })).toBeVisible({ timeout: 3500 })
    await apiCall(b, 'DELETE', `${API}/clients/${c.id}`)
    await apiCall(b, 'DELETE', `${API}/tenants/${t2.id}`)
  } finally { await close() }
})

test('audit log and groups follow other admins', async ({ browser, baseURL }) => {
  const { a, b, close } = await twoAdmins(browser, baseURL, `${A}/groups`)
  try {
    await a.waitForSelector('tbody tr')
    const g = uniq('grp')
    await apiCall(b, 'POST', `${API}/groups`, { display_name: g })
    await a.getByRole('searchbox', { name: 'Search groups' }).fill(g)
    await expect(a.getByRole('row', { name: new RegExp(g) })).toBeVisible()
    const grp = (await apiCall(b, 'GET', `${API}/groups?q=${g}`)).items[0]
    // members dialog follows member changes
    await a.getByRole('button', { name: new RegExp('Members of ' + g) }).click()
    const dlg = a.getByRole('dialog', { name: 'Members of ' + g })
    await expect(dlg.getByText('This group has no members yet.')).toBeVisible()
    const user = (await apiCall(b, 'GET', `${API}/users?q=alan`)).items[0]
    await apiCall(b, 'PUT', `${API}/groups/${grp.id}/members/${user.id}`)
    await expect(dlg.getByRole('row', { name: /Alan Turing/ })).toBeVisible({ timeout: 3500 })
    await apiCall(b, 'DELETE', `${API}/groups/${grp.id}/members/${user.id}`)
    await expect(dlg.getByText('This group has no members yet.')).toBeVisible({ timeout: 3500 })
    await a.keyboard.press('Escape')
    await apiCall(b, 'DELETE', `${API}/groups/${grp.id}`)
    await expect(a.getByRole('row', { name: new RegExp(g) })).toHaveCount(0, { timeout: 4000 })
    // audit log
    await a.goto(`${A}/audit`)
    await a.waitForSelector('tbody tr')
    const g2 = uniq('aud')
    await apiCall(b, 'POST', `${API}/groups`, { display_name: g2 })
    await expect(a.getByRole('cell', { name: g2 }).first()).toBeVisible({ timeout: 3500 })
  } finally { await close() }
})

test('user page and settings page refetch; settings keeps unsaved edits', async ({ browser, baseURL }) => {
  const name = uniq('zzdet')
  const { a, b, close } = await twoAdmins(browser, baseURL, `${A}/audit`)
  try {
    const u = await apiCall(b, 'POST', `${API}/users`, { username: name, email: `${name}@acme.example`, given_name: 'Detail', family_name: 'One' })
    await a.goto(`${A}/users/${u.id}`)
    await expect(a.getByRole('heading', { level: 1 })).toHaveText('Detail One')
    await apiCall(b, 'PATCH', `${API}/users/${u.id}`, { family_name: 'Two' })
    await expect(a.getByRole('heading', { level: 1 })).toHaveText('Detail Two', { timeout: 3500 })
    await apiCall(b, 'DELETE', `${API}/users/${u.id}`)
    await expect(a.locator('.alert', { hasText: 'This user was deleted by someone else' })).toBeVisible({ timeout: 3500 })

    // settings: a clean form follows; an edited form keeps its edits and offers the latest version
    await a.goto(`${A}/settings`)
    await a.waitForSelector('#f-display_name')
    const before = await a.locator('#f-display_name').inputValue()
    await apiCall(b, 'PUT', `${API}/settings`, { display_name: before + ' 2' })
    await expect(a.locator('#f-display_name')).toHaveValue(before + ' 2', { timeout: 3500 })
    await a.locator('#f-display_name').fill('Mine, unsaved')
    await a.locator('#f-display_name').blur()
    await apiCall(b, 'PUT', `${API}/settings`, { display_name: before })
    await expect(a.getByText('changed by someone else')).toBeVisible({ timeout: 3500 })
    await expect(a.locator('#f-display_name')).toHaveValue('Mine, unsaved')
    await a.getByRole('button', { name: /load the latest/ }).click()
    await expect(a.locator('#f-display_name')).toHaveValue(before)
  } finally { await close() }
})

test('super admin: the organizations list follows new organizations', async ({ browser, baseURL }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, baseURL })
  const a = await ctx.newPage()
  await signIn(a, 'super')
  await a.goto('/admin/orgs')
  await a.waitForSelector('tbody tr')
  const ctx2 = await browser.newContext({ ignoreHTTPSErrors: true, baseURL })
  const b = await ctx2.newPage()
  await signIn(b, 'super')
  await b.goto('/admin/orgs')
  const slug = uniq('lo')
  await apiCall(b, 'POST', '/api/v1/orgs', { name: slug, display_name: 'Live Org ' + slug })
  await a.getByRole('searchbox', { name: 'Search organizations' }).fill(slug)
  await expect(a.getByRole('link', { name: 'Live Org ' + slug })).toBeVisible({ timeout: 3500 })
  await apiCall(b, 'DELETE', `/api/v1/orgs/${slug}`)
  await expect(a.getByRole('link', { name: 'Live Org ' + slug })).toHaveCount(0, { timeout: 3500 })
  await ctx.close(); await ctx2.close()
})
