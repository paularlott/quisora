// Keyboard-only behaviour: skip link, tab order, sortable headers, theme switch, dialog focus trap / Esc / focus return,
// inline field errors, reflow at 320px.
import { test, expect } from '@playwright/test'
import { signIn, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'

async function gotoRows(page, path, as = 'admin') {
  await signIn(page, as)
  await page.goto(path, { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
}

test('skip link is the first tab stop and moves focus to main', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  await page.keyboard.press('Tab')
  const skip = page.getByRole('link', { name: 'Skip to main content' })
  await expect(skip).toBeFocused()
  await expect(skip).toBeInViewport()
  await page.keyboard.press('Enter')
  await expect(page.locator('#main')).toBeFocused()
})

test('landmarks and headings are present', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  for (const role of ['banner', 'navigation', 'main', 'contentinfo']) await expect(page.getByRole(role).first()).toBeVisible()
  await expect(page.getByRole('navigation', { name: 'Primary' })).toBeVisible()
  await expect(page.locator('h1')).toHaveCount(1)
  await expect(page.locator('a[aria-current="page"]')).toHaveText(/Users/)
})

test('every interactive control is reachable with Tab and there is no keyboard trap', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  const expected = await page.evaluate(() => {
    const vis = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && getComputedStyle(el).visibility !== 'hidden'
    return [...document.querySelectorAll('a[href], button, input, select, textarea, [tabindex="0"]')]
      .filter((el) => !el.disabled && vis(el) && !el.closest('dialog:not([open])') && !el.closest('[inert]')).length
  })
  const seen = new Set()
  for (let i = 0; i < expected + 5; i++) {
    await page.keyboard.press('Tab')
    seen.add(await page.evaluate(() => {
      const a = document.activeElement
      if (!a || a === document.body) return 'body'
      a.dataset.tabseen = a.dataset.tabseen || String(Math.random())
      return a.dataset.tabseen
    }))
  }
  // the focus order wrapped around without getting stuck: we visited (almost) every control
  expect(seen.size).toBeGreaterThanOrEqual(expected - 1)
})

test('focus indicator is visible (>= 2px outline) on buttons, links and inputs', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  for (const sel of ['#list-search', 'button:has-text("New user")', 'tbody a']) {
    await page.locator(sel).first().focus()
    await page.keyboard.press('Shift+Tab')
    await page.keyboard.press('Tab')
    const w = await page.locator(sel).first().evaluate((el) => parseFloat(getComputedStyle(el).outlineWidth))
    expect(w, sel).toBeGreaterThanOrEqual(2)
  }
})

test('sortable headers are buttons that update aria-sort from the keyboard', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  const th = page.locator('th', { hasText: 'Role' })
  const btn = th.getByRole('button', { name: 'Role' })
  await expect(th).not.toHaveAttribute('aria-sort', /./)
  await btn.focus()
  await page.keyboard.press('Enter')
  await expect(th).toHaveAttribute('aria-sort', 'ascending')
  await page.keyboard.press('Space')
  await expect(th).toHaveAttribute('aria-sort', 'descending')
  // the user column lost its sort state
  await expect(page.locator('th', { hasText: 'User' }).first()).not.toHaveAttribute('aria-sort', /./)
})

test('search filters server-side and announces the result', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  await page.getByRole('searchbox', { name: 'Search users' }).fill('turing')
  await expect(page.locator('tbody tr')).toHaveCount(1)
  await expect(page.locator('#live-polite')).toContainText('1 users match')
  await page.getByRole('searchbox', { name: 'Search users' }).fill('zzzz-nothing')
  await expect(page.getByRole('heading', { name: 'Nothing matches your search' })).toBeVisible()
  await page.getByRole('button', { name: 'Clear search' }).first().click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
})

test('pagination moves between pages', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  await page.locator('#page-size').selectOption('10')
  await expect(page.locator('tbody tr')).toHaveCount(10)
  const first = await page.locator('tbody tr').first().innerText()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect.poll(async () => page.locator('tbody tr').first().innerText()).not.toBe(first)
  await page.getByRole('button', { name: 'Previous' }).click()
  await expect.poll(async () => page.locator('tbody tr').first().innerText()).toBe(first)
})

test('theme switch toggles with the keyboard and persists', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  const sw = page.getByRole('switch', { name: 'Dark theme' })
  const before = await page.locator('html').getAttribute('data-theme')
  await sw.focus()
  await page.keyboard.press('Space')
  const after = await page.locator('html').getAttribute('data-theme')
  expect(after).not.toBe(before)
  await expect(sw).toHaveAttribute('aria-checked', after === 'dark' ? 'true' : 'false')
  await page.reload({ waitUntil: 'load' })
  expect(await page.locator('html').getAttribute('data-theme')).toBe(after)
})

test('theme bootstrap: no flash, honours the stored choice before first paint', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('quisora-theme', 'dark'))
  await signIn(page, 'admin')
  const res = await page.goto(`${A}/users`)
  expect(res.headers()['content-security-policy']).not.toContain('unsafe-inline')
  expect(await page.locator('html').getAttribute('data-theme')).toBe('dark')
  // the theme script is an external file in <head> and runs before the stylesheet
  const order = await page.evaluate(() => [...document.head.children].filter((e) => e.tagName === 'SCRIPT' || e.tagName === 'LINK').map((e) => (e.src || e.href).split('/').pop().split('-')[0]))
  expect(order.indexOf('theme')).toBeLessThan(order.indexOf('main'))
})

test('dialog: opens from the keyboard, traps focus, Esc closes and returns focus', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  const opener = page.getByRole('button', { name: 'New user' })
  await opener.focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'New user' })
  await expect(dlg).toBeVisible()
  await expect(page.locator('#f-email')).toBeFocused()
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press('Tab')
    expect(await page.evaluate(() => !!document.activeElement.closest('dialog[open]')), `tab ${i}`).toBe(true)
  }
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press('Shift+Tab')
    expect(await page.evaluate(() => !!document.activeElement.closest('dialog[open]'))).toBe(true)
  }
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
  await expect(opener).toBeFocused()
})

test('form: empty submit shows inline errors, focuses the field and sets aria-invalid', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  await page.getByRole('button', { name: 'New organization' }).click()
  await page.getByRole('button', { name: 'Create organization' }).click()
  const name = page.locator('#f-name')
  await expect(name).toHaveAttribute('aria-invalid', 'true')
  await expect(name).toBeFocused()
  await expect(page.locator('#e-name')).not.toBeEmpty()
  const describedby = await name.getAttribute('aria-describedby')
  expect(describedby).toContain('e-name')
  await expect(page.locator('dialog[open] [data-live=assertive]')).not.toBeEmpty()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('create, edit and delete an organization through the modal + confirm dialog', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  await page.getByRole('button', { name: 'New organization' }).click()
  await page.locator('#f-display_name').fill('Kbd Test Org')
  await page.locator('#f-name').fill('kbdtest')
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog')).toBeHidden()
  await expect(page.getByRole('link', { name: 'Kbd Test Org' })).toBeVisible()
  await expect(page.locator('.toast', { hasText: 'Organization created' })).toBeVisible()

  await page.getByRole('button', { name: 'Edit Kbd Test Org' }).click()
  await page.locator('#f-display_name').fill('Kbd Renamed')
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByRole('link', { name: 'Kbd Renamed' })).toBeVisible()

  await page.getByRole('button', { name: 'Delete Kbd Renamed' }).click()
  const confirm = page.getByRole('dialog', { name: 'Delete organization?' })
  await expect(confirm).toBeVisible()
  await expect(confirm).toContainText('Kbd Renamed')
  await expect(confirm.getByRole('button', { name: 'Delete organization' })).toBeDisabled() // must type the name
  await page.keyboard.press('Escape')
  await expect(confirm).toBeHidden()
  await expect(page.getByRole('link', { name: 'Kbd Renamed' })).toBeVisible()
  await page.getByRole('button', { name: 'Delete Kbd Renamed' }).click()
  await page.locator('#confirm-text').fill('kbdtest')
  await page.getByRole('button', { name: 'Delete organization' }).click()
  await expect(page.getByRole('link', { name: 'Kbd Renamed' })).toHaveCount(0)
})

test('client secret is shown once with a copy button; a public client\'s dialog has no secret', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await gotoRows(page, `${A}/tenants/customers/clients`)
  await page.getByRole('button', { name: 'New client' }).click()
  await page.locator('#f-name').fill('Secret test')
  await page.getByLabel('Redirect URI 1', { exact: true }).fill('https://x.example/cb')
  await page.getByRole('button', { name: 'Create client' }).click()
  const dlg = page.getByRole('dialog', { name: 'Client created' })
  await expect(dlg).toBeVisible()
  const secret = (await dlg.locator('#client-secret').innerText()).trim()
  expect(secret).toMatch(/^qsrs_/)
  await dlg.getByRole('button', { name: 'Copy client secret' }).click()
  await expect(page.locator('dialog[open] [data-live=polite]')).toContainText('Copied client secret')
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(secret)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await page.keyboard.press('Escape')
  // public client: no secret, no rotate button
  await page.getByRole('button', { name: 'New client' }).click()
  await page.locator('#f-name').fill('Public test')
  await page.locator('#f-token_endpoint_auth_method').selectOption('none')
  await expect(page.getByText('Client credentials')).toBeHidden()
  await page.getByLabel('Redirect URI 1', { exact: true }).fill('com.example.app:/callback')
  await page.getByRole('button', { name: 'Create client' }).click()
  await expect(page.getByRole('dialog', { name: 'Client created' }).locator('#client-secret')).toBeHidden()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('button', { name: 'Rotate secret of Public test' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Rotate secret of Secret test' })).toBeVisible()
})

test('tenant dialog: keyboard, provider checklist, org-disabled methods, delete rules', async ({ page }) => {
  await gotoRows(page, `${A}/tenants`)
  await expect(page.locator('a[aria-current="page"]')).toHaveText(/Tenants/)
  // each tenant is searched for first: other tests add tenants to the same server, which may push it past the first page
  const search = (q) => page.getByRole('searchbox', { name: 'Search tenants' }).fill(q)
  await search('Staff tools')
  // edit dialog opens focused on the first field, Tab stays inside, Esc returns focus to the opener
  const edit = page.getByRole('button', { name: 'Edit Staff tools' })
  await edit.focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'Edit sign-in rules' })
  await expect(dlg).toBeVisible()
  await expect(page.locator('#f-display_name')).toBeFocused()
  await expect(page.locator('#f-password_login')).not.toBeChecked()
  await expect(page.locator('#f-all_providers')).not.toBeChecked()
  await expect(dlg.getByRole('checkbox', { name: /Acme SSO/ })).toBeChecked()
  await expect(dlg.getByText('OpenID Connect, enabled').first()).toBeVisible()
  await expect(dlg.getByText('GitHub, disabled')).toBeVisible()
  for (let i = 0; i < 40; i++) {
    await page.keyboard.press('Tab')
    expect(await page.evaluate(() => !!document.activeElement.closest('dialog[open]'))).toBe(true)
  }
  // the provider checklist is replaced by the "all providers" switch
  await page.locator('#f-all_providers').check()
  await expect(dlg.getByRole('checkbox', { name: /Acme SSO/ })).toBeHidden()
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
  await expect(edit).toBeFocused()

  // create, with a validation error, then success
  await search('Kbd tenant')
  await page.getByRole('button', { name: 'New tenant' }).click()
  await expect(page.locator('#f-display_name')).toBeFocused()
  await page.locator('#f-display_name').fill('Kbd tenant')
  await page.locator('#f-tenant_name').fill('Bad Name')
  await page.getByRole('button', { name: 'Create tenant' }).click()
  await expect(page.locator('#e-tenant_name')).not.toBeEmpty()
  await expect(page.locator('#f-tenant_name')).toBeFocused()
  await page.locator('#f-tenant_name').fill('kbd-tenant')
  await page.locator('#f-require_mfa').check()
  await page.getByRole('button', { name: 'Create tenant' }).click()
  await expect(page.getByRole('row', { name: /kbd-tenant/ })).toContainText('Requires a second factor')
  await expect(page.getByRole('row', { name: /kbd-tenant/ })).toContainText('Password, Passkeys, All providers')

  // delete: the confirmation names the tenant
  await page.getByRole('button', { name: 'Delete Kbd tenant' }).click()
  const confirm = page.getByRole('dialog', { name: 'Delete tenant?' })
  await expect(confirm).toContainText('Kbd tenant')
  await confirm.getByRole('button', { name: 'Delete tenant' }).click()
  await expect(page.getByRole('row', { name: /kbd-tenant/ })).toHaveCount(0)

  // a tenant with clients cannot be deleted
  await search('Customer apps')
  await page.getByRole('button', { name: 'Delete Customer apps' }).click()
  await page.getByRole('dialog', { name: 'Delete tenant?' }).getByRole('button', { name: 'Delete tenant' }).click()
  await expect(page.locator('.toasts')).toContainText('still has clients')
  await expect(page.getByRole('row', { name: /customers/ })).toBeVisible()
})

test('clients: the tenant\'s clients page lists only its own clients, with the tenant preset in the new-client dialog', async ({ page }) => {
  await gotoRows(page, `${A}/tenants/staff/clients`)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Clients: Staff tools')
  await expect(page.getByRole('row', { name: /Internal tool 1/ })).toBeVisible()
  await expect(page.getByRole('row', { name: /Customer portal/ })).toHaveCount(0)
  await expect(page.getByRole('columnheader', { name: 'Tenant' })).toHaveCount(0)
  await page.getByRole('button', { name: 'New client' }).click()
  // creating: the tenant is preset and cannot be picked; moving is an edit-dialog field
  await expect(page.locator('#f-tenant_id')).toBeHidden()
  await page.getByRole('button', { name: 'Cancel' }).click()
  await page.getByRole('button', { name: 'Edit Internal tool 1' }).click()
  await expect(page.locator('#f-tenant_id option:checked')).toHaveText('Staff tools')
})

test('org methods turned off are disabled in the tenant dialog', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`, { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  await page.route('**/api/orgs/acme', async (route) => {
    const res = await route.fetch()
    const j = await res.json()
    j.settings.password_login = false
    await route.fulfill({ response: res, json: j })
  })
  await page.reload({ waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  await page.getByRole('button', { name: 'New tenant' }).click()
  await expect(page.locator('#f-password_login')).toBeDisabled()
  await expect(page.locator('#h-password_login')).toHaveText('Turned off for the organization')
  await expect(page.locator('#h-password_login')).toBeVisible()
  await expect(page.locator('#h-passkey_login')).toBeHidden()
  await expect(page.locator('#f-passkey_login')).toBeEnabled()
})

test('header is as wide as the page content and centred at every width', async ({ page }) => {
  await signIn(page, 'admin')
  for (const w of [320, 768, 1280, 1920, 2560]) {
    await page.setViewportSize({ width: w, height: 900 })
    await page.goto(`${A}/users`, { waitUntil: 'load' })
    const g = await page.evaluate(() => {
      const r = (s) => { const b = document.querySelector(s).getBoundingClientRect(); return [b.left, b.right] }
      return { header: r('.app-header'), body: r('.app-body'), nav: r('.app-nav'), main: r('.app-main'), vw: document.documentElement.clientWidth }
    })
    const left = g.nav[0] > 0 && g.nav[1] > 0 && g.nav[0] < g.main[0] ? g.nav[0] : g.main[0]
    expect(Math.abs(g.header[0] - left), `${w}px left edge`).toBeLessThanOrEqual(1)
    expect(Math.abs(g.header[1] - g.main[1]), `${w}px right edge`).toBeLessThanOrEqual(1)
    expect(Math.abs(g.header[0] - (g.vw - g.header[1])), `${w}px centred`).toBeLessThanOrEqual(1)
    expect(g.header[1] - g.header[0], `${w}px max width`).toBeLessThanOrEqual(92 * 16)
  }
})

test('manager sees only users; admin pages refuse with a styled 403', async ({ page }) => {
  await signIn(page, 'manager')
  await page.goto(`${A}/users`, { waitUntil: 'load' })
  await expect(page.getByRole('link', { name: 'Clients' })).toHaveCount(0)
  const res = await page.goto(`${A}/clients`)
  expect(res.status()).toBe(403)
  await expect(page.getByRole('heading', { name: 'Not allowed' })).toBeVisible()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('401 from the API redirects to sign-in', async ({ page, context }) => {
  await gotoRows(page, `${A}/users`)
  await context.clearCookies()
  await page.getByRole('searchbox', { name: 'Search users' }).fill('a')
  await page.waitForURL(/\/login\?next=/)
})

for (const path of ['/users', '/groups', '/tenants', '/tenants/staff', '/tenants/staff/clients', '/tenants/servers/ssh', '/providers', '/audit']) {
  test(`reflows at 320px without horizontal page scroll: ${path}`, async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 640 })
    await signIn(page, 'admin')
    await page.goto(A + path, { waitUntil: 'load' })
    await page.waitForTimeout(500)
    const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(over).toBeLessThanOrEqual(0)
    // the navigation is a drawer behind a menu button on small screens (nav-drawer.spec.mjs)
    const toggle = page.getByRole('button', { name: 'Open navigation menu' })
    await expect(toggle).toBeVisible()
    await toggle.click()
    await expect(page.getByRole('navigation', { name: 'Primary' })).toBeVisible()
    await expect(toggle).toHaveAttribute('aria-expanded', 'true')
    await expect(page.getByRole('button', { name: 'Close navigation menu' })).toBeFocused()
  })
}

test('400% zoom (320x256 CSS px) keeps dialogs usable', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 256 })
  await signIn(page, 'admin')
  await page.goto(`${A}/groups`, { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  await page.getByRole('button', { name: 'New group' }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg).toBeVisible()
  await dlg.getByRole('button', { name: 'Create group' }).scrollIntoViewIfNeeded()
  await expect(dlg.getByRole('button', { name: 'Create group' })).toBeInViewport()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)
})

test('reduced motion stops the aurora animation', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await gotoRows(page, `${A}/users`)
  expect(await page.locator('.aurora i').first().evaluate((el) => getComputedStyle(el).animationName)).toBe('none')
})

test('forced colours and high contrast render without losing structure', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active', contrast: 'more' })
  await gotoRows(page, `${A}/users`)
  await expect(page.locator('.aurora')).toBeHidden()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('prefers-contrast: more makes glass opaque; the reduced-transparency rule ships in the stylesheet', async ({ page }) => {
  await page.emulateMedia({ contrast: 'more' })
  await gotoRows(page, `${A}/users`)
  const bg = await page.locator('.app-nav').evaluate((el) => getComputedStyle(el).backgroundColor)
  expect(bg).not.toMatch(/rgba/) // fully opaque: rgb(...)
  // Chromium cannot emulate prefers-reduced-transparency yet: check the media rule is present instead.
  const has = await page.evaluate(() => [...document.styleSheets].some((ss) => [...ss.cssRules].some((r) => r.media && r.media.mediaText.includes('prefers-reduced-transparency'))))
  expect(has).toBe(true)
})

test('account: Create token asks for re-authentication, keeps focus in the dialogs and retries after success', async ({ page }) => {
  await signIn(page, 'user')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  // The server demands a re-authentication on the first attempt only; the re-auth call itself is stubbed (the demo
  // user's password is random), the retried token request goes through to the real server for the "after" state.
  let tokenCalls = 0
  await page.route('**/api-internal/account/tokens', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    tokenCalls++
    if (tokenCalls === 1) return route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'Confirm it is you with your password or a passkey first.', field: 'reauth' }) })
    return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ token: 'qsr_test_secret', item: { id: 'x', name: 'ci', scopes: ['api'], expires: null, last_used: null } }) })
  })
  let reauthPosts = 0
  await page.route('**/api-internal/account/reauth', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    reauthPosts++
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, valid_for: 300 }) })
  })

  const opener = page.locator('#tokens').getByRole('button', { name: 'New token' })
  await opener.focus()
  await page.keyboard.press('Enter')
  const tokenDlg = page.getByRole('dialog', { name: 'New API token' })
  await expect(tokenDlg).toBeVisible()
  await page.locator('#f-tk_name').fill('ci')
  const create = tokenDlg.getByRole('button', { name: 'Create token' })

  // 1. Esc on the re-authentication dialog gives up: focus returns to the control that was used, nothing is created.
  await create.focus()
  await page.keyboard.press('Enter')
  const reauth = page.getByRole('dialog', { name: 'Confirm it is you' })
  await expect(reauth).toBeVisible()
  await expect(page.locator('#f-ra_password')).toBeFocused()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press('Tab')
    expect(await page.evaluate(() => !!document.activeElement.closest('#reauth-dialog')), `tab ${i}`).toBe(true)
  }
  await page.keyboard.press('Escape')
  await expect(reauth).toBeHidden()
  await expect(tokenDlg).toBeVisible()
  await expect(create).toBeFocused()
  expect(reauthPosts).toBe(0)

  // 2. Confirming re-authenticates and retries the original action: the secret dialog opens.
  tokenCalls = 0
  await page.keyboard.press('Enter')
  await expect(reauth).toBeVisible()
  await page.locator('#f-ra_password').fill('whatever')
  await page.keyboard.press('Enter')
  await expect(reauth).toBeHidden()
  await expect.poll(() => tokenCalls).toBe(2)
  const secret = page.getByRole('dialog', { name: 'Your new token' })
  await expect(secret).toBeVisible()
  await expect(secret).toContainText('qsr_test_secret')
  expect(reauthPosts).toBe(1)
  await page.keyboard.press('Escape')
  await expect(secret).toBeHidden()
  const after = await axe(page)
  expect(after.violations.length, fmt(after.violations)).toBe(0)
})

test('new user dialog has no password; the email checkbox follows the email field; creating shows the invitation link', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await gotoRows(page, `${A}/users`)
  await page.getByRole('button', { name: 'New user' }).focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'New user' })
  await expect(dlg).toBeVisible()
  await expect(dlg.locator('input[type=password], #f-password')).toHaveCount(0)
  const box = dlg.getByLabel('Email the invitation')
  await expect(box).not.toBeChecked()
  const name = 'kbd' + Date.now()
  await page.locator('#f-email').fill(name + '@acme.example')
  await expect(box).toBeChecked()
  await page.locator('#f-email').fill('')
  await expect(box).not.toBeChecked()
  await page.keyboard.press('Shift+Tab')
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
  await expect(page.getByRole('button', { name: 'New user' })).toBeFocused()

  await page.getByRole('button', { name: 'New user' }).click()
  await page.locator('#f-email').fill(name + '@acme.example')
  await page.locator('#f-given_name').fill('Kbd')
  await page.keyboard.press('Enter')
  const inv = page.getByRole('dialog', { name: 'Invitation link' })
  await expect(inv).toBeVisible()
  const link = (await inv.locator('#invite-url').innerText()).trim()
  expect(link).toMatch(/\/invite\?token=/)
  await expect(inv.getByRole('button', { name: /Copy/ })).toBeFocused()
  await page.keyboard.press('Enter')
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link)
  // Tab stays inside the dialog
  for (let i = 0; i < 6; i++) { await page.keyboard.press('Tab'); expect(await page.evaluate(() => !!document.activeElement.closest('dialog[open]'))).toBe(true) }
  await page.keyboard.press('Escape')
  await expect(inv).toBeHidden()
  await page.getByRole('searchbox', { name: 'Search users' }).fill(name)
  const row = page.getByRole('row', { name: new RegExp(name) })
  await expect(row).toContainText('No password')
  // the list finds people; editing and deleting are on the user's page
  await expect(row.getByRole('button')).toHaveCount(0)
  await expect(row.getByRole('link', { name: 'Kbd' })).toBeVisible()
})

test('user page: sign-in section, remove password confirm and new invitation link dialog work from the keyboard', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await gotoRows(page, `${A}/users`)
  // a fresh user so the shared seed data stays as is
  const stamp = Date.now()
  const name = 'sign' + stamp + '@acme.example' // the username defaults to the email; the full name is first + last name
  const fullName = 'Sign ' + stamp
  await page.getByRole('button', { name: 'New user' }).click()
  await page.locator('#f-email').fill(name)
  await page.locator('#f-given_name').fill('Sign')
  await page.locator('#f-family_name').fill(String(stamp))
  await page.keyboard.press('Enter')
  // the invitation dialog after creating goes on to the new user's page
  await page.getByRole('dialog', { name: 'Invitation link' }).getByRole('link', { name: 'Open user' }).click()
  await expect(page.getByRole('heading', { name: fullName, level: 1 })).toBeVisible()
  await page.waitForSelector('text=Profile')
  const sec = page.getByRole('region', { name: 'Sign-in', exact: true })
  await expect(sec).toContainText('Not set')
  await expect(sec.getByRole('button', { name: 'Remove password' })).toHaveCount(0)

  // New invitation link: explanation first, then the generated link
  const gen = sec.getByRole('button', { name: 'New invitation link' })
  await gen.focus()
  await page.keyboard.press('Enter')
  const dlg = page.locator('#invite-dialog')
  await expect(dlg).toBeVisible()
  await expect(dlg).toContainText('earlier invitation link')
  await expect(dlg.getByRole('button', { name: 'Generate link' })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(dlg.locator('#invite-url')).toContainText('/invite?token=')
  await expect(dlg.getByRole('button', { name: /Copy/ })).toBeFocused()
  await expect(dlg.getByRole('button', { name: 'Send by email' })).toBeVisible() // every user has an email address
  await expect(dlg.getByRole('link', { name: 'Open user' })).toBeHidden() // already on their page
  await page.keyboard.press('Escape')
  await expect(gen).toBeFocused()

  // a user with a password: Remove password asks first; Escape / Cancel keeps it
  await page.goto(`${A}/users`, { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  await page.getByRole('link', { name: 'Alan Turing' }).click()
  await page.waitForSelector('text=Profile')
  const sec2 = page.getByRole('region', { name: 'Sign-in', exact: true })
  await expect(sec2).toContainText('Set')
  await sec2.getByRole('button', { name: 'Remove password' }).focus()
  await page.keyboard.press('Enter')
  const confirm = page.getByRole('dialog', { name: 'Remove password?' })
  await expect(confirm).toBeVisible()
  await expect(confirm).toContainText('until they accept a new invitation')
  await page.keyboard.press('Escape')
  await expect(confirm).toBeHidden()
  await expect(sec2.getByRole('button', { name: 'Remove password' })).toBeFocused()
  await expect(sec2).toContainText('Set')
})

test('the organization block links administrators to its overview; the organizations list is under System', async ({ page }) => {
  await gotoRows(page, `${A}/users`, 'admin')
  const org = page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: /Organization\s*Acme Corporation/ })
  await expect(org).toHaveAttribute('href', A)
  await org.focus()
  expect(await org.evaluate((el) => parseFloat(getComputedStyle(el).outlineWidth))).toBeGreaterThanOrEqual(2)
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(new RegExp(A + '$'))
  await expect(org).toHaveAttribute('aria-current', 'page')
  await expect(page.getByRole('link', { name: 'Organizations' })).toHaveCount(0)
  // a super admin also has the organizations list, first in System
  await gotoRows(page, `${A}/users`, 'super')
  const system = page.getByRole('navigation', { name: 'Primary' }).locator('.nav-group', { hasText: 'System' })
  await expect(system.getByRole('link').first()).toHaveAccessibleName('Organizations')
  await expect(system.getByRole('link').first()).toHaveAttribute('href', '/admin/orgs')
  // a manager gets a plain label: the overview is for administrators
  await gotoRows(page, `${A}/users`, 'manager')
  await expect(page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: /Acme Corporation/ })).toHaveCount(0)
  await expect(page.getByRole('navigation', { name: 'Primary' })).toContainText('Acme Corporation')
})

// ---- Account: compact security rows with their dialogs ------------------------------------------------------
import { accountStub } from './pages.mjs'

test('account: Change password opens from the keyboard, traps focus, closes with Esc and returns focus', async ({ page }) => {
  await signIn(page, 'user')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const opener = page.getByRole('button', { name: /Change… password/ })
  await expect(opener).toBeVisible()
  await expect(page.getByRole('button', { name: /Set up… Authenticator App/ })).toBeVisible()
  await opener.focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'Change password' })
  await expect(dlg).toBeVisible()
  await expect(page.locator('#f-pw_current')).toBeFocused()
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press('Tab')
    expect(await page.evaluate(() => !!document.activeElement.closest('#password-dialog')), `tab ${i}`).toBe(true)
  }
  // mismatching confirmation: inline error linked with aria-describedby, focus on the field
  await page.locator('#f-pw_current').fill('whatever')
  await page.locator('#f-pw_new').fill('a perfectly fine password')
  await page.locator('#f-pw_confirm').fill('something else entirely')
  await dlg.getByRole('button', { name: 'Change password' }).click()
  await expect(page.locator('#e-pw_confirm')).toHaveText('The two passwords do not match.')
  await expect(page.locator('#f-pw_confirm')).toBeFocused()
  expect(await page.locator('#f-pw_confirm').getAttribute('aria-describedby')).toContain('e-pw_confirm')
  // a wrong current password is refused inline by the server
  await page.locator('#f-pw_confirm').fill('a perfectly fine password')
  await dlg.getByRole('button', { name: 'Change password' }).click()
  await expect(page.locator('#e-pw_current')).toHaveText('That password is incorrect.')
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
  await expect(opener).toBeFocused()
})

test('account: a user without a password in an organization without passwords sees why, and no way to add one', async ({ page }) => {
  await signIn(page, 'user')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  await accountStub({ has_password: false, passwords_allowed: false })(page)
  await expect(page.getByText('Your organization does not sign people in with passwords.')).toBeVisible()
  await expect(page.getByRole('button', { name: /Change… password/ })).toBeHidden()
  await expect(page.getByRole('button', { name: 'Set a password…' })).toBeHidden()
})

test('account: a user without a password can set one: the dialog asks for no current password and returns focus', async ({ page }) => {
  await signIn(page, 'user')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  await accountStub({ has_password: false, passwords_allowed: true })(page)
  await expect(page.getByText('You sign in without a password. You can add one as another way to sign in.')).toBeVisible()
  const opener = page.getByRole('button', { name: 'Set a password…' })
  await opener.focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'Set a password' })
  await expect(dlg).toBeVisible()
  await expect(page.locator('#f-pw_current')).toBeHidden()
  await expect(page.locator('#f-pw_new')).toBeFocused()
  await expect(dlg.getByRole('button', { name: 'Set password' })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
  await expect(opener).toBeFocused()
})

test('account: Authenticator App set-up dialog opens, shows the key, closes with Esc and returns focus', async ({ page }) => {
  await signIn(page, 'user')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const opener = page.getByRole('button', { name: /Set up… Authenticator App/ })
  await opener.focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'Set up Authenticator App' })
  await expect(dlg).toBeVisible()
  await expect(dlg.getByRole('img', { name: /QR code/ })).toBeVisible()
  await expect(dlg.locator('#totp-secret')).not.toBeEmpty()
  await expect(page.locator('#f-totp_code')).toBeFocused()
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press('Tab')
    expect(await page.evaluate(() => !!document.activeElement.closest('#totp-dialog')), `tab ${i}`).toBe(true)
  }
  await page.locator('#f-totp_code').fill('000000')
  await dlg.getByRole('button', { name: 'Turn on' }).click()
  await expect(dlg.locator('.toasts').getByText(/That code is incorrect/)).toBeVisible()
  await expect(page.locator('#f-totp_code')).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
  await expect(opener).toBeFocused()
})

test('account: Remove Authenticator App asks to confirm; Esc cancels and returns focus', async ({ page }) => {
  await signIn(page, 'user')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  await accountStub({ totp: true })(page)
  await expect(page.getByText('On', { exact: true }).first()).toBeVisible()
  const opener = page.getByRole('button', { name: /Remove… Authenticator App/ })
  await opener.focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'Remove Authenticator App' })
  await expect(dlg).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
  await expect(opener).toBeFocused()
})

// ---- tag editor ----------------------------------------------------------------------------------------------
const tagTexts = (dlg) => dlg.locator('.tag-chip-text').allTextContents()

test('tag editor: add with Enter, comma and space; Backspace removes the last; chips have named remove buttons', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  await page.getByRole('button', { name: 'New user' }).click()
  const dlg = page.getByRole('dialog', { name: 'New user' })
  const input = dlg.getByRole('textbox', { name: 'Tags' })
  await expect(input).toBeVisible()
  await input.focus()
  await page.keyboard.type('dept:finance')
  await page.keyboard.press('Enter')
  await page.keyboard.type('Vip,')
  await page.keyboard.type('x/y_z ')
  await page.keyboard.type('Dept:Finance') // case is kept, so this is a different tag
  await page.keyboard.press('Enter')
  expect(await tagTexts(dlg)).toEqual(['dept:finance', 'Vip', 'x/y_z', 'Dept:Finance'])
  await expect(input).toBeFocused()
  await expect(input).toHaveValue('')
  await expect(dlg.getByRole('button', { name: 'Remove tag dept:finance', exact: true })).toBeVisible()
  // a duplicate is not added twice
  await page.keyboard.type('Vip,')
  expect((await tagTexts(dlg)).length).toBe(4)
  // Backspace on the empty input removes the last chip; with text it only edits the text
  await page.keyboard.press('Backspace')
  expect(await tagTexts(dlg)).toEqual(['dept:finance', 'Vip', 'x/y_z'])
  await page.keyboard.type('ab')
  await page.keyboard.press('Backspace')
  expect((await tagTexts(dlg)).length).toBe(3)
  await expect(input).toHaveValue('a')
  await page.keyboard.press('Backspace')
  await page.keyboard.press('Backspace')
  expect(await tagTexts(dlg)).toEqual(['dept:finance', 'Vip'])
  // the remove button works from the keyboard and returns focus to the input
  const rm = dlg.getByRole('button', { name: 'Remove tag dept:finance', exact: true })
  await rm.focus()
  await page.keyboard.press('Enter')
  expect(await tagTexts(dlg)).toEqual(['Vip'])
  await expect(input).toBeFocused()
  // Tab order: input -> next field (chips' remove buttons come before the input)
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
})

test('tag editor: invalid tags show an inline error, nothing is added, the text stays for correction', async ({ page }) => {
  await gotoRows(page, `${A}/groups`)
  await page.getByRole('button', { name: 'New group' }).click()
  const dlg = page.getByRole('dialog', { name: 'New group' })
  const input = dlg.getByRole('textbox', { name: 'Tags' })
  await input.focus()
  await page.keyboard.type('-nope')
  await page.keyboard.press('Enter')
  await expect(dlg.locator('#e-tags')).toContainText('“-nope” is not a valid tag: use letters, digits and . _ : / -')
  await expect(input).toHaveAttribute('aria-invalid', 'true')
  await expect(input).toHaveAttribute('aria-describedby', /e-tags/)
  expect(await tagTexts(dlg)).toEqual([])
  await expect(input).toHaveValue('-nope')
  await input.fill('fixed')
  await expect(dlg.locator('#e-tags')).toBeEmpty()
  await page.keyboard.press('Enter')
  expect(await tagTexts(dlg)).toEqual(['fixed'])
})

test('tag editor: saving keeps typed-but-uncommitted text, the server validates, and tags show in the table', async ({ page }) => {
  await gotoRows(page, `${A}/groups`)
  const name = 'Tagged' + Date.now()
  await page.getByRole('button', { name: 'New group' }).click()
  const dlg = page.getByRole('dialog', { name: 'New group' })
  await dlg.getByLabel('Group name').fill(name)
  await dlg.getByRole('textbox', { name: 'Tags' }).fill('team:z')
  await page.keyboard.press('Enter')
  await dlg.getByRole('textbox', { name: 'Tags' }).fill('last-word') // not committed with a key
  await dlg.getByRole('button', { name: 'Create group' }).click()
  await expect(dlg).toBeHidden()
  const row = page.getByRole('row', { name: new RegExp(name) })
  await expect(row.getByRole('list', { name: 'Tags' }).getByRole('listitem')).toHaveText(['last-word', 'team:z'])
})

test('users: clicking a tag badge filters the list by it; Clear removes the filter', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  const total = await page.locator('tbody tr').count()
  const badge = page.getByRole('button', { name: 'Show users tagged vip' }).first()
  await badge.focus()
  await page.keyboard.press('Enter')
  const clear = page.getByRole('button', { name: 'Clear tag filter vip' })
  await expect(clear).toBeVisible()
  await expect(clear).toBeFocused()
  await expect(page.locator('tbody tr')).toHaveCount(1)
  await expect(page).toHaveURL(/tag=vip/)
  await page.keyboard.press('Enter')
  await expect(page.getByRole('button', { name: 'Clear tag filter vip' })).toBeHidden()
  await expect(page.locator('tbody tr')).toHaveCount(total)
  // a shared link opens already filtered
  await page.goto(`${A}/users?tag=vip`, { waitUntil: 'load' })
  await expect(page.locator('tbody tr')).toHaveCount(1)
})

test('tags can be edited in the user dialog and saved', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  const id = 'tagedit' + Date.now().toString(36)
  await page.getByRole('button', { name: 'New user' }).click()
  const dlg = page.getByRole('dialog', { name: 'New user' })
  await dlg.locator('#f-email').fill(id + '@acme.example')
  await dlg.getByLabel('First name').fill('Tag')
  await dlg.getByLabel('Last name').fill(id)
  await dlg.getByLabel('Email the invitation').uncheck()
  await dlg.getByRole('textbox', { name: 'Tags' }).fill('b-tag,a-tag ')
  await dlg.getByRole('button', { name: 'Create user' }).click()
  await page.getByRole('dialog', { name: 'Invitation link' }).waitFor()
  await page.keyboard.press('Escape')
  await page.getByRole('searchbox', { name: 'Search users' }).fill(id) // the search finds users by family name
  const row = page.getByRole('row', { name: new RegExp('Tag ' + id) })
  await expect(row).toBeVisible()
  await expect(row.getByRole('button', { name: /Show users tagged/ })).toHaveText(['a-tag', 'b-tag'])
  await row.getByRole('link', { name: 'Tag ' + id }).click()
  await page.getByRole('button', { name: 'Edit user' }).click()
  const edit = page.getByRole('dialog', { name: 'Edit user' })
  expect(await tagTexts(edit)).toEqual(['b-tag', 'a-tag'].sort())
})

// ---- Email addresses ------------------------------------------------------------------------------------------

test('admin user page: add and remove an email address from the keyboard', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  await page.getByRole('link', { name: 'Alan Turing' }).click()
  const list = page.getByRole('list', { name: 'Email addresses' })
  await list.waitFor()
  const add = page.getByRole('button', { name: 'Add email' })
  await expect(page.getByText('Sign-ins from GitHub, Google and other providers that use one of these verified addresses find this user.')).toBeVisible()
  await expect(list.getByRole('listitem').first()).toContainText('Primary')

  // Add email opens a dialog with focus in the input; Esc cancels and returns focus to the button
  await add.focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'Add email address' })
  await expect(dlg).toBeVisible()
  const input = page.locator('#f-em_address')
  await expect(input).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(dlg).toBeHidden()
  await expect(add).toBeFocused()

  // an invalid address: the error is linked to the input and announced, nothing is added
  await page.keyboard.press('Enter')
  await input.fill('nope')
  await page.keyboard.press('Enter')
  await expect(page.locator('#e-em_address')).not.toBeEmpty()
  await expect(input).toHaveAttribute('aria-invalid', 'true')
  await expect(input).toBeFocused()

  // a good one: Enter submits, the row appears (unverified: the demo has email on, so the user is mailed a link,
  // which can be sent again) and focus returns
  const address = 'kbd' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6) + '@the7thdream.example'
  await input.fill(address)
  await page.keyboard.press('Enter')
  const row = list.getByRole('listitem').filter({ hasText: address })
  await expect(row).toBeVisible()
  await expect(row).toContainText('Unverified')
  await expect(row.getByRole('button', { name: 'Resend link for ' + address })).toBeVisible()
  await expect(dlg).toBeHidden()
  await expect(add).toBeFocused()

  // Remove asks first; Esc cancels and returns focus to the delete button
  const remove = page.getByRole('button', { name: 'Remove ' + address })
  await remove.focus()
  await page.keyboard.press('Enter')
  const confirm = page.getByRole('dialog', { name: 'Remove email address' })
  await expect(confirm).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(confirm).toBeHidden()
  await expect(remove).toBeFocused()
  await page.keyboard.press('Enter')
  await confirm.getByRole('button', { name: 'Remove address' }).click()
  await expect(row).toHaveCount(0)
  await expect(add).toBeFocused()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('account: below manager, addresses are set by a manager: read-only, verify, resend and make primary only', async ({ page }) => {
  await signIn(page, 'user')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  const list = page.getByRole('list', { name: 'Email addresses' })
  await list.waitFor()
  await expect(page.locator('#f-email-ro')).toHaveAttribute('readonly', '')
  await expect(page.locator('#f-email')).toBeHidden()
  await expect(page.getByText('Your administrator adds and removes these.', { exact: false })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Add email' })).toBeHidden()
  await expect(list.getByRole('button', { name: /^Remove / })).toHaveCount(0)
  await expect(list.getByRole('button', { name: 'Make primary for alan.turing@bletchley.example' })).toBeVisible()
  await expect(list.getByRole('button', { name: 'Resend link for alan@the7thdream.example' })).toBeVisible()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('account: managers too: the address is read-only and there is no Add email', async ({ page }) => {
  await signIn(page, 'manager')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  await page.locator('#f-email-ro').waitFor()
  await expect(page.locator('#f-email-ro')).toHaveAttribute('readonly', '')
  await expect(page.locator('#f-email')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Add email' })).toBeHidden()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('admin user page: your own page manages your addresses after confirming it is you, and lists your sessions and connections', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  await page.getByRole('link', { name: 'Ada Lovelace' }).click()
  await page.getByRole('heading', { name: 'Profile' }).waitFor()
  await expect(page.getByText('Your own addresses: changes ask you to confirm it is you', { exact: false })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible()
  await expect(page.getByRole('table', { name: 'Sessions of this user' }).locator('.badge:visible', { hasText: 'This session' })).toHaveCount(1)
  await expect(page.getByRole('heading', { name: 'Connected apps' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Sign-in providers' })).toBeVisible()
  // adding an address: the server asks to re-authenticate first, the shared dialog opens, then it is added unverified
  const address = 'ada' + Date.now().toString(36) + '@the7thdream.example'
  let posts = 0
  await page.route('**/emails', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    posts++
    if (posts === 1) return route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'Confirm it is you with your password or a passkey first.', field: 'reauth' }) })
    return route.fallback()
  })
  await page.route('**/api-internal/account/reauth', async (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, valid_for: 300 }) })
  })
  const add = page.getByRole('button', { name: 'Add email' })
  await add.click()
  await page.locator('#f-em_address').fill(address)
  await page.keyboard.press('Enter')
  const reauth = page.getByRole('dialog', { name: 'Confirm it is you' })
  await expect(reauth).toBeVisible()
  await reauth.locator('#f-ra_password').fill('stubbed')
  await page.keyboard.press('Enter')
  const row = page.getByRole('list', { name: 'Email addresses' }).getByRole('listitem').filter({ hasText: address })
  await expect(row).toContainText('Unverified', { timeout: 5000 })
  // the edit dialog keeps your primary address fixed (add one, verify it, make it primary)
  await page.getByRole('button', { name: 'Edit user' }).click()
  const dlg = page.getByRole('dialog', { name: 'Edit user' })
  await expect(dlg.locator('#f-email-self')).toHaveAttribute('readonly', '')
  await page.keyboard.press('Escape')
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('admin user page: remove a connected app and disconnect a provider from the keyboard', async ({ page }) => {
  await gotoRows(page, `${A}/users`)
  await page.getByRole('link', { name: 'Alan Turing' }).click()
  const apps = page.getByRole('table', { name: 'Applications this user connected' })
  await expect(apps.getByRole('row', { name: /Mobile app/ })).toBeVisible()
  // Remove asks first; Esc cancels and returns focus; confirming removes the row and focuses the card heading
  const remove = page.getByRole('button', { name: 'Remove access for Mobile app' })
  await remove.focus()
  await page.keyboard.press('Enter')
  const confirm = page.getByRole('dialog', { name: 'Remove access?' })
  await expect(confirm).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(confirm).toBeHidden()
  await expect(remove).toBeFocused()
  await page.keyboard.press('Enter')
  await confirm.getByRole('button', { name: 'Remove access' }).click()
  await expect(apps.getByRole('row', { name: /Mobile app/ })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Connected apps' })).toBeFocused()
  // the provider: the dialog explains what happens; cancelling keeps it (other tests use it)
  const providers = page.getByRole('list', { name: 'Sign-in providers connected to this user' })
  await expect(providers).toContainText('Acme SSO')
  await expect(providers).toContainText('alan@acme.example')
  await providers.getByRole('button', { name: 'Disconnect Acme SSO' }).click()
  const dc = page.getByRole('dialog', { name: 'Disconnect provider?' })
  await expect(dc).toContainText('send them a new invitation link')
  await page.keyboard.press('Escape')
  await expect(dc).toBeHidden()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

// The language and time zone autocompleters: type to filter, Down/Up move, Enter chooses, Escape closes the list
// without closing the dialog; the chosen value is what is saved.
test('autocomplete fields', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme/users', { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  await page.getByRole('link', { name: 'Alan Turing' }).first().click()
  await page.getByRole('button', { name: 'Edit user' }).click()
  const lang = page.locator('#f-locale')
  await lang.fill('english (u')
  await expect(page.getByRole('listbox', { name: 'Language' })).toBeVisible()
  await page.keyboard.press('ArrowDown')
  await expect(lang).toHaveAttribute('aria-activedescendant', /combo-locale-0/)
  await page.keyboard.press('ArrowDown')
  await page.keyboard.press('Enter')
  await expect(lang).toHaveValue(/English \(United (Kingdom|States)\)/)
  await expect(page.getByRole('listbox', { name: 'Language' })).toBeHidden()
  // Escape closes only the list
  await lang.fill('fren')
  await expect(page.getByRole('listbox', { name: 'Language' })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('listbox', { name: 'Language' })).toBeHidden()
  await expect(page.getByRole('dialog')).toBeVisible()
  // choose a time zone with the mouse and save
  await lang.fill('')
  await page.locator('#f-zoneinfo').fill('tokyo')
  await page.getByRole('option', { name: /Asia\/Tokyo/ }).click()
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByRole('dialog')).toBeHidden()
  const u = await page.evaluate(async () => {
    const r = await fetch('/api/orgs/acme/users?q=alan', { headers: { 'X-CSRF-Token': document.querySelector('meta[name=csrf-token]').content } })
    return (await r.json()).items.find((x) => x.username === 'alan')
  })
  expect(u.zoneinfo).toBe('Asia/Tokyo')
  expect(u.locale || '').toBe('')
})

test('account page: the time zone list is drawn over the cards below it', async ({ page }) => {
  await page.setViewportSize({ width: 1360, height: 1400 })
  await signIn(page, 'user')
  await page.goto('/o/acme/account', { waitUntil: 'load' })
  await page.locator('#f-zoneinfo').fill('e')
  await expect(page.getByRole('listbox', { name: 'Time zone' })).toBeVisible()
  const r = await page.evaluate(() => {
    const l = document.getElementById('l-zoneinfo').getBoundingClientRect(), e = document.getElementById('emails').getBoundingClientRect()
    const el = document.elementFromPoint(l.left + 20, Math.max(l.top, e.top) + 10)
    return { overlap: l.bottom > e.top, onTop: !!el?.closest('#l-zoneinfo') }
  })
  expect(r.overlap).toBe(true)
  expect(r.onTop).toBe(true)
})
