// Skins: a super admin views a built-in skin, copies it into a custom one (its selectors made to style any skin), is
// refused a stylesheet styling another skin, previews it; an organization's administrator chooses it on the branding
// card and its pages (console and sign-in) wear it; removed, the organization falls back to the primary
// organization's. Only super admins have the skins page.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt } from './helpers.mjs'

const API = '/api/orgs/acme'

async function cleanUp(page) {
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  await apiCall(page, 'PATCH', `${API}/branding`, { skin: '' })
  await apiCall(page, 'PATCH', '/api/orgs/primary/branding', { skin: '' })
  const l = await apiCall(page, 'GET', '/api/skins')
  for (const k of l.items) if (!k.builtin) await apiCall(page, 'DELETE', `/api/skins/${k.name}`)
}

test.describe.configure({ mode: 'serial' })

test('a super admin copies a built-in skin into a custom one, and an organization wears it', async ({ page, browser }) => {
  await cleanUp(page)
  try {
    await page.goto('/admin/skins', { waitUntil: 'load' })
    await expect(page.getByRole('link', { name: 'Skins' })).toHaveAttribute('aria-current', 'page')
    const row = page.getByRole('row', { name: /Matte/ })
    await expect(row.getByText('Built-in')).toBeVisible()
    await expect(row.getByRole('button', { name: 'Remove Matte' })).toBeHidden()

    // Default (no skin) is listed and can be copied: its design tokens
    const dflt = page.getByRole('row', { name: /Default/ })
    await expect(dflt.getByText('Built-in')).toBeVisible()
    await dflt.getByRole('button', { name: 'View Default', exact: true }).click()
    const dd = page.getByRole('dialog', { name: 'Default' })
    await expect(dd.locator('.ace_content')).toContainText(':root[data-skin]')
    await expect(dd.getByText('These are its design tokens')).toBeVisible()
    await dd.getByRole('button', { name: 'Close', exact: true }).click()
    await page.getByRole('button', { name: 'New skin' }).click()
    const fresh = page.getByRole('dialog', { name: 'New skin' })
    await expect(fresh.getByLabel('Start from').locator('option')).toHaveText(['A blank skin', 'Default', 'Matte'])
    await fresh.getByLabel('Start from').selectOption('default')
    await expect(fresh.locator('.ace_content')).toContainText('--page-bg')
    await fresh.getByRole('button', { name: 'Cancel' }).click()

    // a built-in skin: viewed, not changed, copied
    await row.getByRole('button', { name: 'View Matte', exact: true }).click()
    const dlg = page.getByRole('dialog', { name: 'Matte' })
    await expect(dlg).toBeVisible()
    await expect(dlg.locator('.ace_content')).toContainText('data-skin="matte"')
    // the stylesheet can be searched (Ctrl+F / ⌘F)
    await page.locator('#f-css').focus()
    await page.keyboard.press('ControlOrMeta+f')
    await expect(dlg.locator('.ace_search')).toBeVisible()
    await page.keyboard.type('accent')
    await expect(dlg.locator('.ace_search_counter')).toHaveText(/^1 of \d+$/)
    await page.keyboard.press('Escape')
    await expect(dlg.locator('.ace_search')).toBeHidden()
    await expect(dlg.getByRole('button', { name: 'Save skin' })).toBeHidden()
    await dlg.getByRole('button', { name: 'Copy to a new skin' }).click()
    const make = page.getByRole('dialog', { name: 'New skin' })
    await expect(make.getByLabel('Name', { exact: true })).toHaveValue('matte-copy')
    await expect(make.locator('.ace_content')).not.toContainText('data-skin="matte"')
    await expect(make.locator('.ace_content')).toContainText(':root[data-skin]')
    await make.getByLabel('Name', { exact: true }).fill('ocean')
    await make.getByLabel('Display name').fill('Ocean')
    let r = await axe(page, { include: '#skin-dialog' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    await make.getByRole('button', { name: 'Add skin' }).click()
    await expect(page.getByText('Skin “Ocean” added.')).toBeVisible()
    const ocean = page.getByRole('row', { name: /Ocean/ })
    await expect(ocean.getByText('Custom')).toBeVisible()

    // a stylesheet styling another skin is refused, under the editor
    await ocean.getByRole('button', { name: 'Edit Ocean' }).click()
    const edit = page.getByRole('dialog', { name: 'Edit Ocean' })
    await expect(edit.getByLabel('Name', { exact: true })).toBeDisabled()
    await page.locator('#f-css').focus()
    await page.keyboard.press('ControlOrMeta+a')
    await page.keyboard.insertText(':root[data-skin="matte"] { --accent-solid: #0e7490; }')
    await edit.getByRole('button', { name: 'Save skin' }).click()
    await expect(edit.locator('#e-css')).toContainText('style another skin')
    await expect(page.locator('#f-css')).toHaveAttribute('aria-invalid', 'true')
    await page.keyboard.press('ControlOrMeta+a')
    await page.keyboard.insertText(':root[data-skin] { --accent-solid: #0e7490; }')
    await edit.getByRole('button', { name: 'Save skin' }).click()
    await expect(page.getByText('Skin “Ocean” saved.')).toBeVisible()

    // the preview, in a dialog: the sign-in page (shown although signed in), then this page, in the skin
    await ocean.getByRole('button', { name: 'Preview Ocean', exact: true }).click()
    const pv = page.getByRole('dialog', { name: 'Preview: Ocean' })
    await expect(pv).toBeVisible()
    await expect(pv.locator('iframe')).toHaveAttribute('src', /\/login\?skin=ocean$/)
    let frame = page.frameLocator('#skin-preview iframe')
    await expect(frame.locator('html')).toHaveAttribute('data-skin', 'ocean')
    await expect(frame.getByRole('button', { name: /Continue|Sign in/ }).first()).toBeVisible()
    r = await axe(page, { include: '#skin-preview .dialog-panel', exclude: '#skin-preview iframe' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    await pv.getByRole('tab', { name: 'This page' }).click()
    await expect(pv.locator('iframe')).toHaveAttribute('src', '/admin/skins?skin=ocean')
    await expect(frame.getByRole('heading', { name: 'Skins', level: 1 })).toBeVisible()
    await expect(frame.locator('link[href^="/branding/skins/ocean.css?v="]')).toHaveCount(1)
    await pv.getByRole('button', { name: 'Close', exact: true }).click()
    await expect(pv).toBeHidden()

    // the organization's administrator chooses it
    await signIn(page, 'admin')
    await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
    await expect(page.locator('html')).not.toHaveAttribute('data-skin', /.*/)
    const card = page.getByRole('region', { name: 'Branding' })
    const pick = card.getByLabel('Skin')
    await expect(pick.locator('option')).toHaveText(['Same as the primary organization', 'Default', 'Matte', 'Ocean (custom)'])
    await pick.selectOption('ocean')
    await card.getByRole('button', { name: 'Preview' }).click()
    const cpv = page.getByRole('dialog', { name: 'Preview: Ocean (custom)' })
    await expect(cpv.locator('iframe')).toHaveAttribute('src', '/o/acme/login?skin=ocean')
    await expect(page.frameLocator('#skin-preview iframe').locator('html')).toHaveAttribute('data-skin', 'ocean')
    await cpv.getByRole('button', { name: 'Close', exact: true }).click()
    await card.getByRole('button', { name: 'Save branding' }).click()
    await expect(page.getByText('Branding saved.')).toBeVisible()
    await page.reload({ waitUntil: 'load' })
    await expect(page.locator('html')).toHaveAttribute('data-skin', 'ocean')
    await expect(card.getByLabel('Skin')).toHaveValue('ocean')
    const anon = await browser.newPage({ ignoreHTTPSErrors: true })
    await anon.goto('/o/acme/login', { waitUntil: 'load' })
    await expect(anon.locator('html')).toHaveAttribute('data-skin', 'ocean')

    // removed: the organization shows the primary organization's (here Matte)
    await signIn(page, 'super')
    await page.goto('/admin/orgs', { waitUntil: 'load' })
    await apiCall(page, 'PATCH', '/api/orgs/primary/branding', { skin: 'matte' })
    await page.goto('/admin/skins', { waitUntil: 'load' })
    await page.getByRole('button', { name: 'Remove Ocean' }).click()
    await page.getByRole('dialog', { name: 'Remove the skin?' }).getByRole('button', { name: 'Remove skin' }).click()
    await expect(page.getByText('Skin “Ocean” removed.')).toBeVisible()
    await anon.reload({ waitUntil: 'load' })
    await expect(anon.locator('html')).toHaveAttribute('data-skin', 'matte')
    await anon.close()
  } finally {
    await cleanUp(page)
  }
})

test('only super admins have the skins page', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
  await expect(page.getByRole('link', { name: 'Skins' })).toHaveCount(0)
  const res = await page.goto('/admin/skins')
  expect(res.status()).toBe(404)
})
