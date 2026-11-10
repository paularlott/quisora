// The email templates page: an administrator edits the layout and an email's subject and bodies in tabs, sees which
// tabs are customized and which unsaved, previews an email (HTML in a sandboxed frame with its inline styles, and the
// plain text), gets a template the server refuses shown under its editor, puts one tab's default back, saves one tab
// at a time, and sends a test of a tab's email from a dialog. Managers have no such page.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt } from './helpers.mjs'

const PAGE = '/admin/orgs/acme/emails'
const API = '/api/orgs/acme/email-templates'

const reset = (page) => apiCall(page, 'PUT', API, {})

// typeInEditor replaces the text of the Ace editor of a field (#f-html, #f-text is its input).
async function typeInEditor(page, id, text) {
  await page.locator(id).focus()
  await page.keyboard.press('ControlOrMeta+a')
  await page.keyboard.press('Delete')
  await page.keyboard.insertText(text)
}

test.describe.configure({ mode: 'serial' })

test('an admin edits, previews, saves and tests the email templates', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto('/healthz')
  await page.goto(PAGE, { waitUntil: 'load' })
  try {
    await reset(page)
    await page.reload({ waitUntil: 'load' })
    await expect(page.getByRole('link', { name: 'Emails' })).toHaveAttribute('aria-current', 'page')
    const layoutTab = page.getByRole('tab', { name: 'Layout' })
    await expect(layoutTab).toHaveAttribute('aria-selected', 'true')
    await expect(page.locator('.ace_editor')).toHaveCount(2)
    await expect(page.locator('.et-head .badge')).toHaveText('Default')
    const save = page.locator('#et-panel button[type="submit"]')
    await expect(save).toHaveText('Save layout')
    await expect(save).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Use the default layout' })).toBeDisabled()
    await expect(page.getByText('Template fields')).toBeVisible()
    // the inherited layout is in the editors
    await expect(page.locator('[x-ref="html"] .ace_content')).toContainText('{{template "body" .}}')

    let r = await axe(page)
    expect(r.violations.length, fmt(r.violations)).toBe(0)

    // the reset email's subject: the tab is marked customized and Save comes on
    await page.getByRole('tab', { name: 'Password reset' }).click()
    await expect(page.getByLabel('Subject')).toHaveValue('Reset your {{.Site}} password')
    await page.getByLabel('Subject').fill('{{.Org}}: choose a new password')
    await expect(page.getByRole('tab', { name: /^Password reset\s*\(customized\)\s*\(unsaved\)$/ })).toBeVisible()
    await expect(page.locator('.et-head .badge')).toHaveText('Customized')
    await expect(page.locator('.et-unsaved .badge-warning')).toHaveText('Unsaved changes')
    await expect(save).toHaveText('Save password reset')
    await expect(save).toBeEnabled()

    // the layout's HTML gets a banner in the organization's colour
    await layoutTab.click()
    await page.locator('#f-html').focus()
    await page.keyboard.press('ControlOrMeta+Home')
    await page.keyboard.insertText('<div style="background:{{.PrimaryColor}};color:#fff;padding:8px">Banner {{.Org}}</div>\n')
    await expect(page.getByRole('tab', { name: /^Layout\s*\(customized\)\s*\(unsaved\)$/ })).toBeVisible()
    // the fields are listed as they are written
    await page.getByText('Template fields').click()
    await expect(page.locator('.kv-fields dt').first()).toHaveText('{{.Site}}')
    await expect(page.locator('.kv-fields dt').first()).toHaveCSS('text-transform', 'none')

    // the layout tab previews the layout around the invitation
    await page.getByRole('button', { name: 'Preview layout' }).click()
    let dlg = page.getByRole('dialog', { name: 'Preview: Layout, with the invitation' })
    await expect(dlg).toBeVisible()
    await expect(page.frameLocator('iframe.email-frame').getByText('Banner Acme Corporation')).toBeVisible()
    await dlg.getByRole('button', { name: 'Close', exact: true }).click()
    await expect(dlg).toBeHidden()

    // a preview of the unsaved templates: HTML in the frame, with its inline styles, and the text
    await page.getByRole('tab', { name: /^Password reset/ }).click()
    await page.getByRole('button', { name: 'Preview password reset' }).click()
    dlg = page.getByRole('dialog', { name: 'Preview: Password reset' })
    await expect(dlg).toBeVisible()
    await expect(dlg.getByText('Acme Corporation: choose a new password')).toBeVisible()
    const frame = page.frameLocator('iframe.email-frame')
    await expect(frame.getByText('Banner Acme Corporation')).toBeVisible()
    await expect(frame.getByText('Hello Alex Example,')).toBeVisible()
    await expect(frame.getByRole('link', { name: 'Reset password' })).toHaveCSS('background-color', 'rgb(55, 48, 163)')
    r = await axe(page, { include: '#email-preview' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    await expect(dlg.locator('pre.email-text')).toBeHidden()
    await dlg.getByRole('tab', { name: 'Plain text' }).click()
    await expect(page.locator('iframe.email-frame')).toBeHidden()
    await expect(dlg.locator('pre.email-text')).toContainText('Hello Alex Example,')
    await expect(dlg.locator('pre.email-text')).toContainText('/reset?token=preview')
    await dlg.getByRole('button', { name: 'Close', exact: true }).click()
    await expect(dlg).toBeHidden()

    // an invitation without its link is refused: the error is shown under the editor at fault
    await page.getByRole('tab', { name: 'Invitation' }).click()
    await typeInEditor(page, '#f-html', '<p>Welcome aboard</p>')
    await expect(save).toHaveText('Save invitation')
    await save.click()
    await expect(page.locator('#e-html')).toHaveText('must show the link: {{.Link}}')
    await expect(page.locator('#f-html')).toHaveAttribute('aria-invalid', 'true')
    // this tab's default comes back, and no other tab's, after a confirmation that can be cancelled
    await page.getByRole('button', { name: 'Use the default invitation' }).click()
    const confirm = page.getByRole('dialog', { name: 'Use the default invitation?' })
    await expect(confirm).toBeVisible()
    await confirm.getByRole('button', { name: 'Cancel' }).click()
    await expect(confirm).toBeHidden()
    await expect(page.locator('.et-head .badge')).toHaveText('Customized')
    await page.getByRole('button', { name: 'Use the default invitation' }).click()
    await confirm.getByRole('button', { name: 'Use the default', exact: true }).click()
    await expect(page.getByText('The default invitation is in the editors.')).toBeVisible()
    await expect(page.locator('.et-head .badge')).toHaveText('Default')
    await expect(page.getByRole('tab', { name: 'Invitation', exact: true })).toBeVisible()
    await expect(save).toBeDisabled()
    await expect(page.getByRole('tab', { name: /^Layout\s*\(customized\)\s*\(unsaved\)$/ })).toBeVisible()

    // saving the reset email saves only it: the layout stays unsaved
    await page.getByRole('tab', { name: /^Password reset/ }).click()
    await save.click()
    await expect(page.getByText('Password reset saved.')).toBeVisible()
    await expect(save).toBeDisabled()
    await expect(page.getByRole('tab', { name: /^Password reset\s*\(customized\)$/ })).toBeVisible()
    let v = await apiCall(page, 'GET', API)
    expect(v.own.emails.reset).toEqual({ subject: '{{.Org}}: choose a new password', html: '', text: '' })
    expect(v.own.layout_html).toBe('')
    await layoutTab.click()
    await save.click()
    await expect(page.getByText('Layout saved.')).toBeVisible()
    v = await apiCall(page, 'GET', API)
    expect(v.own.layout_html).toContain('Banner {{.Org}}')
    expect(v.own.emails.reset.subject).toBe('{{.Org}}: choose a new password')
    expect(v.own.emails.invite).toBeUndefined()

    // the default for a saved tab is put in the editors; saving the tab removes its own, and keeps every other tab
    await page.getByRole('tab', { name: /^Password reset/ }).click()
    await page.getByRole('button', { name: 'Use the default password reset' }).click()
    const confirmReset = page.getByRole('dialog', { name: 'Use the default password reset?' })
    await expect(confirmReset.getByText("The default is the primary organization's, else the built-in one.")).toBeVisible()
    await expect(confirmReset.getByText('Your subject, HTML and plain text in the editors will be replaced. Save the tab to keep it.')).toBeVisible()
    await confirmReset.getByRole('button', { name: 'Use the default', exact: true }).click()
    await expect(page.getByLabel('Subject')).toHaveValue('Reset your {{.Site}} password')
    await expect(page.locator('.et-unsaved .badge-warning')).toHaveText('Unsaved changes')
    v = await apiCall(page, 'GET', API)
    expect(v.own.emails.reset.subject).toBe('{{.Org}}: choose a new password')
    await save.click()
    await expect(page.getByText('Password reset saved.')).toBeVisible()
    v = await apiCall(page, 'GET', API)
    expect((v.own.emails || {}).reset).toBeUndefined()
    expect(v.own.layout_html).toContain('Banner {{.Org}}')

    // a test email of the tab's email, to an address given in a dialog
    await page.getByRole('tab', { name: 'Sign-in code' }).click()
    await page.getByRole('button', { name: 'Send test' }).click()
    const send = page.getByRole('dialog', { name: 'Send a test email' })
    await expect(send).toBeVisible()
    await expect(send.getByText('The sign-in code, from the templates')).toBeVisible()
    await expect(send.getByLabel('Send to')).toBeFocused()
    r = await axe(page, { include: '#email-test' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    await send.getByLabel('Send to').fill('not an address')
    await send.getByRole('button', { name: 'Send', exact: true }).click()
    await expect(send.locator('#e-to')).toContainText('enter an email address')
    await send.getByLabel('Send to').fill('pat@example.com')
    const req = page.waitForRequest((q) => q.url().endsWith('/email-templates/test'))
    await send.getByRole('button', { name: 'Send', exact: true }).click()
    expect((await req).postDataJSON()).toMatchObject({ email: 'code', to: 'pat@example.com' })
    await expect(page.getByText('Test email queued for pat@example.com.')).toBeVisible()
    await expect(send).toBeHidden()
    await expect(page.getByRole('button', { name: 'Send test' })).toBeFocused()
  } finally {
    await reset(page)
  }
})

// The preview frame runs script (its own), so it must not leave the email: a page it moved to would run in the
// console's dialog. Neither the email's meta refresh nor a click on one of its links moves it.
test('the email preview stays on the email', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(PAGE, { waitUntil: 'load' })
  await page.getByRole('tab', { name: 'Password reset' }).click()
  await typeInEditor(page, '#f-html', '<meta http-equiv="refresh" content="0;url=/healthz">' +
    '<p><a href="{{.Link}}">Reset now</a> <a href="/healthz">Elsewhere</a></p>')
  await page.getByRole('button', { name: 'Preview password reset' }).click()
  const dlg = page.getByRole('dialog', { name: 'Preview: Password reset' })
  const frame = page.frameLocator('iframe.email-frame')
  await expect(frame.getByRole('link', { name: 'Reset now' })).toBeVisible()
  await page.waitForTimeout(1000) // a refresh would have moved the frame by now
  await frame.getByRole('link', { name: 'Elsewhere' }).click()
  await page.waitForTimeout(500)
  await expect(frame.getByRole('link', { name: 'Reset now' })).toBeVisible()
  expect(page.frames().map((f) => new URL(f.url()).pathname)).not.toContain('/healthz')
  await dlg.getByRole('button', { name: 'Close', exact: true }).click()
})

test('managers have no email templates page', async ({ page }) => {
  await signIn(page, 'manager')
  await page.goto('/admin/orgs/acme/users', { waitUntil: 'load' })
  await expect(page.getByRole('link', { name: 'Emails' })).toHaveCount(0)
  const res = await page.goto(PAGE)
  expect(res.status()).toBe(403)
})
