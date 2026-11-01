// Authorization details (RFC 9396): the client dialog's types and its own tokens' details, and the access dialog's
// details, edited in an Ace JSON editor (lib/detailsfield.js): completion, the checker's problems in the gutter and
// under the editor, errors refused before anything is sent, the keyboard exit, no Content-Security-Policy violations,
// and axe.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, uniq, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'
const TYPE = 'urn:example:admin'

async function freshTenant(page, clientTypes) {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`, { waitUntil: 'load' })
  const slug = uniq('ad')
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'Details ' + slug, settings: { members_only: true } })
  const portal = await apiCall(page, 'POST', `${API}/clients`, { name: 'Portal', tenant_id: t.id, redirect_uris: ['https://portal.example/cb'],
    ...(clientTypes ? { authorization_details_types: clientTypes } : {}) })
  return { slug, id: t.id, portal }
}

// Collect Content-Security-Policy violations (Ace must inject no styles and start no workers).
function cspWatch(page) {
  const seen = []
  page.on('console', (m) => { if (/Content.Security.Policy|Refused to/i.test(m.text())) seen.push(m.text()) })
  return seen
}

const editorOf = (page) => page.locator('#f-authorization_details')
const editorText = (page) => page.evaluate(() => document.getElementById('f-authorization_details').closest('.ace_editor').env.editor.getValue())

// setText replaces the editor's text as a paste would (no auto-closed brackets).
async function setText(page, text) {
  await editorOf(page).focus()
  await page.keyboard.press('ControlOrMeta+A')
  if (text) await page.keyboard.insertText(text)
  else await page.keyboard.press('Delete')
}

test('client dialog: types, and its own tokens’ details in the editor, checked as typed and on save', async ({ page }) => {
  const csp = cspWatch(page)
  const t = await freshTenant(page)
  await page.goto(`${A}/tenants/${t.slug}/clients`, { waitUntil: 'load' })
  await page.getByRole('button', { name: 'Edit Portal' }).click()
  const dlg = page.getByRole('dialog', { name: 'Edit client' })
  await expect(dlg).toBeVisible()
  const field = dlg.locator('[data-name="authorization_details"]')
  // only for an application that acts as itself
  await expect(field).toBeHidden()
  await dlg.getByRole('checkbox', { name: /^Client credentials/ }).check()
  await expect(field.locator('.ace_editor')).toBeVisible()
  // the editor's input is the labelled, described control
  const input = editorOf(page)
  await expect(input).toHaveAccessibleName('Authorization details of its own tokens')
  await expect(input).toHaveAttribute('aria-describedby', /h-authorization_details p-authorization_details e-authorization_details/)

  // a type the application does not list: a warning in the gutter and under the editor, gone once it is listed
  await setText(page, `[{"type": "${TYPE}", "actions": ["read"]}]`)
  const problems = page.locator('#p-authorization_details')
  await expect(problems).toContainText(`Line 1: “${TYPE}” is not one of the application’s authorization details types`)
  await expect(field.locator('.ace_gutter .ace_warning').first()).toBeVisible()
  await dlg.getByRole('button', { name: 'Add type' }).click()
  await dlg.getByRole('textbox', { name: 'Authorization details type 1' }).fill(TYPE)
  await expect(problems).toBeHidden()

  // not JSON: refused here with the line, nothing sent; the editor is invalid and has the focus
  await setText(page, `[\n  {"type": "${TYPE}",}\n]`)
  await expect(problems).toContainText('Line 2: Remove the comma before “}”.')
  await expect(field.locator('.ace_gutter .ace_error').first()).toBeVisible()
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.locator('#e-authorization_details')).toHaveText('Line 2: Remove the comma before “}”.')
  await expect(input).toHaveAttribute('aria-invalid', 'true')
  await expect(input).toBeFocused()
  await expect(field.locator('.details-editor')).toHaveAttribute('data-invalid', 'true')
  let r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  // valid: saved compact and shown indented again
  await setText(page, `[{"type": "${TYPE}", "actions": ["write"], "tenants": ["acme"]}]`)
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(dlg).toBeHidden()
  const saved = await apiCall(page, 'GET', `${API}/clients/${t.portal.id}`)
  expect(saved.authorization_details_types).toEqual([TYPE])
  expect(saved.authorization_details).toEqual([{ type: TYPE, actions: ['write'], tenants: ['acme'] }])
  await page.getByRole('button', { name: 'Edit Portal' }).click()
  await expect(dlg.getByRole('textbox', { name: 'Authorization details type 1' })).toHaveValue(TYPE)
  await expect.poll(() => editorText(page)).toBe(JSON.stringify(saved.authorization_details, null, 2))
  expect(csp).toEqual([])
})

test('access dialog: completion of fields, types and placeholders; the limits; the keyboard exit', async ({ page }) => {
  const csp = cspWatch(page)
  const t = await freshTenant(page, [TYPE])
  const alan = (await apiCall(page, 'GET', `${API}/users?q=alan`)).items.find((u) => u.username === 'alan')
  await apiCall(page, 'POST', `${API}/tenants/${t.id}/access`, { subject_type: 'user', subject_id: alan.id,
    authorization_details: [{ type: TYPE, actions: ['read'], tenants: ['{{tenant}}'] }] })
  await page.goto(`${A}/tenants/${t.slug}`, { waitUntil: 'load' })
  await page.getByRole('button', { name: 'Edit access for Alan Turing' }).click()
  const dlg = page.getByRole('dialog', { name: 'Edit access' })
  await expect(dlg).toBeVisible()
  await expect.poll(() => editorText(page)).toContain('"{{tenant}}"')
  await expect(editorOf(page)).toHaveAccessibleName('Authorization details')

  // typed from empty (at a person's pace: Ace updates its suggestions as typing pauses): the editor closes brackets
  // and quotes; completion offers the fields, then the types
  const type = (text) => page.keyboard.type(text, { delay: 60 })
  await setText(page, '')
  await type('[{"ty')
  const popup = page.locator('.ace_autocomplete')
  await expect(popup).toBeVisible()
  await expect(popup).toContainText('type')
  await page.keyboard.press('Enter')
  await expect.poll(() => editorText(page)).toBe('[{"type": }]')
  await type('"urn:ex')
  await expect(popup).toContainText(TYPE)
  await page.keyboard.press('Enter')
  await expect.poll(() => editorText(page)).toBe(`[{"type": "${TYPE}"}]`)
  // a placeholder inside a string
  await page.keyboard.press('End')
  await page.keyboard.press('ArrowLeft')
  await page.keyboard.press('ArrowLeft')
  await type(', "identifier": "u-{{s')
  await expect(popup).toContainText('{{sub}}')
  await page.keyboard.press('Enter')
  await expect.poll(() => editorText(page)).toBe(`[{"type": "${TYPE}", "identifier": "u-{{sub}}"}]`)
  await expect(page.locator('#p-authorization_details')).toBeHidden()

  // Escape, then Tab, leaves the editor (Tab alone indents); the dialog stays open
  await page.keyboard.press('Escape')
  await page.keyboard.press('Tab')
  await expect(editorOf(page)).not.toBeFocused()
  await expect(dlg).toBeVisible()

  // the server's size limit is checked as typed
  await setText(page, `[{"type": "${TYPE}", "x": "${'y'.repeat(9000)}"}]`)
  await expect(page.locator('#p-authorization_details')).toContainText('limited to 8192 bytes')
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  // emptied: removed
  await setText(page, '')
  await dlg.getByRole('button', { name: 'Save changes' }).click()
  await expect(dlg).toBeHidden()
  const list = await apiCall(page, 'GET', `${API}/tenants/${t.id}/access`)
  expect(list.items[0].authorization_details).toBeUndefined()
  expect(csp).toEqual([])
})
