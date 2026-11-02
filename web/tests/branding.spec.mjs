// Branding card of the organization overview: an administrator sets a logo (and a dark one) and the primary colour, sees
// them previewed and saved, gets the server's refusal of a colour too light for white text and the size check of a
// logo before anything is sent, and removes a logo; managers do not see the card.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'
const CARD = 'section[aria-labelledby="brand-h"]' // the whole page is audited by a11y.spec.mjs

// a 1x1 PNG, and a small SVG
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64')
const SVG = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40"><rect width="120" height="40" fill="#fff"/></svg>')
const png = { name: 'logo.png', mimeType: 'image/png', buffer: PNG }
const svg = { name: 'logo-dark.svg', mimeType: 'image/svg+xml', buffer: SVG }

const reset = (page) => apiCall(page, 'PATCH', `${API}/branding`, { logo_light: '', logo_dark: '', primary_color: '' })

test.describe.configure({ mode: 'serial' })

test('an admin saves a logo, a dark logo and a colour, and removes them again', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(A, { waitUntil: 'load' })
  const card = page.getByRole('region', { name: 'Branding' })
  try {
    await reset(page)
    await page.reload({ waitUntil: 'load' })
    await expect(card).toBeVisible()
    await expect(card.getByText('None: the server’s logo is shown.')).toBeVisible()
    await expect(card.getByText('Add a logo first.')).toBeVisible()
    await expect(card.locator('#f-logo_dark')).toBeDisabled()
    await expect(card.getByRole('button', { name: 'Remove light logo' })).toBeDisabled()
    const save = card.getByRole('button', { name: 'Save branding' })
    await expect(save).toBeDisabled()

    // choose the logo and a colour: previewed before anything is saved
    await card.getByLabel('Logo (light theme)').setInputFiles(png)
    await expect(card.getByAltText('Preview of the light logo')).toBeVisible()
    await expect(card.getByText('Chosen: it is saved when you save.')).toBeVisible()
    await expect(card.locator('#f-logo_dark')).toBeEnabled()
    await expect(card.getByText('None: the light logo is shown in the dark theme.')).toBeVisible()
    await expect(card.getByRole('button', { name: 'Remove dark logo' })).toBeDisabled()
    await card.locator('#f-primary_color').fill('#1d4ed8')
    await expect(card.locator('#f-primary_color_picker')).toHaveValue('#1d4ed8')
    await card.locator('#f-primary_color_picker').fill('#065f46') // the picker writes the text field
    await expect(card.locator('#f-primary_color')).toHaveValue('#065f46')
    await card.locator('#f-logo_dark').setInputFiles(svg)
    await expect(card.getByAltText('Preview of the dark logo')).toBeVisible()
    await expect(card.getByRole('button', { name: 'Remove dark logo' })).toBeEnabled()
    let r = await axe(page, { include: CARD })
    expect(r.violations.length, fmt(r.violations)).toBe(0)

    await save.click()
    await expect(page.getByText('Branding saved.')).toBeVisible()
    const b = (await apiCall(page, 'GET', API)).branding
    expect(b.primary_color).toBe('#065f46')
    expect(b.logo_light).toMatch(/\/branding\/logo-light\?v=/)
    expect(b.logo_dark).toMatch(/\/branding\/logo-dark\?v=/)
    await expect(card.getByAltText('Preview of the light logo')).toHaveAttribute('src', b.logo_light)
    await expect(card.getByAltText('Preview of the dark logo')).toHaveAttribute('src', b.logo_dark)
    await expect(card.locator('#f-primary_color')).toHaveValue('#065f46')
    await expect(card.getByText('Chosen: it is saved when you save.')).toHaveCount(0)
    await expect(save).toBeDisabled()
    expect((await card.getByAltText('Preview of the light logo').evaluate((i) => i.complete && i.naturalWidth))).toBeGreaterThan(0)

    // it is still there after a reload
    await page.reload({ waitUntil: 'load' })
    await expect(card.getByAltText('Preview of the light logo')).toHaveAttribute('src', b.logo_light)
    await expect(card.locator('#f-primary_color')).toHaveValue('#065f46')

    // the dark logo alone removed: the light one stays
    await card.getByRole('button', { name: 'Remove dark logo' }).click()
    await card.getByRole('button', { name: 'Save branding' }).click()
    await expect(card.getByText('None: the light logo is shown in the dark theme.')).toBeVisible()
    const light = (await apiCall(page, 'GET', API)).branding
    expect(light.logo_light).toBeTruthy()
    expect(light.logo_dark).toBeUndefined()
    await expect(card.getByText('None: the light logo is shown in the dark theme.')).toBeVisible()
    await expect(card.getByRole('button', { name: 'Remove dark logo' })).toBeDisabled()

    // the server's colour again, and the logo removed (a dark logo would go with it)
    await card.getByRole('button', { name: "Use the server's colour" }).click()
    await expect(card.locator('#f-primary_color')).toBeFocused()
    await expect(card.locator('#f-primary_color')).toHaveValue('')
    await card.getByRole('button', { name: 'Remove light logo' }).click()
    await expect(card.getByText('It is removed when you save.')).toBeVisible()
    await expect(card.getByText('None: the server’s logo is shown.')).toBeVisible()
    await expect(card.locator('#f-logo_dark')).toBeDisabled()
    await save.click()
    await expect(page.getByText('Branding saved.')).toBeVisible()
    const none = (await apiCall(page, 'GET', API)).branding
    expect(none.primary_color).toBe('')
    expect(none.logo_light).toBeUndefined()
    expect(none.logo_dark).toBeUndefined()
  } finally {
    await reset(page)
  }
})

test('a colour too light for white text, and a logo over 256 KB, show their errors on the field', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(A, { waitUntil: 'load' })
  const card = page.getByRole('region', { name: 'Branding' })
  await card.locator('#f-primary_color').fill('#fde047')
  await card.locator('#f-primary_color').press('Enter') // saved from the keyboard
  const err = card.locator('#e-primary_color')
  await expect(err).not.toBeEmpty()
  await expect(card.locator('#f-primary_color')).toHaveAttribute('aria-invalid', 'true')
  await expect(card.locator('#f-primary_color')).toBeFocused()
  await expect(card.locator('#f-primary_color')).toHaveAttribute('aria-describedby', /e-primary_color/)
  expect((await apiCall(page, 'GET', API)).branding.primary_color).toBe('')
  let r = await axe(page, { include: CARD })
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  await card.locator('#f-primary_color').fill('')
  await card.getByLabel('Logo (light theme)').setInputFiles({ name: 'big.png', mimeType: 'image/png', buffer: Buffer.alloc(300 * 1024) })
  await expect(card.locator('#e-logo_light')).toContainText('256 KB')
  await expect(card.getByAltText('Preview of the light logo')).toBeHidden()
  await expect(card.getByRole('button', { name: 'Save branding' })).toBeDisabled()
  r = await axe(page, { include: CARD })
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('a manager is not shown the branding card, and cannot change the branding', async ({ page }) => {
  await signIn(page, 'manager')
  await page.goto(A, { waitUntil: 'load' })
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Users') // the overview is not for managers: they land on the users
  await expect(page.getByRole('heading', { name: 'Branding' })).toHaveCount(0)
  await expect(page.locator('#f-logo_light')).toHaveCount(0)
  await expect(apiCall(page, 'PATCH', `${API}/branding`, { primary_color: '#1d4ed8' })).rejects.toThrow(/403/)
})

// The organization dialog of the organizations list (super admins) has the same fields: an edit saves the branding
// after the settings, and a new organization sends its branding with it.
test('the organization dialog sets the branding when editing and creating', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  try {
    await reset(page)
    await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
    let dlg = page.getByRole('dialog', { name: 'Edit organization' })
    await expect(dlg.getByText('None: the server’s logo is shown.')).toBeVisible()
    await dlg.locator('#f-primary_color').fill('#fde047') // too light: refused on the field, the dialog stays
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg.locator('#e-primary_color')).not.toBeEmpty()
    await expect(dlg).toBeVisible()
    await dlg.locator('#f-primary_color').fill('#065f46')
    await dlg.getByLabel('Logo (light theme)').setInputFiles(png)
    await expect(dlg.getByAltText('Preview of the light logo')).toBeVisible()
    let r = await axe(page, { include: '#org-dialog' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg).toBeHidden()
    const b = (await apiCall(page, 'GET', API)).branding
    expect(b.primary_color).toBe('#065f46')
    expect(b.logo_light).toMatch(/\/branding\/logo-light\?v=/)

    // opened again, it shows what is saved
    await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
    dlg = page.getByRole('dialog', { name: 'Edit organization' })
    await expect(dlg.getByAltText('Preview of the light logo')).toHaveAttribute('src', b.logo_light)
    await expect(dlg.locator('#f-primary_color')).toHaveValue('#065f46')
    await page.keyboard.press('Escape')

    // a new organization: the branding goes with the creation (answered here, so nothing is made)
    let sent = null
    await page.route('**/api/orgs', (route) => {
      if (route.request().method() !== 'POST') return route.fallback()
      sent = route.request().postDataJSON()
      return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 'x', name: 'branded', settings: {}, branding: {} }) })
    })
    await page.getByRole('button', { name: 'New organization' }).click()
    dlg = page.getByRole('dialog', { name: 'New organization' })
    await expect(dlg.locator('#f-logo_dark')).toBeDisabled()
    await dlg.getByLabel('URL name').fill('branded')
    await dlg.getByLabel('Logo (light theme)').setInputFiles(svg)
    await dlg.locator('#f-primary_color').fill('#1d4ed8')
    await dlg.getByRole('button', { name: 'Create organization' }).click()
    await expect(dlg).toBeHidden()
    expect(sent.branding.primary_color).toBe('#1d4ed8')
    expect(sent.branding.logo_light).toMatch(/^data:image\/svg\+xml;base64,/)
    expect(sent.branding.logo_dark).toBeUndefined()
  } finally {
    await reset(page)
  }
})
