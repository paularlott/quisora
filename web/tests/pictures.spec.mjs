// Profile pictures: choosing, replacing and removing your own on the account page (the client refuses a wrong file before
// sending, the server's refusal shows at the field), an organization that leaves pictures to its administrators, an
// administrator setting and removing another user's on the user page, and avatars (the picture, else initials) in the
// lists and the header's account menu.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt, uniq } from './helpers.mjs'

const API = '/api/orgs/acme'
const ACCOUNT = '/o/acme/account'

test.describe.configure({ mode: 'serial' })

// A small square PNG of one colour, made in the page (the images need no fixture files).
async function png(page, color) {
  const url = await page.evaluate((c) => {
    const cv = document.createElement('canvas')
    cv.width = cv.height = 64
    const g = cv.getContext('2d')
    g.fillStyle = c
    g.fillRect(0, 0, 64, 64)
    return cv.toDataURL('image/png')
  }, color)
  return { name: 'avatar.png', mimeType: 'image/png', buffer: Buffer.from(url.split(',')[1], 'base64') }
}

// Katherine's own picture, through the account API (to start from none, and to leave none).
async function clearOwn(page) {
  await apiCall(page, 'DELETE', ACCOUNT.replace('/account', '') + '/api-internal/account/picture').catch(() => {})
}

async function imageType(page, url) {
  return page.evaluate(async (u) => { const r = await fetch(u); return r.ok ? r.headers.get('content-type') : String(r.status) }, url)
}

test('account: upload a picture, replace it, remove it after confirming', async ({ page }) => {
  await signIn(page, 'otp') // Katherine Johnson: a plain user with no picture
  await page.goto(ACCOUNT, { waitUntil: 'load' })
  await clearOwn(page)
  await page.reload({ waitUntil: 'load' })
  const card = page.locator('#picture')
  try {
    // no picture: initials, in the card and in the header's account menu
    await expect(card.locator('.avatar')).toHaveText('KJ')
    await expect(card.locator('.avatar-img')).toBeHidden()
    await expect(page.locator('.user-chip .avatar')).toHaveText('KJ')
    await expect(card.getByRole('button', { name: 'Remove picture' })).toBeHidden()

    await card.locator('#f-image-file').setInputFiles(await png(page, '#be123c'))
    await expect(page.getByText('Picture saved.')).toBeVisible()
    const img = card.locator('.avatar-img')
    await expect(img).toBeVisible()
    const first = await img.getAttribute('src')
    expect(first).toMatch(/\/o\/[^/]+\/pictures\/[A-Za-z0-9]+$/)
    expect(await imageType(page, first)).toMatch(/^image\/(png|jpeg)/)
    // the avatar is decoration: no text alternative, hidden from assistive technology
    await expect(card.locator('.avatar')).toHaveAttribute('aria-hidden', 'true')
    await expect(img).toHaveAttribute('alt', '')
    // the header follows without a reload
    await expect(page.locator('.user-chip .avatar-img')).toHaveAttribute('src', first)
    await expect(card.getByRole('button', { name: 'Remove picture' })).toBeVisible()

    // replace: a new picture has a new address
    await card.locator('#f-image-file').setInputFiles(await png(page, '#1d4ed8'))
    await expect(img).not.toHaveAttribute('src', first)
    const second = await img.getAttribute('src')
    expect(await imageType(page, second)).toMatch(/^image\//)
    await page.reload({ waitUntil: 'load' })
    await expect(card.locator('.avatar-img')).toHaveAttribute('src', second)

    // remove: asks first; Cancel keeps it
    await card.getByRole('button', { name: 'Remove picture' }).click()
    const dlg = page.getByRole('dialog', { name: 'Remove picture' })
    await expect(dlg).toBeVisible()
    const r = await axe(page, { include: '#confirm-dialog' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    await dlg.getByRole('button', { name: 'Cancel' }).click()
    await expect(dlg).toBeHidden()
    await expect(card.locator('.avatar-img')).toBeVisible()
    await card.getByRole('button', { name: 'Remove picture' }).click()
    await dlg.getByRole('button', { name: 'Remove picture' }).click()
    await expect(dlg).toBeHidden()
    await expect(page.getByText('Picture removed.')).toBeVisible()
    await expect(card.locator('.avatar')).toHaveText('KJ')
    await expect(page.locator('.user-chip .avatar')).toHaveText('KJ')
    await expect(card.locator('#f-image')).toBeFocused() // back to the picture
    expect(await imageType(page, second)).toBe('404')
  } finally { await clearOwn(page) }
})

// Clicking the picture opens the same file chooser as the input (a shortcut for the mouse); the input stays the one
// control, so the picture is neither focusable nor announced.
test('account: clicking the picture opens the file chooser, and the chosen file is saved', async ({ page }) => {
  await signIn(page, 'otp')
  await page.goto(ACCOUNT, { waitUntil: 'load' })
  await clearOwn(page)
  await page.reload({ waitUntil: 'load' })
  const card = page.locator('#picture')
  try {
    const pick = card.getByRole('button', { name: 'Upload a picture' })
    await expect(pick).toHaveAttribute('id', 'f-image')
    await expect(card.locator('.picture-pick-hint')).toHaveAttribute('aria-hidden', 'true')
    await expect(card.locator('#f-image-file')).toBeHidden() // no bar: the picture is the control
    const [chooser] = await Promise.all([page.waitForEvent('filechooser'), pick.click()])
    expect(await chooser.element().getAttribute('id')).toBe('f-image-file')
    await chooser.setFiles(await png(page, '#0f766e'))
    await expect(page.getByText('Picture saved.')).toBeVisible()
    await expect(card.locator('.avatar-img')).toBeVisible()
    // once there is one, the picture's button says so; the card's controls are it and Remove picture
    await expect(card.getByRole('button', { name: 'Change picture' })).toBeVisible()
    await expect(card.getByRole('button')).toHaveCount(2)
    // the keyboard reaches it and opens the chooser with Enter
    await card.getByRole('button', { name: 'Change picture' }).focus()
    const [again] = await Promise.all([page.waitForEvent('filechooser'), page.keyboard.press('Enter')])
    expect(await again.element().getAttribute('id')).toBe('f-image-file')
  } finally {
    await clearOwn(page)
  }
})

test('account: a picture changed elsewhere shows when the page comes back', async ({ page, context }) => {
  await signIn(page, 'otp')
  await page.goto(ACCOUNT, { waitUntil: 'load' })
  await clearOwn(page)
  await page.reload({ waitUntil: 'load' })
  const card = page.locator('#picture')
  try {
    await expect(card.locator('.avatar')).toHaveText('KJ')
    // another tab of the same person sets it
    const other = await context.newPage()
    await other.goto(ACCOUNT, { waitUntil: 'load' })
    await other.locator('#picture').locator('#f-image-file').setInputFiles(await png(other, '#15803d'))
    await expect(other.locator('#picture .avatar-img')).toBeVisible()
    await other.close()
    // this tab comes back to the foreground (more than 5 s after it loaded, as the page waits)
    await page.waitForTimeout(5200)
    await page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' }); document.dispatchEvent(new Event('visibilitychange')); window.dispatchEvent(new Event('focus')) })
    await expect(card.locator('.avatar-img')).toBeVisible({ timeout: 10_000 })
  } finally { await clearOwn(page) }
})

test('account: a wrong type or a file over 5 MB is refused before it is sent', async ({ page }) => {
  await signIn(page, 'otp')
  await page.goto(ACCOUNT, { waitUntil: 'load' })
  const card = page.locator('#picture')
  await expect(card.locator('.avatar')).toBeVisible()
  const puts = []
  page.on('request', (r) => { if (r.method() === 'PUT' && r.url().endsWith('/picture')) puts.push(r.url()) })
  const input = card.locator('#f-image-file')

  await input.setInputFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('hello') })
  await expect(card.locator('#e-image')).toHaveText('Use a JPEG, PNG or WebP image.')
  await expect(card.locator('#f-image')).toHaveAttribute('aria-invalid', 'true')
  await expect(card.locator('#f-image')).toBeFocused()
  await expect(card.locator('#f-image-file')).toHaveValue('') // the refused file is not kept

  await input.setInputFiles({ name: 'big.png', mimeType: 'image/png', buffer: Buffer.alloc(5 * 1024 * 1024 + 1) })
  await expect(card.locator('#e-image')).toHaveText('The image is larger than 5 MB.')
  const r = await axe(page, { include: '#picture' })
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  expect(puts).toEqual([])
})

test('account: the server\'s refusal of an image is shown at the field and announced', async ({ page }) => {
  await signIn(page, 'otp')
  await page.goto(ACCOUNT, { waitUntil: 'load' })
  const card = page.locator('#picture')
  await expect(card.locator('.avatar')).toBeVisible()
  await card.locator('#f-image-file').setInputFiles({ name: 'broken.png', mimeType: 'image/png', buffer: Buffer.from('not really an image') })
  await expect(card.locator('#e-image')).toHaveText(/\S/)
  await expect(card.locator('#f-image')).toHaveAttribute('aria-invalid', 'true')
  await expect(card.locator('#f-image')).toBeFocused()
  await expect(page.locator('#live-assertive')).toHaveText(/\S/)
  await expect(card.locator('.avatar')).toHaveText('KJ') // nothing changed
  // a stubbed 422 with its own message
  await page.route('**/api-internal/account/picture', (route) => route.request().method() === 'PUT'
    ? route.fulfill({ status: 422, contentType: 'application/json', body: JSON.stringify({ error: 'The image could not be read.', field: 'image' }) }) : route.fallback())
  await card.locator('#f-image-file').setInputFiles(await png(page, '#7e22ce'))
  await expect(card.locator('#e-image')).toHaveText('The image could not be read.')
  // a limit reached is not about the field: an error toast
  await page.unroute('**/api-internal/account/picture')
  await page.route('**/api-internal/account/picture', (route) => route.request().method() === 'PUT'
    ? route.fulfill({ status: 429, contentType: 'application/json', body: JSON.stringify({ error: 'The picture was changed too often; try again in an hour.' }) }) : route.fallback())
  await card.locator('#f-image-file').setInputFiles(await png(page, '#7e22ce'))
  await expect(page.locator('.toast-error')).toContainText('changed too often')
})

test('user page: an administrator sets, replaces and removes another user\'s picture', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto(`${API.replace('/api', '/admin')}/users`, { waitUntil: 'load' })
  const id = uniq('pic')
  const u = await apiCall(page, 'POST', `${API}/users`, { username: id, email: id + '@acme.example', given_name: 'Pia', family_name: 'Picture' })
  try {
    await page.goto(`/admin/orgs/acme/users/${u.id}`, { waitUntil: 'load' })
    const card = page.getByRole('region', { name: 'Picture' })
    const head = page.locator('.page-head .avatar')
    await expect(head).toHaveText('PP')
    await expect(card.locator('.avatar')).toHaveText('PP')
    await card.locator('#f-image-file').setInputFiles(await png(page, '#0f766e'))
    await expect(page.getByText('Picture saved.')).toBeVisible()
    await expect(head.locator('.avatar-img')).toBeVisible()
    const url = await head.locator('.avatar-img').getAttribute('src')
    expect(await imageType(page, url)).toMatch(/^image\//)
    expect((await apiCall(page, 'GET', `${API}/users/${u.id}`)).picture).toBe(url)

    // the users list shows it beside the name
    await page.goto('/admin/orgs/acme/users', { waitUntil: 'load' })
    await page.locator('#list-search').fill(id)
    const row = page.getByRole('row', { name: new RegExp(id) })
    await expect(row.locator('.avatar-img')).toHaveAttribute('src', url)
    await expect(row.locator('.avatar-img')).toHaveAttribute('loading', 'lazy')

    // replace, then remove after confirming
    await page.goto(`/admin/orgs/acme/users/${u.id}`, { waitUntil: 'load' })
    await card.locator('#f-image-file').setInputFiles(await png(page, '#b45309'))
    await expect(head.locator('.avatar-img')).not.toHaveAttribute('src', url)
    const r = await axe(page, { include: '#main' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    await card.getByRole('button', { name: 'Remove picture' }).click()
    const dlg = page.getByRole('dialog', { name: 'Remove picture' })
    await expect(dlg.getByText('Remove the picture of Pia Picture?')).toBeVisible()
    await dlg.getByRole('button', { name: 'Remove picture' }).click()
    await expect(page.getByText('Picture removed.')).toBeVisible()
    await expect(head).toHaveText('PP')
    expect((await apiCall(page, 'GET', `${API}/users/${u.id}`)).picture).toBeUndefined()
    await expect(card.getByRole('button', { name: 'Remove picture' })).toBeHidden()

    // a wrong file is refused here too
    await card.locator('#f-image-file').setInputFiles({ name: 'a.gif', mimeType: 'image/gif', buffer: Buffer.from('GIF89a') })
    await expect(card.locator('#e-image')).toHaveText('Use a JPEG, PNG or WebP image.')
  } finally { await apiCall(page, 'DELETE', `${API}/users/${u.id}`).catch(() => {}) }
})

test('avatars: the picture where there is one, initials on a colour where not', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme/users', { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  const alan = page.getByRole('row', { name: /Alan Turing/ })
  await expect(alan.locator('.avatar')).toHaveText('AT')
  await expect(alan.locator('.avatar-img')).toBeHidden()
  const tone = await alan.locator('.avatar').getAttribute('data-tone')
  expect(tone).toMatch(/^[0-7]$/)
  await page.locator('#list-search').fill('grace')
  const grace = page.getByRole('row', { name: /Grace Hopper/ })
  await expect(grace.locator('.avatar-img')).toBeVisible()
  await expect(grace.locator('.avatar-img')).toHaveAttribute('alt', '')
  await expect(grace.locator('.avatar')).toHaveAttribute('aria-hidden', 'true')
  // the same user, the same colour on their own page
  await page.locator('#list-search').fill('alan')
  await page.getByRole('link', { name: 'Alan Turing' }).click()
  await expect(page.locator('.page-head .avatar')).toHaveAttribute('data-tone', tone)
  await expect(page.locator('.page-head .avatar')).toHaveText('AT')
  // the header's account menu: the signed-in user's own picture (Ada has one)
  await expect(page.locator('.user-chip .avatar-img')).toHaveAttribute('src', /\/o\/[^/]+\/pictures\//)
  await signIn(page, 'user')
  await page.goto(ACCOUNT, { waitUntil: 'load' })
  await expect(page.locator('.user-chip .avatar')).toHaveText('AT')
  // group members
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme/groups', { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
  await page.getByRole('row', { name: /Everyone/ }).getByRole('button', { name: /Members/ }).click()
  const members = page.getByRole('region', { name: 'Group members' })
  await expect(members.locator('.avatar').first()).toBeVisible()
})
