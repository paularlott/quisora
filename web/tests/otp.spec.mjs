// The six-digit code field (one input drawn as six boxes): paste, digit filtering, auto-submit, errors, a11y.
import { test, expect } from '@playwright/test'
import { axe, fmt, signIn } from './helpers.mjs'

// RFC 6238 TOTP (SHA-1, 6 digits, 30 s) from a base32 secret, for driving the enrolment step.
export async function totp(secret) {
  const { createHmac } = await import('node:crypto')
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const ch of secret.replace(/=+$/, '').toUpperCase()) bits += alpha.indexOf(ch).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const h = createHmac('sha1', key).update(msg).digest()
  const o = h[h.length - 1] & 15
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0')
}


test('authenticator set-up dialog: paste fills the boxes, the 6th digit submits, errors and retry work', async ({ page }) => {
  await signIn(page, 'otp') // its own demo user: this test turns the Authenticator App on
  await page.goto('/o/acme/account')
  await page.getByRole('button', { name: /Set up… Authenticator App/ }).click()
  const code = page.getByLabel('Code from the app')
  await expect(code).toBeFocused()
  const secret = (await page.locator('#totp-secret').innerText()).trim()
  // a pasted, spaced, wrong code: kept as digits only, then submitted by itself
  await page.keyboard.insertText('00 00 0')
  await expect(code).toHaveValue('000000'.slice(0, 5))
  await expect(page.locator('.otp-box.is-filled')).toHaveCount(5)
  await page.keyboard.insertText('0x')
  // the wrong code is rejected: the error is a toast (nothing appears under the boxes, so the dialog keeps its size),
  // the boxes are emptied and keep focus
  const dlg = page.getByRole('dialog', { name: 'Set up Authenticator App' })
  const before = (await dlg.boundingBox()).height
  await expect(code).toHaveAttribute('aria-invalid', 'true')
  await expect(code).toHaveValue('')
  await expect(code).toBeFocused()
  const err = page.locator('.toasts').getByText(/That code is incorrect/)
  await expect(err).toHaveCount(1)
  await expect(page.locator('#e-totp_code')).toBeEmpty()
  expect((await dlg.boundingBox()).height).toBe(before)
  // a second wrong code replaces the toast rather than stacking another
  await page.keyboard.insertText('111111')
  await expect(code).toHaveValue('')
  await expect(err).toHaveCount(1)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  // correcting the code submits again
  await page.keyboard.insertText(await totp(secret))
  await expect(page.getByText('Authenticator App is on').first()).toBeVisible()
  await expect(err).toHaveCount(0)
})

test('Authenticator App on: "Set up again…" (add or change phones) asks to re-confirm, explains, and switches over', async ({ page }) => {
  const { accountStub } = await import('./pages.mjs')
  await signIn(page, 'user')
  await page.goto('/o/acme/account')
  await accountStub({ totp: true })(page)
  // the server asks for a re-authentication first; the stubbed reauth then lets the begin through
  let begins = 0
  await page.route('**/api-internal/account/totp/begin', (route) => {
    begins++
    if (begins === 1) return route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'Confirm it is you with your password or a passkey first.', field: 'reauth' }) })
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ secret: 'JBSWY3DPEHPK3PXP', qr: 'data:image/svg+xml;base64,PHN2Zy8+', uri: 'otpauth://totp/x' }) })
  })
  await page.route('**/api-internal/account/reauth', (route) => route.request().method() === 'POST'
    ? route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }) : route.fallback())
  await page.route('**/api-internal/account/totp/confirm', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }))
  await expect(page.getByRole('button', { name: /Remove… Authenticator App/ })).toBeVisible()
  await page.getByRole('button', { name: /Set up again… Authenticator App/ }).click()
  const reauth = page.getByRole('dialog', { name: 'Confirm it is you' })
  // the six boxes line up with the password input above them, edge to edge (measured once the dialog has opened)
  await reauth.evaluate((el) => Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished)))
  const pw = await reauth.getByLabel('Password').boundingBox()
  const boxes = reauth.locator('.otp-box')
  const first = await boxes.first().boundingBox(), last = await boxes.last().boundingBox()
  expect(Math.abs(first.x - pw.x)).toBeLessThan(1.5)
  expect(Math.abs((last.x + last.width) - (pw.x + pw.width))).toBeLessThan(1.5)
  await reauth.getByLabel('Password').fill('anything')
  await reauth.getByRole('button', { name: 'Confirm' }).click()
  const dlg = page.getByRole('dialog', { name: 'Set up Authenticator App again' })
  await expect(dlg).toBeVisible()
  await expect(dlg.getByText('Scan it on every phone you want to use')).toBeVisible()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await dlg.getByLabel('Code from the app').focus()
  await page.keyboard.insertText('123456')
  await expect(page.getByText('Authenticator App set up again').first()).toBeVisible()
})

test('"Confirm it is you": a lost authenticator app is confirmed with the password and a recovery code instead', async ({ page }) => {
  const { accountStub } = await import('./pages.mjs')
  await signIn(page, 'user')
  await page.goto('/o/acme/account')
  await accountStub({ totp: true, recovery_left: 4 })(page)
  let begins = 0
  await page.route('**/api-internal/account/totp/begin', (route) => {
    begins++
    if (begins === 1) return route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'Confirm it is you with your password or a passkey first.', field: 'reauth' }) })
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ secret: 'JBSWY3DPEHPK3PXP', qr: 'data:image/svg+xml;base64,PHN2Zy8+', uri: 'otpauth://totp/x' }) })
  })
  const sent = []
  await page.route('**/api-internal/account/reauth', (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    const body = route.request().postDataJSON()
    sent.push(body)
    if (body.recovery_code !== 'GOOD-CODE') return route.fulfill({ status: 422, contentType: 'application/json', body: JSON.stringify({ error: 'That recovery code is incorrect or has already been used.', field: 'recovery_code' }) })
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' })
  })
  await page.getByRole('button', { name: /Set up again… Authenticator App/ }).click()
  const reauth = page.getByRole('dialog', { name: 'Confirm it is you' })
  await reauth.getByRole('button', { name: 'Lost your authenticator app? Use a recovery code' }).click()
  const rc = reauth.getByLabel('Recovery code')
  await expect(rc).toBeFocused()
  await expect(reauth.getByLabel('Authenticator code')).toBeHidden()
  await expect(reauth.getByLabel('Password')).toBeVisible()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  // a wrong code is flagged on its field
  await reauth.getByLabel('Password').fill('anything')
  await rc.fill('BAD-CODE')
  await reauth.getByRole('button', { name: 'Confirm' }).click()
  await expect(reauth.locator('#e-ra_recovery_code')).toContainText('That recovery code is incorrect')
  await expect(rc).toHaveAttribute('aria-invalid', 'true')
  // the right one confirms, without an authenticator code
  await rc.fill('GOOD-CODE')
  await reauth.getByRole('button', { name: 'Confirm' }).click()
  await expect(page.getByRole('dialog', { name: 'Set up Authenticator App again' })).toBeVisible()
  expect(sent.at(-1)).toEqual({ password: 'anything', recovery_code: 'GOOD-CODE' })
})

test('"Confirm it is you": no recovery code link without codes left', async ({ page }) => {
  const { accountStub } = await import('./pages.mjs')
  await signIn(page, 'user')
  await page.goto('/o/acme/account')
  await accountStub({ totp: true, recovery_left: 0 })(page)
  await page.route('**/api-internal/account/totp/begin', (route) => route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'Confirm it is you with your password or a passkey first.', field: 'reauth' }) }))
  await page.getByRole('button', { name: /Set up again… Authenticator App/ }).click()
  const reauth = page.getByRole('dialog', { name: 'Confirm it is you' })
  await expect(reauth.getByLabel('Authenticator code')).toBeVisible()
  await expect(reauth.getByRole('button', { name: /Use a recovery code/ })).toHaveCount(0)
})
