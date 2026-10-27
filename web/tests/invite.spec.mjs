// The invitation page now that passkeys work (the demo serves https://localhost, a valid WebAuthn origin).
import { test, expect } from '@playwright/test'
import { axe, fmt } from './helpers.mjs'

test('passkey option is offered, reachable by keyboard and accessible (password + passkey organization)', async ({ page }) => {
  await page.goto('/__demo/invite?as=iris')
  await expect(page.getByRole('heading', { name: /Welcome/ })).toBeVisible()
  const btn = page.getByRole('button', { name: 'Create a passkey' })
  await expect(btn).toBeVisible()
  await expect(page.getByText('This browser or device cannot create passkeys.')).toBeHidden()
  // the passkey comes first and is the main action; Tab from it reaches the password fields
  const pw = page.locator('#f-password')
  expect(await btn.evaluate((b, p) => !!(b.compareDocumentPosition(p) & Node.DOCUMENT_POSITION_FOLLOWING), await pw.elementHandle())).toBe(true)
  await expect(btn).toHaveClass(/btn-primary/)
  await expect(page.getByRole('button', { name: 'Set password' })).toHaveClass(/btn-secondary/)
  await btn.focus()
  await page.keyboard.press('Tab') // "Password"
  await expect(pw).toBeFocused()
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

test('passkey-only organization: creating a passkey with a virtual authenticator completes the invitation', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
  await page.goto('/__demo/invite?as=quinn')
  const btn = page.getByRole('button', { name: 'Create a passkey' })
  await expect(btn).toBeVisible()
  await expect(page.getByLabel('Password')).toHaveCount(0)
  await btn.focus()
  await page.keyboard.press('Enter')
  // the invitation is consumed: the page moves on (account page, or a follow-up step) and no error is shown
  await expect(page.locator('.alert-error:visible')).toHaveCount(0)
  await page.waitForURL((u) => !/\/invite$/.test(u.pathname), { timeout: 10000 })
})

test('browser without WebAuthn: the passkey button is replaced by an explanation', async ({ page }) => {
  await page.addInitScript(() => { delete window.PublicKeyCredential })
  await page.goto('/__demo/invite?as=iris')
  await expect(page.getByRole('button', { name: 'Create a passkey' })).toHaveCount(0)
  const note = page.getByText('This browser or device cannot create passkeys. Set a password instead.')
  await expect(note).toBeVisible()
  await expect(page.getByRole('button', { name: 'Set password' })).toHaveClass(/btn-primary/)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
})

// RFC 6238 TOTP (SHA-1, 6 digits, 30 s) from a base32 secret, for driving the enrolment step.
async function totp(secret) {
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

test('MFA-required organization: after the password the authenticator set-up shows at once (no choice screen)', async ({ page }) => {
  // The demo's primary organization requires MFA; its admin has no second factor yet.
  await page.goto('/__demo/invite?as=admin')
  await page.locator('#f-password').fill('correct horse battery staple')
  await page.locator('#f-confirm').fill('correct horse battery staple')
  await page.locator('#f-confirm').press('Enter')
  // straight to the QR code and the code box, focus in the code field, no intermediate buttons
  await expect(page.getByRole('img', { name: 'QR code for your Authenticator App' })).toBeVisible()
  await expect(page.locator('#f-ecode')).toBeFocused()
  await expect(page.getByRole('button', { name: 'Use an Authenticator App' })).toHaveCount(0)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  const secret = (await page.locator('.code-box code').innerText()).trim()
  // a wrong code: an error toast, nothing under the boxes (the panel keeps its size), boxes emptied, focus kept
  const panel = page.locator('main')
  const before = (await panel.boundingBox()).height
  await page.locator('#f-ecode').fill('000000')
  await expect(page.locator('.toasts').getByText(/That code is incorrect/)).toBeVisible()
  await expect(page.locator('#f-ecode')).toHaveValue('')
  await expect(page.locator('#f-ecode')).toBeFocused()
  await expect(page.locator('#e-ecode')).toBeEmpty()
  expect((await panel.boundingBox()).height).toBe(before)
  // the sixth digit submits by itself (no button press)
  await page.locator('#f-ecode').fill(await totp(secret))
  await expect(page).toHaveURL(/\/account|\/admin/)
})
