// The sign-in page asks for the email address first, then the password: providers and the passkey sit on the email
// step, and the password step looks the same for every address (the server is asked nothing in between).
import { test, expect } from '@playwright/test'
import { axe, fmt, signIn } from './helpers.mjs'

test('email first, then the password', async ({ page }) => {
  await signIn(page, 'none')
  let calls = 0
  let sent = null
  await page.route('**/api-internal/login/password', (route) => {
    calls++
    sent = route.request().postDataJSON()
    return route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'Wrong email address or password.' }) })
  })
  await page.goto('/o/acme/login')

  // the email step: the field, Continue, providers; no password field yet
  const email = page.locator('#f-email')
  await expect(email).toBeVisible()
  await expect(email).toHaveAttribute('autocomplete', 'username webauthn')
  await expect(page.locator('#f-password')).toBeHidden()
  await expect(page.getByRole('link', { name: /^Continue with / }).first()).toBeVisible()
  // the passkey is the last of the one-step sign-ins, above the email form
  const oneStep = page.locator('.provider-list').locator('a, button')
  await expect(oneStep.last()).toHaveText(/Sign in with a passkey/)
  expect(await oneStep.count()).toBeGreaterThan(1)
  const below = await page.evaluate(() => {
    const pk = [...document.querySelectorAll('button')].find((b) => /Sign in with a passkey/.test(b.textContent))
    return !!(pk.compareDocumentPosition(document.getElementById('f-email')) & Node.DOCUMENT_POSITION_FOLLOWING)
  })
  expect(below, 'email field after the passkey button').toBe(true)

  // an empty or malformed address stays on the email step, with the error at the field
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(page.locator('#e-email')).toHaveText('Enter your email address.')
  await email.fill('alan')
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(page.locator('#e-email')).toContainText('Enter an email address')
  await expect(email).toBeFocused()

  // a well-formed address moves on without asking the server: nothing to learn about the account
  await email.fill('  someone@acme.example ')
  await page.keyboard.press('Enter')
  const password = page.locator('#f-password')
  await expect(password).toBeFocused()
  await expect(page.locator('#f-login_email')).toHaveValue('someone@acme.example')
  await expect(page.locator('#f-login_email')).toHaveAttribute('autocomplete', 'username')
  await expect(page.locator('.account-chip')).toContainText('someone@acme.example')
  await expect(email).toBeHidden()
  await expect(page.getByRole('link', { name: /^Continue with / }).first()).toBeHidden()
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeHidden()
  expect(calls).toBe(0)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  // the password goes with the address
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.locator('#e-password')).toHaveText('Enter your password.')
  await password.fill('not it')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText('Wrong email address or password.').first()).toBeVisible()
  expect(calls).toBe(1)
  expect(sent).toMatchObject({ email: 'someone@acme.example', password: 'not it' })
  expect(sent).not.toHaveProperty('org') // the organization is the page's, in its address

  // Change goes back to the email step with the address kept and the password dropped
  await page.getByRole('button', { name: /^Change/ }).click()
  await expect(email).toBeFocused()
  await expect(email).toHaveValue('someone@acme.example')
  await page.keyboard.press('Enter')
  await expect(password).toHaveValue('')
})

// Codes by email: the step itself when the server sent one (no factor of the account's own), a new code on request,
// and the option under "Try another way" at the authenticator-code step.
test('a code by email finishes the second factor', async ({ page }) => {
  await signIn(page, 'none')
  let step = { step: 'email_code', ticket: 'n1.stub', email: 'a•••@acme.example', alternatives: [] }
  await page.route('**/api-internal/login/password', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(step) }))
  let sends = 0
  await page.route('**/api-internal/login/email/send', (r) => {
    sends++
    return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ email: 'a•••@acme.example' }) })
  })
  let verified = null
  await page.route('**/api-internal/login/email', (r) => {
    verified = r.request().postDataJSON()
    return r.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'That code is incorrect, or a newer one was sent.', field: 'mcode' }) })
  })
  const toPassword = async () => {
    await page.goto('/o/acme/login')
    await page.locator('#f-email').fill('alan@acme.example')
    await page.getByRole('button', { name: 'Continue' }).click()
    await page.locator('#f-password').fill('stubbed password')
    await page.locator('#f-password').press('Enter')
  }

  await toPassword()
  await expect(page.getByText('We emailed a 6-digit code to a•••@acme.example.')).toBeVisible()
  await expect(page.locator('#f-mcode')).toBeFocused()
  await page.keyboard.insertText('123456')
  await expect.poll(() => verified).toEqual({ ticket: 'n1.stub', code: '123456' })
  await expect(page.getByText('That code is incorrect, or a newer one was sent.').first()).toBeVisible()
  expect(sends, 'the server sent the first code itself').toBe(0)
  await page.getByRole('button', { name: 'Send a new code' }).click()
  await expect(page.getByText('A new code is on its way.').first()).toBeVisible()
  expect(sends).toBe(1)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)

  // at the authenticator-code step it is one of the other ways, and choosing it sends a code
  step = { step: 'totp', ticket: 'n1.stub', email: 'a•••@acme.example', alternatives: ['email_code'] }
  await toPassword()
  await page.getByRole('button', { name: 'Try another way' }).first().click()
  await page.getByRole('button', { name: 'Email a code to a•••@acme.example' }).click()
  await expect(page.locator('#f-mcode')).toBeVisible()
  expect(sends).toBe(2)
  // back to the list and to the code again: no second send
  await page.getByRole('button', { name: 'Try another way' }).last().click()
  await page.getByRole('button', { name: 'Email a code to a•••@acme.example' }).click()
  await expect(page.locator('#f-mcode')).toBeVisible()
  expect(sends).toBe(2)
})
