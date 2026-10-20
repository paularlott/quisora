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
  await page.goto('/login/acme')

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
  expect(sent).toMatchObject({ org: 'acme', email: 'someone@acme.example', password: 'not it' })

  // Change goes back to the email step with the address kept and the password dropped
  await page.getByRole('button', { name: /^Change/ }).click()
  await expect(email).toBeFocused()
  await expect(email).toHaveValue('someone@acme.example')
  await page.keyboard.press('Enter')
  await expect(password).toHaveValue('')
})
