// Messages: errors about a whole action are error toasts that stay until dismissed — inside an open dialog when there
// is one (a modal dialog makes the rest of the page inert) — while field errors stay at the field.
import { test, expect } from '@playwright/test'
import { axe, fmt, signIn } from './helpers.mjs'

const failWith = (page, pattern, status, message) =>
  page.route(pattern, (route) => route.request().method() === 'GET' ? route.fallback()
    : route.fulfill({ status, contentType: 'application/json', body: JSON.stringify({ error: message }) }))

test('an action error inside a dialog is an error toast in the dialog, stays, and can be dismissed', async ({ page }) => {
  await signIn(page, 'super')
  await page.goto('/admin/orgs')
  await failWith(page, '**/api/orgs', 500, 'Something went wrong. Please try again.')
  await page.getByRole('button', { name: 'New organization' }).click()
  const dialog = page.getByRole('dialog', { name: 'New organization' })
  await dialog.getByLabel('Display name').fill('Toast Test')
  await dialog.getByLabel('URL name').fill('toast-test')
  await dialog.getByRole('button', { name: 'Create organization' }).click()
  const toast = dialog.locator('.toast-error')
  await expect(toast).toContainText('Something went wrong')
  await expect(page.getByRole('alert').filter({ hasText: 'Something went wrong' }).first()).toBeAttached()
  // the dialog stays open with the input kept, and nothing is shown as a field error
  await expect(dialog.getByLabel('URL name')).toHaveValue('toast-test')
  await expect(dialog.locator('[aria-invalid="true"]')).toHaveCount(0)
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  // error toasts do not time out (success toasts go after 6 s)
  await page.waitForTimeout(6500)
  await expect(toast).toBeVisible()
  await toast.getByRole('button', { name: 'Dismiss message' }).click()
  await expect(toast).toHaveCount(0)
})

test('an action error on a page is an error toast; a success is a success toast', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme/settings')
  await page.waitForSelector('#f-display_name')
  await failWith(page, '**/api/orgs/acme/settings', 403, 'You do not have permission to do that.')
  await page.getByRole('button', { name: 'Save settings' }).click()
  const err = page.locator('body > .toasts .toast-error')
  await expect(err).toContainText('You do not have permission')
  await err.getByRole('button', { name: 'Dismiss message' }).click()
  await expect(err).toHaveCount(0)
  await page.unroute('**/api/orgs/acme/settings')
  await page.getByRole('button', { name: 'Save settings' }).click()
  await expect(page.locator('.toast-success')).toBeVisible()
})
