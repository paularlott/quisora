// Tenant access (the tenant page's Access card): add a user and a group, limit to some applications, roles and tags,
// an end date, edit, remove; the tenant's "Who can sign in" setting; keyboard use and axe.
import { test, expect } from '@playwright/test'
import { signIn, apiCall, uniq, axe, fmt } from './helpers.mjs'

const A = '/admin/orgs/acme'
const API = '/api/orgs/acme'

async function freshTenant(page, settings) {
  await signIn(page, 'admin')
  await page.goto(`${A}/tenants`, { waitUntil: 'load' })
  const slug = uniq('ac')
  const t = await apiCall(page, 'POST', `${API}/tenants`, { name: slug, display_name: 'Access ' + slug, ...(settings ? { settings } : {}) })
  const portal = await apiCall(page, 'POST', `${API}/clients`, { name: 'Portal', tenant_id: t.id, redirect_uris: ['https://portal.example/cb'] })
  const billing = await apiCall(page, 'POST', `${API}/clients`, { name: 'Billing', tenant_id: t.id, redirect_uris: ['https://billing.example/cb'] })
  await page.goto(`${A}/tenants/${slug}`, { waitUntil: 'load' })
  await page.getByRole('button', { name: 'Add access' }).waitFor()
  return { slug, id: t.id, portal, billing }
}

test('access: add a user by keyboard with roles, tags, some applications and an end date; edit; remove', async ({ page }) => {
  const t = await freshTenant(page)
  await expect(page.locator('section[aria-labelledby="access-h"]')).toContainText('Only these users and groups can sign in')
  await expect(page.getByRole('heading', { name: 'No one has been given access' })).toBeVisible()

  const add = page.getByRole('button', { name: 'Add access' })
  await add.focus()
  await page.keyboard.press('Enter')
  const dlg = page.getByRole('dialog', { name: 'Add access' })
  await expect(dlg).toBeVisible()
  const find = dlg.getByRole('combobox', { name: 'Find a user or group' })
  await expect(find).toBeFocused()
  // nothing chosen: the error is on the search field
  await dlg.getByRole('button', { name: 'Add access' }).click()
  await expect(page.locator('#e-acc_subject')).toHaveText('Choose a user or group from the list.')
  await expect(find).toBeFocused()
  // type: users and groups that match appear in a list over the form, each tagged User or Group
  await page.keyboard.type('a')
  const list = dlg.getByRole('listbox', { name: 'Users and groups' })
  await expect(list).toBeVisible()
  await expect(find).toHaveAttribute('aria-expanded', 'true')
  await expect(list.getByRole('option').first()).toContainText('User')
  // Escape closes the list but not the dialog; Down opens it again
  await page.keyboard.press('Escape')
  await expect(list).toBeHidden()
  await expect(dlg).toBeVisible()
  await page.keyboard.press('ArrowDown')
  await expect(list).toBeVisible()
  // narrow it, move with the arrow keys and choose with Enter (which does not submit the dialog)
  await page.keyboard.type('lan tur')
  const alan = list.getByRole('option', { name: /Alan Turing/ })
  await expect(list.getByRole('option')).toHaveCount(1)
  await page.keyboard.press('ArrowDown')
  await expect(alan).toHaveAttribute('aria-selected', 'true')
  await expect(find).toHaveAttribute('aria-activedescendant', await alan.getAttribute('id'))
  await page.keyboard.press('Enter')
  await expect(list).toBeHidden()
  await expect(find).toHaveValue('Alan Turing')
  await expect(dlg).toBeVisible()
  await page.locator('#f-roles').fill('editor viewer ')
  await expect(dlg.getByRole('list', { name: 'Current roles' }).getByRole('listitem')).toHaveCount(2)
  await page.locator('#f-tags').fill('team:blue')
  await page.keyboard.press('Enter')
  await dlg.getByRole('switch', { name: /All of this tenant's applications/ }).uncheck()
  await dlg.getByRole('checkbox', { name: 'Billing' }).check()
  await page.locator('#f-acc_expires').fill('2099-03-04')
  const r = await axe(page)
  expect(r.violations.length, fmt(r.violations)).toBe(0)
  await dlg.getByRole('button', { name: 'Add access' }).click()
  await expect(dlg).toBeHidden()
  await expect(add).toBeFocused()
  await expect(page.locator('.toasts')).toContainText('Alan Turing now has access.')

  const row = page.locator('section[aria-labelledby="access-h"] tbody tr').filter({ hasText: 'Alan Turing' })
  await expect(row).toContainText('editor, viewer')
  await expect(row).toContainText('team:blue')
  await expect(row).toContainText('Billing')
  await expect(row).not.toContainText('Portal')
  const saved = (await apiCall(page, 'GET', `${API}/tenants/${t.id}/access`)).items[0]
  expect(saved.roles).toEqual(['editor', 'viewer'])
  expect(saved.all_clients).toBe(false)
  expect(saved.clients).toEqual([t.billing.id])
  expect(saved.expires).toBeTruthy()

  // adding the same user again is refused at the choice list
  await add.click()
  await page.locator('#f-acc_subject').fill('alan')
  await dlg.getByRole('option', { name: /Alan Turing/ }).click()
  await dlg.getByRole('button', { name: 'Add access' }).click()
  await expect(page.locator('#e-acc_subject')).toContainText('already has access')
  await page.keyboard.press('Escape')

  // edit: all applications, no end date
  const edit = page.getByRole('button', { name: 'Edit access for Alan Turing' })
  await edit.click()
  const ed = page.getByRole('dialog', { name: 'Edit access' })
  await expect(ed).toContainText('Alan Turing')
  await expect(ed.getByRole('combobox', { name: 'Find a user or group' })).toBeHidden()
  await ed.getByRole('switch', { name: /All of this tenant's applications/ }).check()
  await page.locator('#f-acc_expires').fill('')
  await ed.getByRole('button', { name: 'Save changes' }).click()
  await expect(ed).toBeHidden()
  await expect(edit).toBeFocused()
  await expect(row).toContainText('All applications')
  await expect(row).toContainText('No end')

  // remove asks first
  await page.getByRole('button', { name: 'Remove access for Alan Turing' }).click()
  const confirm = page.getByRole('dialog', { name: 'Remove access' })
  await expect(confirm).toContainText('can no longer sign in')
  await confirm.getByRole('button', { name: 'Remove access' }).click()
  await expect(row).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'No one has been given access' })).toBeVisible()
})

test('access: a group, search in the list, and an open tenant hides the Access card', async ({ page }) => {
  const t = await freshTenant(page)
  const g = await apiCall(page, 'POST', `${API}/groups`, { display_name: uniq('Ops') })
  await apiCall(page, 'POST', `${API}/tenants/${t.id}/access`, { subject_type: 'user', subject_id: (await apiCall(page, 'GET', `${API}/users?q=alan`)).items[0].id })
  await page.getByRole('button', { name: 'Add access' }).click()
  const dlg = page.getByRole('dialog', { name: 'Add access' })
  await page.locator('#f-acc_subject').fill(g.display_name)
  const opt = dlg.getByRole('option', { name: new RegExp(g.display_name) })
  await expect(opt).toContainText('Group')
  await page.keyboard.press('ArrowDown')
  await page.keyboard.press('Enter')
  await expect(page.locator('#f-acc_subject')).toHaveValue(g.display_name)
  await dlg.getByRole('button', { name: 'Add access' }).click()
  await expect(dlg).toBeHidden()
  const rows = page.locator('section[aria-labelledby="access-h"] tbody tr')
  await expect(rows).toHaveCount(2)
  await expect(rows.filter({ hasText: g.display_name })).toContainText('Group')

  // the list's own search
  await page.locator('#access-search').fill('zzzz-nothing')
  await expect(page.locator('section[aria-labelledby="access-h"]').getByRole('heading', { name: 'Nothing matches your search' })).toBeVisible()
  await page.locator('#access-search').fill('alan')
  await expect(rows).toHaveCount(1)

  // open the tenant to everyone through the sign-in rules dialog
  await page.getByRole('button', { name: 'Edit sign-in rules' }).click()
  const td = page.getByRole('dialog', { name: 'Edit sign-in rules' })
  await expect(td.getByRole('radio', { name: /Only users and groups given access/ })).toBeChecked()
  await td.getByRole('radio', { name: /Everyone in the organization/ }).check()
  await td.getByRole('button', { name: 'Save changes' }).click()
  await expect(td).toBeHidden()
  await expect(page.locator('section[aria-labelledby="rules-h"]')).toContainText('Everyone in the organization')
  // everyone may sign in: the Access card is not shown (its entries are kept for switching back)
  await expect(page.locator('section[aria-labelledby="access-h"]')).toBeHidden()
  await page.getByRole('button', { name: 'Edit sign-in rules' }).click()
  await td.getByRole('radio', { name: /Only users and groups given access/ }).check()
  await td.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.locator('section[aria-labelledby="access-h"] tbody tr')).toHaveCount(1) // still filtered by "alan"
  const saved = await apiCall(page, 'GET', `${API}/tenants/${t.id}`)
  expect(saved.settings.members_only).toBe(true)
})
