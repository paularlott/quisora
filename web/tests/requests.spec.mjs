import { test, expect } from '@playwright/test'
import { apiCall, signIn, uniq } from './helpers.mjs'

const API = '/api/orgs/acme'

// A requester group (Alan) and its approver group (Grace), and a members-only tenant, made for one test.
async function setUp(page) {
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme/groups', { waitUntil: 'load' })
  const id = (q) => apiCall(page, 'GET', `${API}/users?q=${q}`).then((r) => r.items[0].id)
  const [alan, grace] = [await id('alan'), await id('grace')]
  const tag = uniq('rq')
  const tenant = await apiCall(page, 'POST', `${API}/tenants`, { name: tag, display_name: 'Requested ' + tag })
  const approvers = await apiCall(page, 'POST', `${API}/groups`, { display_name: 'Approvers ' + tag, approves_requests: true })
  await apiCall(page, 'PUT', `${API}/groups/${approvers.id}/members/${grace}`)
  const requesters = await apiCall(page, 'POST', `${API}/groups`, { display_name: 'Requesters ' + tag,
    access_requests: { enabled: true, approvers: approvers.id, lengths: [3600, 86400] } })
  await apiCall(page, 'PUT', `${API}/groups/${requesters.id}/members/${alan}`)
  const tearDown = async () => {
    await signIn(page, 'admin')
    await page.goto('/admin/orgs/acme/groups', { waitUntil: 'load' })
    await apiCall(page, 'DELETE', `${API}/groups/${requesters.id}`)
    await apiCall(page, 'DELETE', `${API}/groups/${approvers.id}`)
  }
  return { tenant, approvers, requesters, tag, tearDown }
}

test('access requests: Alan asks, Grace approves, Alan ends it; the menu shows each page only to whom it concerns', async ({ page }) => {
  const s = await setUp(page)
  try {
    // Alan asks
    await signIn(page, 'user')
    await page.goto('/o/acme/account/requests', { waitUntil: 'load' })
    await page.getByRole('button', { name: 'Account menu' }).click()
    await expect(page.locator('#user-menu').getByRole('link', { name: 'Request access' })).toBeVisible()
    await expect(page.locator('#user-menu').getByRole('link', { name: 'Approvals' })).toHaveCount(0)
    await page.keyboard.press('Escape')
    const opener = page.getByRole('button', { name: 'Request access' })
    await opener.click()
    const ask = page.getByRole('dialog', { name: 'Request access' })
    const tenant = ask.getByRole('combobox', { name: 'Tenant' })
    await tenant.fill('Requested ' + s.tag.slice(0, 4))
    await ask.getByRole('option', { name: new RegExp('Requested ' + s.tag) }).click()
    const from = ask.locator('#f-approvers')
    if (await from.isVisible()) await from.selectOption({ label: s.approvers.display_name }) // Alan is in Support too
    await ask.locator('#f-length').selectOption({ label: '1 day' })
    await ask.getByLabel(/Why you need it/).fill('INC-77: a customer cannot sign in')
    await ask.getByRole('button', { name: 'Send request' }).click()
    await expect(ask).toBeHidden()
    await expect(opener).toBeFocused() // focus goes back to the button that opened it
    await expect(page.locator('.toasts')).toContainText('Request sent')
    const mine = page.getByRole('row', { name: new RegExp('Requested ' + s.tag) })
    await expect(mine).toContainText('Waiting')
    await expect(mine).toContainText('1 day')

    // Grace approves
    await signIn(page, 'manager')
    await page.goto('/o/acme/account/approvals', { waitUntil: 'load' })
    const row = page.getByRole('row', { name: new RegExp('Requested ' + s.tag) })
    await expect(row).toContainText('Alan Turing')
    await expect(row).toContainText('INC-77')
    // who: the name (a manager's link to the user page) and the email below it
    await expect(row.getByRole('link', { name: 'Alan Turing' })).toHaveAttribute('href', /^\/admin\/orgs\/acme\/users\/[A-Za-z0-9_-]+$/)
    await expect(row).toContainText('@acme.example')
    await row.getByRole('button', { name: /^Approve/ }).click()
    const dlg = page.getByRole('dialog', { name: 'Approve the request' })
    await expect(dlg).toContainText('Alan Turing asks for access to Requested ' + s.tag + ' for 1 day.')
    await dlg.getByLabel(/Note for them/).fill('Go ahead')
    await dlg.getByRole('button', { name: 'Approve' }).click()
    await expect(page.locator('.toasts')).toContainText('Approved: Alan Turing has access to Requested ' + s.tag)
    await expect(page.getByRole('row', { name: new RegExp('Requested ' + s.tag) })).toContainText('Grace Hopper')

    // Alan sees it active, and ends it
    await signIn(page, 'user')
    await page.goto('/o/acme/account/requests', { waitUntil: 'load' })
    await expect(mine).toContainText('Active')
    await expect(mine).toContainText('Note: “Go ahead”')
    await mine.getByRole('button', { name: /^End now: your access/ }).click()
    await page.getByRole('dialog', { name: 'End your access' }).getByRole('button', { name: 'End access' }).click()
    await expect(page.locator('.toasts')).toContainText('has ended')
    await expect(mine).toContainText('Ended early')
  } finally {
    await s.tearDown()
  }
})

test('groups: an administrator turns access requests on, choosing from the groups that approve; one in use keeps approving; managers cannot add members to either group', async ({ page }) => {
  const s = await setUp(page)
  try {
    const plain = await apiCall(page, 'POST', `${API}/groups`, { display_name: 'Plain ' + s.tag })
    const other = await apiCall(page, 'POST', `${API}/groups`, { display_name: 'Other ' + s.tag })
    await page.reload({ waitUntil: 'load' })
    await page.getByRole('searchbox').first().fill('Plain ' + s.tag)
    await page.getByRole('button', { name: 'Edit Plain ' + s.tag }).click()
    const dlg = page.getByRole('dialog', { name: 'Edit group' })
    await dlg.getByRole('switch', { name: /Members can request access/ }).check()
    await expect(dlg.getByText('Only administrators can change who is in this group.')).toBeVisible()
    const by = dlg.getByRole('combobox', { name: 'Approved by' })
    await by.fill('Other ' + s.tag) // a group that does not approve is not offered
    await expect(dlg.getByRole('option', { name: 'Other ' + s.tag })).toHaveCount(0)
    await by.fill('Approvers ' + s.tag.slice(0, 3))
    await dlg.getByRole('option', { name: 'Approvers ' + s.tag }).click()
    await dlg.getByLabel('4 hours').check()
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg).toBeHidden()
    const g = await apiCall(page, 'GET', `${API}/groups/${plain.id}`)
    expect(g.access_requests).toEqual({ approvers: s.approvers.id, lengths: [14400], service_accounts: false })
    await expect(page.getByRole('row', { name: new RegExp('Plain ' + s.tag) })).toContainText('Can request access')
    await apiCall(page, 'DELETE', `${API}/groups/${plain.id}`)
    await apiCall(page, 'DELETE', `${API}/groups/${other.id}`)

    // the approver group is marked, and keeps approving while a group uses it
    await page.getByRole('searchbox').first().fill('Approvers ' + s.tag)
    await expect(page.getByRole('row', { name: new RegExp('Approvers ' + s.tag) })).toContainText('Approves requests')
    await page.getByRole('button', { name: 'Edit Approvers ' + s.tag }).click()
    const sw = dlg.getByRole('switch', { name: /Members approve access requests/ })
    await expect(sw).toBeChecked()
    await sw.uncheck()
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg.getByText(/uses this group to approve its requests/).first()).toBeVisible()
    await dlg.getByRole('button', { name: 'Cancel' }).click()

    // a manager is refused adding anyone to a protected group
    await signIn(page, 'manager')
    await page.goto('/admin/orgs/acme/groups', { waitUntil: 'load' })
    const katherine = (await apiCall(page, 'GET', `${API}/users?q=katherine`)).items[0]
    await expect(apiCall(page, 'PUT', `${API}/groups/${s.approvers.id}/members/${katherine.id}`)).rejects.toThrow(/only administrators/)
  } finally {
    await s.tearDown()
  }
})

test('tenant: defaults for new access are edited on the access card and fill the Add access dialog', async ({ page }) => {
  const s = await setUp(page)
  try {
    await page.goto(`/admin/orgs/acme/tenants/${s.tenant.name}`, { waitUntil: 'load' })
    await expect(page.getByText('No defaults for new access: it gets only what you give it.')).toBeVisible()
    await page.getByRole('button', { name: 'Edit defaults' }).click()
    const dlg = page.getByRole('dialog', { name: 'Defaults for new access' })
    await dlg.locator('#f-dft_roles').fill('support')
    await dlg.locator('#f-dft_roles').press('Enter')
    await dlg.getByRole('button', { name: 'Save defaults' }).click()
    await expect(dlg).toBeHidden()
    await expect(page.getByText('Defaults for new access: roles support.')).toBeVisible()
    await page.getByRole('button', { name: 'Add access' }).click()
    const add = page.getByRole('dialog', { name: 'Add access' })
    await expect(add.getByRole('list', { name: 'Current roles' })).toContainText('support')
    await add.getByRole('button', { name: 'Cancel' }).click()
    expect((await apiCall(page, 'GET', `${API}/tenants/${s.tenant.id}`)).access_defaults.roles).toEqual(['support'])
  } finally {
    await s.tearDown()
  }
})

test('console: the access requests page lists the organization’s requests, narrowed by state', async ({ page }) => {
  await signIn(page, 'admin')
  await page.goto('/admin/orgs/acme/access-requests', { waitUntil: 'load' })
  await expect(page.getByRole('row', { name: /INC-2041/ })).toContainText('Ops tools')
  await expect(page.getByRole('row', { name: /INC-2041/ })).toContainText('Waiting for On-call leads')
  await page.locator('#f-rq-state').selectOption('approved')
  await expect(page.getByRole('row', { name: /SUP-311/ })).toContainText('Active')
  await expect(page.getByRole('row', { name: /INC-2041/ })).toHaveCount(0)
})
