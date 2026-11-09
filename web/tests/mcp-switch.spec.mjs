// An organization's own MCP server: off until a super admin switches it on in the organization dialog; the overview
// then lists its address last among the addresses, to copy, and says when no tenant accepts AI clients for it yet.
// (The demo server does not run the MCP server itself: internal/mcpapi's tests cover its address on and off.)
import { test, expect } from '@playwright/test'
import { signIn, apiCall, axe, fmt } from './helpers.mjs'

const API = '/api/orgs/acme'

async function setMCP(page, on) {
  const o = await apiCall(page, 'GET', API)
  await apiCall(page, 'PATCH', API, { settings: { ...o.settings, mcp_server: on } })
}

test.describe.configure({ mode: 'serial' })

test('a super admin switches an organization\'s MCP server on and off', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await signIn(page, 'super')
  await page.goto('/admin/orgs', { waitUntil: 'load' })
  try {
    await setMCP(page, false)
    const org = await apiCall(page, 'GET', API)
    const mcp = `${new URL(page.url()).origin}/o/${org.id}/mcp`
    const addresses = page.getByRole('region', { name: 'Addresses' })
    const setting = page.locator('dl.kv > div').filter({ has: page.locator('dt', { hasText: 'MCP server for AI clients' }) }).locator('dd')

    // off (the default): not on the overview
    await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
    await expect(setting).toHaveText('Off')
    await expect(addresses.locator('#addr-mcp')).toHaveCount(0)

    // switched on in the organization dialog
    await page.goto('/admin/orgs', { waitUntil: 'load' })
    await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
    const dlg = page.getByRole('dialog', { name: 'Edit organization' })
    const sw = dlg.locator('#f-mcp_server')
    await expect(dlg.getByRole('group', { name: 'AI assistants' })).toBeVisible()
    await expect(sw).not.toBeChecked()
    await sw.check()
    const r = await axe(page, { include: '#org-dialog' })
    expect(r.violations.length, fmt(r.violations)).toBe(0)
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg).toBeHidden()
    expect((await apiCall(page, 'GET', API)).settings.mcp_server).toBe(true)

    // the overview lists the address last, with a copy button, and says no tenant accepts AI clients for it yet
    await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
    await expect(setting).toHaveText('On')
    await expect(addresses.locator('#addr-mcp')).toHaveText(mcp)
    await expect(addresses.locator('dt').last()).toHaveText('MCP server (for AI clients)')
    await addresses.getByRole('button', { name: 'Copy MCP server (for AI clients)' }).click()
    await expect(page.locator('#live-polite')).toContainText('Copied MCP server address')
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(mcp)
    await expect(addresses.locator('#mcp-no-tenant')).toBeVisible()
    const a = await axe(page, { include: 'main' })
    expect(a.violations.length, fmt(a.violations)).toBe(0)

    // switched off again: gone from the overview
    await page.goto('/admin/orgs', { waitUntil: 'load' })
    await page.getByRole('button', { name: 'Edit Acme Corporation' }).click()
    await expect(sw).toBeChecked()
    await sw.uncheck()
    await dlg.getByRole('button', { name: 'Save changes' }).click()
    await expect(dlg).toBeHidden()
    await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
    await expect(addresses.locator('#addr-mcp')).toHaveCount(0)
    await expect(setting).toHaveText('Off')
  } finally {
    await setMCP(page, false)
  }
})
