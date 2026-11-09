// The sidebar on wide screens in a window shorter than it: it stays beside the content, no taller than the window,
// and its links scroll inside it, so the last one is in reach without scrolling the page to its end; the list does
// not hand its scrolling on to the page, a focused or current link is brought into view clear of the edge fades, and
// it keeps AA in both themes. A window it fits in shows it whole, with no scrolling and no fade.
import { test, expect } from '@playwright/test'
import { signIn, setTheme, axe, fmt, flatBackdrop, WORST } from './helpers.mjs'

const SHORT = { width: 1280, height: 660 } // above the 40rem the sidebar sticks from, below the super admin's sidebar
const nav = (page) => page.locator('#primary-nav')
const list = (page) => page.locator('#primary-nav .nav-scroll')
const lastLink = (page) => page.locator('#primary-nav .nav-link').last()

// whether el is wholly inside the list's visible area and clear of the fades showing at its edges (none at an end)
async function inView(page, el) {
  return el.evaluate((link) => {
    const l = link.closest('.nav-scroll'), box = l.getBoundingClientRect(), r = link.getBoundingClientRect()
    const cs = getComputedStyle(l)
    const top = parseFloat(cs.getPropertyValue('--nav-fade-top')) || 0, bottom = parseFloat(cs.getPropertyValue('--nav-fade-bottom')) || 0
    return r.top >= box.top + top - 1 && r.bottom <= box.bottom - bottom + 1
  })
}

const fades = (page) => list(page).evaluate((l) => {
  const cs = getComputedStyle(l)
  return [cs.getPropertyValue('--nav-fade-top').trim(), cs.getPropertyValue('--nav-fade-bottom').trim()]
})

test('a sidebar taller than the window scrolls on its own', async ({ page }) => {
  await page.setViewportSize(SHORT)
  await signIn(page, 'super')
  await page.goto('/admin/orgs/acme', { waitUntil: 'load' })

  // no taller than the window, and its list scrolls
  const box = await nav(page).boundingBox()
  expect(box.y + box.height).toBeLessThanOrEqual(SHORT.height)
  const { scroll, client } = await list(page).evaluate((l) => ({ scroll: l.scrollHeight, client: l.clientHeight }))
  expect(scroll, 'the super admin sidebar should not fit this window').toBeGreaterThan(client)
  await expect(lastLink(page)).not.toBeInViewport()

  // at the top: a fade at the bottom only
  expect(await fades(page)).toEqual(['0px', '24px'])

  // the wheel over the sidebar scrolls its list to the end, and the page not at all
  expect(await page.evaluate(() => window.scrollY)).toBe(0)
  await nav(page).hover()
  for (let i = 0; i < 8; i++) await page.mouse.wheel(0, 400)
  await expect.poll(() => list(page).evaluate((l) => Math.ceil(l.scrollTop + l.clientHeight) >= l.scrollHeight)).toBe(true)
  expect(await page.evaluate(() => window.scrollY)).toBe(0)
  await expect(lastLink(page)).toBeInViewport()
  expect(await fades(page)).toEqual(['24px', '0px'])

  // followed, its link is current and in view on the new page
  const href = await lastLink(page).getAttribute('href')
  await lastLink(page).click()
  await page.waitForURL((u) => u.pathname === href)
  await expect(lastLink(page)).toHaveAttribute('aria-current', 'page')
  await expect.poll(() => inView(page, lastLink(page))).toBe(true) // the fades follow the scroll a frame later

  // the keyboard: a link reached with Tab is scrolled into view, clear of the fade
  await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
  const links = page.locator('#primary-nav .nav-link')
  const n = await links.count()
  await links.first().focus()
  for (let i = 1; i < n; i++) await page.keyboard.press('Tab')
  await expect(lastLink(page)).toBeFocused()
  await expect.poll(() => inView(page, lastLink(page))).toBe(true) // the fades follow the scroll a frame later
  expect(await page.evaluate(() => window.scrollY)).toBe(0)
})

test('a sidebar the window holds is shown whole', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 1400 })
  await signIn(page, 'super')
  await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
  const { scroll, client } = await list(page).evaluate((l) => ({ scroll: l.scrollHeight, client: l.clientHeight }))
  expect(scroll).toBe(client)
  await expect(lastLink(page)).toBeInViewport()
  expect(await fades(page)).toEqual(['0px', '0px'])
})

for (const theme of ['light', 'dark']) {
  test(`the scrolling sidebar keeps AA (${theme})`, async ({ page }) => {
    await setTheme(page, theme)
    await page.setViewportSize(SHORT)
    await signIn(page, 'super')
    await page.goto('/admin/orgs/acme', { waitUntil: 'load' })
    for (const bg of WORST[theme]) {
      await flatBackdrop(page, bg)
      const r = await axe(page, { include: '#primary-nav' })
      expect(r.violations.length, `${bg}\n${fmt(r.violations)}`).toBe(0)
    }
  })
}
