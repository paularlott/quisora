// The navigation drawer on small screens: it opens over the page (the content does not move), holds the focus like a
// dialog, and closes with Escape, its close button, the scrim or a swipe to the left. Wide screens keep the sidebar.
import { test, expect } from '@playwright/test'
import { signIn } from './helpers.mjs'

const A = '/admin/orgs/acme'

async function phone(page) {
  await page.setViewportSize({ width: 390, height: 780 })
  await signIn(page, 'admin')
  await page.goto(`${A}/users`, { waitUntil: 'load' })
  await page.waitForSelector('tbody tr')
}

// by id: the closed drawer is hidden, so it is not in the accessibility tree for getByRole
const nav = (page) => page.locator('#primary-nav')
const toggle = (page) => page.getByRole('button', { name: 'Open navigation menu' })

async function open(page) {
  await toggle(page).click()
  await expect(nav(page)).toHaveAttribute('data-open', 'true')
  await page.waitForTimeout(350) // the slide
}

async function expectClosed(page) {
  await expect(nav(page)).toHaveAttribute('data-open', 'false')
  await expect(nav(page)).toBeHidden()
  expect(await page.locator('#main').evaluate((el) => el.inert)).toBe(false)
}

test('opens over the page without moving it, and holds the focus', async ({ page }) => {
  await phone(page)
  await expect(nav(page)).toBeHidden()
  const before = await page.locator('#main').boundingBox()
  await open(page)
  await expect(page.getByRole('navigation', { name: 'Primary' })).toBeVisible()
  await expect(toggle(page)).toHaveAttribute('aria-expanded', 'true')
  expect(await page.locator('#main').boundingBox()).toEqual(before)
  // in from the left edge
  const box = await nav(page).boundingBox()
  expect(box.x).toBe(0)
  // focus on the close button; the page behind is inert and does not scroll
  await expect(page.getByRole('button', { name: 'Close navigation menu' })).toBeFocused()
  expect(await page.evaluate(() => ['.app-header', '#main', '.app-footer'].every((s) => document.querySelector(s).inert))).toBe(true)
  expect(await page.evaluate(() => getComputedStyle(document.documentElement).overflow)).toBe('hidden')
  // Tab wraps inside the drawer
  await page.keyboard.press('Shift+Tab')
  await expect(nav(page).getByRole('link').last()).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(page.getByRole('button', { name: 'Close navigation menu' })).toBeFocused()
})

test('Escape and the close button shut it and return the focus to the menu button', async ({ page }) => {
  await phone(page)
  await open(page)
  await page.keyboard.press('Escape')
  await expectClosed(page)
  await expect(toggle(page)).toBeFocused()
  await open(page)
  await page.getByRole('button', { name: 'Close navigation menu' }).click()
  await expectClosed(page)
  await expect(toggle(page)).toBeFocused()
})

test('tapping the scrim shuts it', async ({ page }) => {
  await phone(page)
  await open(page)
  await page.mouse.click(380, 400) // right of the drawer
  await expectClosed(page)
})

test('a swipe to the left shuts it; a short one springs back', async ({ page }) => {
  await phone(page)
  await open(page)
  const box = await nav(page).boundingBox()
  const y = box.y + box.height / 2
  // short and slow: springs back
  await page.mouse.move(box.width - 40, y)
  await page.mouse.down()
  for (let i = 1; i <= 10; i++) { await page.mouse.move(box.width - 40 - i * 4, y); await page.waitForTimeout(30) }
  await page.mouse.up()
  await page.waitForTimeout(350)
  await expect(nav(page)).toHaveAttribute('data-open', 'true')
  expect((await nav(page).boundingBox()).x).toBe(0)
  // past a third of its width: closes, and the link it started on is not followed
  const url = page.url()
  await page.mouse.move(box.width - 40, y)
  await page.mouse.down()
  for (let i = 1; i <= 10; i++) { await page.mouse.move(box.width - 40 - i * 20, y); await page.waitForTimeout(30) }
  await page.mouse.up()
  await expectClosed(page)
  expect(page.url()).toBe(url)
})

test('widening the window to the sidebar layout closes the drawer', async ({ page }) => {
  await phone(page)
  await open(page)
  await page.setViewportSize({ width: 1200, height: 800 })
  await expect(nav(page)).toHaveAttribute('data-open', 'false')
  await expect(nav(page)).toBeVisible() // now the sidebar
  expect(await page.locator('#main').evaluate((el) => el.inert)).toBe(false)
  await expect(page.getByRole('button', { name: 'Close navigation menu' })).toBeHidden()
})

// Real touch input (Chromium's touch emulation): a horizontal swipe closes the drawer, a vertical one does not.
test.describe('touch', () => {
  test.use({ hasTouch: true, isMobile: true })
  test('swipe left closes; a vertical drag leaves it open', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'touch emulation through CDP')
    await phone(page)
    await open(page)
    const cdp = await page.context().newCDPSession(page)
    const swipe = async (from, to) => {
      const steps = 12
      await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x: from[0], y: from[1] }] })
      for (let i = 1; i <= steps; i++) {
        const x = from[0] + (to[0] - from[0]) * i / steps, y = from[1] + (to[1] - from[1]) * i / steps
        await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ x, y }] })
        await page.waitForTimeout(16)
      }
      await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] })
      await page.waitForTimeout(400)
    }
    await swipe([200, 500], [200, 250]) // vertical: scrolls, stays open
    await expect(nav(page)).toHaveAttribute('data-open', 'true')
    const url = page.url()
    await swipe([280, 400], [40, 410]) // left
    await expectClosed(page)
    expect(page.url()).toBe(url)
  })
})
