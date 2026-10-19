// WCAG 2.0/2.1/2.2 A+AA audit with axe-core on every page, in both themes, with each dialog open, plus a contrast
// pass against the worst-case backdrop colours. Zero violations required.
import { test, expect } from '@playwright/test'
import { PAGES } from './pages.mjs'
import { axe, fmt, flatBackdrop, setTheme, signIn, WORST } from './helpers.mjs'

for (const theme of ['light', 'dark']) {
  test.describe(`axe ${theme}`, () => {
    for (const p of PAGES) {
      test(`${p.name}`, async ({ page }) => {
        await setTheme(page, theme)
        await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' })
        await signIn(page, p.as)
        await page.goto(p.path, { waitUntil: 'load' })
        for (const step of p.steps || []) await step(page)
        await page.waitForTimeout(500)
        expect(await page.locator('html').getAttribute('data-theme')).toBe(theme)

        // 1) every rule against the real page
        const res = await axe(page)
        expect(res.violations.length, fmt(res.violations)).toBe(0)

        // 2) colour contrast against each worst-case flat backdrop
        for (const c of WORST[theme]) {
          await flatBackdrop(page, c)
          const r = await axe(page, { rules: ['color-contrast'] })
          expect(r.violations.length, `backdrop ${c}\n` + fmt(r.violations)).toBe(0)
        }
      })
    }
  })
}
