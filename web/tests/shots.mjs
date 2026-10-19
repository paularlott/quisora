// Takes screenshots of every page in both themes: node tests/shots.mjs [baseURL] [outDir]
// Needs the demo server (go run ./internal/admin/cmd/uidemo) running.
import { chromium } from '@playwright/test'
import { PAGES } from './pages.mjs'

const base = process.argv[2] || 'https://localhost:18443'
const out = process.argv[3] || 'test-results/screenshots'
const only = process.argv[4]

const browser = await chromium.launch()
for (const theme of ['light', 'dark']) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1360, height: 860 }, colorScheme: theme, reducedMotion: 'reduce' })
  const page = await ctx.newPage()
  await page.addInitScript((t) => { try { localStorage.setItem('quisora-theme', t) } catch {} }, theme)
  let as = null
  for (const p of PAGES) {
    if (only && !p.name.includes(only)) continue
    if (p.as !== as) { if (p.as === 'none') await ctx.clearCookies(); else await page.goto(`${base}/__demo/login?as=${p.as}&next=/healthz`); as = p.as }
    await page.goto(base + p.path, { waitUntil: 'load' })
    await page.waitForTimeout(400)
    for (const step of p.steps || []) await step(page)
    await page.screenshot({ path: `${out}/${p.name}-${theme}.png`, fullPage: false })
    console.log('shot', p.name, theme)
  }
  await ctx.close()
}
await browser.close()
