import AxeBuilder from '@axe-core/playwright'

export const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

// Worst-case backdrops under the glass: the darkest aurora colour in the light theme (dark text suffers) and the
// brightest in the dark theme (light text suffers), plus a darker light-theme case for the dialog scrim.
export const WORST = {
  light: ['#6366f1', '#2f3380'],
  dark: ['#be185d', '#0e7490'],
}

export async function signIn(page, as) {
  if (as === 'none') { await page.context().clearCookies(); return }
  await page.goto(`/__demo/login?as=${as}&next=/healthz`)
}

export async function setTheme(page, theme) {
  await page.addInitScript((t) => { try { localStorage.setItem('quisora-theme', t) } catch {} }, theme)
}

export function fmt(violations) {
  return violations.map((v) => `${v.id} (${v.impact}): ${v.help}\n` + v.nodes.slice(0, 6).map((n) => `   ${n.target.join(' ')} -- ${(n.failureSummary || '').split('\n').slice(0, 3).join(' | ')}`).join('\n')).join('\n')
}

export async function axe(page, { rules, include } = {}) {
  let b = new AxeBuilder({ page }).withTags(WCAG_TAGS)
  if (rules) b = b.withRules(rules)
  if (include) b = b.include(include)
  return b.analyze()
}

// Replace the animated backdrop by a flat colour so axe can compute contrast against a known worst case.
export async function flatBackdrop(page, color) {
  // CSSOM writes are allowed under the page's strict CSP (inline <style> is not)
  await page.evaluate((c) => {
    for (const el of document.querySelectorAll('.aurora')) el.style.setProperty('display', 'none', 'important')
    for (const el of [document.documentElement, document.body]) el.style.setProperty('background', c, 'important')
  }, color)
}

// Call the management API from inside a page (session cookie + CSRF token), as the UI does.
export async function apiCall(page, method, path, body) {
  return page.evaluate(async ([method, path, body]) => {
    const csrf = document.querySelector('meta[name="csrf-token"]').content
    const r = await fetch(path, { method, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-CSRF-Token': csrf, 'Api-Version': '1' }, body: body === undefined ? undefined : JSON.stringify(body) })
    const text = await r.text()
    if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${text}`)
    return text ? JSON.parse(text) : null
  }, [method, path, body])
}

export const uniq = (p) => p + Date.now().toString(36) + Math.floor(Math.random() * 1000).toString(36)
