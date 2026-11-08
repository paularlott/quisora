// fitTabs makes a tab list (.tabs) a grid of chips (.tabs-chips) whenever its tabs would not fit on one row: measured,
// not guessed from the viewport, so it holds for any labels, skin or sidebar. The grid has as many columns as fit
// (each at least MIN_CHIP wide) of those that divide the tabs into full rows (6 tabs: 3 or 2 columns, not 4 and 2).
// It checks again when the space changes.
const MIN_CHIP = 9 // rem

export function fitTabs(el) {
  if (!el) return
  const check = () => {
    el.classList.remove('tabs-chips')
    el.style.gridTemplateColumns = ''
    const tabs = el.querySelectorAll('[role="tab"]')
    const n = tabs.length
    if (n < 2 || tabs[n - 1].offsetTop <= tabs[0].offsetTop + 2) return
    const rem = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16
    const fit = Math.max(1, Math.floor((el.clientWidth + 0.5 * rem) / ((MIN_CHIP + 0.5) * rem))) // 0.5rem gaps
    let cols = 1
    for (let c = Math.min(fit, n - 1); c >= 1; c--) if (n % c === 0) { cols = c; break }
    if (cols === 1 && fit >= 2) cols = Math.min(fit, 2)
    el.classList.add('tabs-chips')
    el.style.gridTemplateColumns = `repeat(${cols}, minmax(0, 1fr))`
  }
  new ResizeObserver(check).observe(el.parentElement)
  check()
}
