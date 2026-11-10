// App shell behaviour: the navigation drawer on small screens and the user menu disclosure.
//
// On small screens (layout.css) the navigation is a drawer over the page. Open, it holds the focus like a dialog: the
// rest of the page is inert and does not scroll, Tab wraps inside it, and Escape, the scrim or its close button shut
// it and return the focus to the menu button. It can also be swiped back to the left. On wider screens it is the
// sidebar and none of this applies.

import { focusWhenShown } from './focus.js'

const NARROW = '(max-width: 47.99rem)'

// The parts of the page outside the drawer, made inert while it is open (the live regions stay live).
const PAGE = ['.skip-link', '.app-header', '#main', '.app-footer']

function setPageInert(on) {
  for (const sel of PAGE) {
    const el = document.querySelector(sel)
    if (el) el.inert = on
  }
  document.documentElement.classList.toggle('nav-locked', on)
}

const FOCUSABLE = 'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'

export default function (Alpine) {
  Alpine.data('shell', () => ({
    navOpen: false, userOpen: false,
    init() {
      const mq = window.matchMedia(NARROW)
      mq.addEventListener('change', () => { if (!mq.matches) this.closeNav(false) })
      // a page restored from the back/forward cache comes back with the drawer shut
      window.addEventListener('pageshow', (ev) => { if (ev.persisted) this.closeNav(false) })
      if (this.$refs.nav) {
        swipeToClose(this.$refs.nav, this.$refs.navScrim, () => this.closeNav())
        revealCurrent(this.$refs.nav)
      }
    },
    openNav() {
      if (this.navOpen || !window.matchMedia(NARROW).matches) return
      this.navOpen = true
      this.userOpen = false
      setPageInert(true)
      this.$nextTick(() => revealCurrent(this.$refs.nav))
      focusWhenShown(() => this.$refs.navClose)
    },
    // closeNav(false) leaves the focus where it is (the window widened, or the page came back from the cache).
    closeNav(restoreFocus) {
      if (!this.navOpen) return
      this.navOpen = false
      setPageInert(false)
      if (restoreFocus !== false && this.$refs.navToggle) this.$refs.navToggle.focus()
    },
    // Tab and Shift+Tab wrap inside the open drawer instead of leaving it for the browser's own controls.
    trapNav(ev) {
      if (!this.navOpen) return
      const items = [...this.$refs.nav.querySelectorAll(FOCUSABLE)].filter((el) => el.offsetParent !== null)
      if (items.length === 0) return
      const first = items[0], last = items[items.length - 1]
      if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus() }
      else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus() }
    },
    onEscape() {
      if (this.navOpen) this.closeNav()
      else this.escUser()
    },
    toggleUser() { this.userOpen = !this.userOpen },
    closeUser() { this.userOpen = false },
    escUser() {
      if (!this.userOpen) return
      this.userOpen = false
      const b = this.$refs.userButton
      if (b) b.focus()
    },
    get navAttr() { return this.navOpen ? 'true' : 'false' },
    get navExpanded() { return this.navOpen ? 'true' : 'false' },
    get userExpanded() { return this.userOpen ? 'true' : 'false' },
  }))
}

// revealCurrent scrolls the navigation's list, when it scrolls at all, so the current page's link is in view: a link
// low in a long list (the sidebar in a short window, or the drawer) is not left out of sight after following it. The
// list is set directly, without moving the page or animating.
function revealCurrent(nav) {
  const list = nav.querySelector('.nav-scroll')
  const link = nav.querySelector('[aria-current="page"]')
  if (!list || !link || list.scrollHeight <= list.clientHeight) return
  const box = list.getBoundingClientRect(), r = link.getBoundingClientRect()
  const pad = parseFloat(getComputedStyle(list).scrollPaddingTop) || 0
  if (r.top >= box.top + pad && r.bottom <= box.bottom - pad) return
  list.scrollTop += r.top - box.top - (list.clientHeight - r.height) / 2
}

// swipeToClose lets the open drawer be swiped back to the left, from the drawer or the scrim: it follows the finger
// (and the scrim fades with it), then closes when let go past a third of its width or flicked, and springs back
// otherwise. A move that starts vertical is left to scrolling the drawer (touch-action: pan-y), and one to the right
// is ignored.
function swipeToClose(nav, scrim, close) {
  let id = null, x0 = 0, y0 = 0, t0 = 0, dx = 0, decided = false, dragging = false
  const surfaces = [nav, scrim].filter(Boolean)

  const reset = () => {
    for (const el of surfaces) el.classList.remove('is-dragging')
    nav.style.removeProperty('--nav-drag')
    if (scrim) scrim.style.removeProperty('--nav-drag-ratio')
    id = null; decided = false; dragging = false; dx = 0
  }
  const down = (ev) => {
    if (nav.dataset.open !== 'true' || id !== null || ev.button > 0) return
    id = ev.pointerId; x0 = ev.clientX; y0 = ev.clientY; t0 = ev.timeStamp
  }
  const move = (ev) => {
    if (ev.pointerId !== id) return
    const mx = ev.clientX - x0, my = ev.clientY - y0
    if (!decided) {
      if (Math.abs(mx) < 8 && Math.abs(my) < 8) return
      decided = true
      dragging = mx < 0 && Math.abs(mx) > Math.abs(my)
      if (!dragging) { id = null; decided = false; return }
      for (const el of surfaces) el.classList.add('is-dragging')
    }
    dx = Math.min(0, mx)
    nav.style.setProperty('--nav-drag', dx + 'px')
    if (scrim) scrim.style.setProperty('--nav-drag-ratio', String(Math.min(1, -dx / nav.offsetWidth)))
  }
  const up = (ev) => {
    if (ev.pointerId !== id) return
    if (dragging) {
      // a drag is not a tap: swallow the click it would end with (a link it started on, or the scrim)
      const swallow = (e) => { e.preventDefault(); e.stopPropagation() }
      window.addEventListener('click', swallow, { capture: true, once: true })
      setTimeout(() => window.removeEventListener('click', swallow, { capture: true }), 0)
      const speed = dx / Math.max(1, ev.timeStamp - t0) // px per ms; negative is to the left
      const shut = dx < -nav.offsetWidth / 3 || speed < -0.5
      reset() // springs back from where it is, or (closing) slides on out
      if (shut) close()
      return
    }
    reset()
  }
  for (const el of surfaces) el.addEventListener('pointerdown', down)
  // with a mouse, dragging a link would start the browser's link drag and cancel the swipe
  nav.addEventListener('dragstart', (ev) => { if (nav.dataset.open === 'true') ev.preventDefault() })
  window.addEventListener('pointermove', move, { passive: true })
  window.addEventListener('pointerup', up)
  window.addEventListener('pointercancel', (ev) => { if (ev.pointerId === id) reset() })
}
