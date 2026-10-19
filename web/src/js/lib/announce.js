// Live-region announcements and toasts. The regions are rendered by the base layout (partials/toasts.html) so they
// exist before anything is announced: a polite status region (toasts and notices) and an assertive alert region.
let seq = 0

// While a modal <dialog> is open the rest of the page is inert (invisible to screen readers), so announcements must
// go to a live region inside the topmost open dialog; otherwise to the page-level regions.
function region(mode) {
  const open = document.querySelectorAll('dialog[open]')
  const d = open[open.length - 1]
  const inDialog = d && d.querySelector(`[data-live="${mode}"]`)
  return inDialog || document.getElementById(mode === 'assertive' ? 'live-assertive' : 'live-polite')
}

// announce speaks a message without showing it (e.g. "12 results"). mode: 'polite' | 'assertive'.
export function announce(message, mode = 'polite') {
  const el = region(mode === 'assertive' ? 'assertive' : 'polite')
  if (!el) return
  el.textContent = ''
  // a tick later so repeated identical messages are announced again
  setTimeout(() => { el.textContent = message }, 30)
}

// placeToasts keeps the toast stack where it can be seen and used: inside the topmost open modal <dialog> (which sits
// in the top layer and makes the rest of the page inert), else at the end of <body>.
function placeToasts() {
  const stack = document.querySelector('.toasts')
  if (!stack) return
  const open = document.querySelectorAll('dialog[open]')
  const host = open.length ? open[open.length - 1] : document.body
  if (stack.parentElement !== host) host.append(stack)
}

export default function (Alpine) {
  // follow dialogs as they close (a dialog opening is handled when a toast is pushed)
  document.addEventListener('close', () => setTimeout(placeToasts, 0), true)
  Alpine.store('toasts', {
    items: [],
    // Success toasts disappear after a few seconds; error toasts stay until dismissed.
    push(message, kind = 'success') {
      placeToasts()
      const t = { id: ++seq, message, kind }
      this.items.push(t)
      if (document.querySelector('dialog[open]')) announce(message, kind === 'error' ? 'assertive' : 'polite')
      if (kind !== 'error') setTimeout(() => this.dismissId(t.id), 6000)
      return t
    },
    dismissId(id) { this.items = this.items.filter((t) => t.id !== id) },
    get polite() { return this.items.filter((t) => t.kind !== 'error') },
    get errors() { return this.items.filter((t) => t.kind === 'error') },
  })
  Alpine.data('toasts', () => ({
    get polite() { return Alpine.store('toasts').polite },
    get errors() { return Alpine.store('toasts').errors },
    dismiss(ev) { Alpine.store('toasts').dismissId(Number(ev.currentTarget.dataset.id)) },
  }))
}

// toast shows a message and returns its id (0 when there is no toast stack and it was only announced).
export function toast(message, kind = 'success') {
  const s = window.Alpine && window.Alpine.store('toasts')
  if (s) return s.push(message, kind).id
  announce(message, kind === 'error' ? 'assertive' : 'polite')
  return 0
}

export function dismissToast(id) {
  const s = window.Alpine && window.Alpine.store('toasts')
  if (s && id) s.dismissId(id)
}
