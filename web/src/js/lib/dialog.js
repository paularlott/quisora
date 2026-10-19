// Modal dialogs on the native <dialog> element: showModal() gives a real focus trap, inert background, Esc to close
// and top-layer stacking. This module adds focus return and focus-first-control behaviour (clicking outside does nothing).
const openers = new WeakMap()

export function openDialog(id, opener) {
  const d = typeof id === 'string' ? document.getElementById(id) : id
  if (!d || d.open) return d
  openers.set(d, opener || document.activeElement)
  d.showModal()
  // Focus: an element marked data-autofocus, else the first form control, else the dialog's title heading.
  const visible = (el) => el.offsetParent !== null || getComputedStyle(el).position === 'fixed'
  const target = [...d.querySelectorAll('[data-autofocus]')].find(visible) ||
    [...d.querySelectorAll('input:not([type=hidden]):not([disabled]), select, textarea')].find(visible)
  if (target) target.focus()
  return d
}

export function closeDialog(id) {
  const d = typeof id === 'string' ? document.getElementById(id) : id
  if (d && d.open) d.close()
}

// Restore focus to whatever opened the dialog; if that is gone (row deleted) use the page's fallback.
export function restoreFocus(d) {
  const o = openers.get(d)
  openers.delete(d)
  if (o && o.isConnected && typeof o.focus === 'function' && o.offsetParent !== null) { o.focus(); return }
  const fb = document.querySelector('[data-return-focus]') || document.getElementById('main')
  if (fb) fb.focus()
}

// dialogMixin gives an Alpine component dialog helpers usable from templates:
//   <dialog @close="onDialogClose" ...>
// Every dialog closes the same three ways: Escape (the topmost dialog only), its Cancel button and its close icon.
// Clicking outside does nothing, so a stray click never throws away what was typed.
export function dialogMixin() {
  return {
    openDlg(id, opener) { return openDialog(id, opener) },
    closeDlg(id) { closeDialog(id) },
    closeThis(ev) { const d = ev.currentTarget.closest('dialog'); if (d) d.close() },
    onDialogClose(ev) { restoreFocus(ev.currentTarget); if (this.stopWatchEdit) this.stopWatchEdit(); if (this.afterClose) this.afterClose(ev.currentTarget.id) },
  }
}

// Native modal dialogs make the page inert, but Tab can still leave the dialog for the browser UI. Wrap focus at the
// ends so keyboard users stay inside until they close it.
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
document.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Tab') return
  const open = document.querySelectorAll('dialog[open]')
  const d = open[open.length - 1]
  if (!d) return
  const items = [...d.querySelectorAll(FOCUSABLE)].filter((el) => el.offsetParent !== null || getComputedStyle(el).position === 'fixed')
  if (!items.length) return
  const first = items[0]
  const last = items[items.length - 1]
  const active = document.activeElement
  if (ev.shiftKey && (active === first || !d.contains(active))) { ev.preventDefault(); last.focus() }
  else if (!ev.shiftKey && (active === last || !d.contains(active))) { ev.preventDefault(); first.focus() }
})

export default function (Alpine) {
  // Global confirmation dialog (partials/confirm-dialog.html): Alpine.store('confirm').ask({...}) -> Promise<boolean>.
  Alpine.store('confirm', {
    title: '', message: '', detail: '', confirmLabel: 'Confirm', danger: true, requireText: '', typed: '', error: '',
    resolve: null,
    ask(opts) {
      Object.assign(this, { title: 'Are you sure?', message: '', detail: '', confirmLabel: 'Confirm', danger: true, requireText: '', typed: '', error: '' }, opts)
      return new Promise((resolve) => {
        this.resolve = resolve
        openDialog('confirm-dialog', document.activeElement)
      })
    },
    finish(v) {
      const r = this.resolve
      this.resolve = null
      closeDialog('confirm-dialog')
      if (r) r(v)
    },
    get blocked() { return this.requireText !== '' && this.typed.trim() !== this.requireText },
    get confirmClass() { return this.danger ? 'btn btn-danger' : 'btn btn-primary' },
    get needsText() { return this.requireText !== '' },
    get typeLabel() { return 'Type ' + this.requireText + ' to confirm' },
  })
  Alpine.data('confirmDialog', () => ({
    get c() { return Alpine.store('confirm') },
    yes() { if (!this.c.blocked) this.c.finish(true) },
    no() { this.c.finish(false) },
    onClose(ev) { // Escape: resolves false
      if (ev.currentTarget.open) return // a late event of an earlier close, the dialog was opened again meanwhile
      const c = this.c
      if (c.resolve) { const r = c.resolve; c.resolve = null; r(false) }
      restoreFocus(ev.currentTarget)
    },
  }))
}
