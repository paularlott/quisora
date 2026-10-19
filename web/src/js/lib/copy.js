// Copy-to-clipboard button: <button x-data="copyButton" data-copy="value" data-what="client ID">.
import { announce } from './announce.js'

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.className = 'sr-only'
    document.body.appendChild(ta)
    ta.select()
    let ok = false
    try { ok = document.execCommand('copy') } catch { ok = false }
    ta.remove()
    return ok
  }
}

export default function (Alpine) {
  Alpine.data('copyButton', () => ({
    done: false,
    async copy(ev) {
      const el = ev.currentTarget
      const ok = await copyText(el.dataset.copy)
      announce(ok ? 'Copied ' + (el.dataset.what || 'text') + ' to the clipboard.' : 'Could not copy. Select the text and copy it manually.',
        ok ? 'polite' : 'assertive')
      this.done = ok
      if (ok) setTimeout(() => { this.done = false }, 2000)
    },
    get iconCopy() { return !this.done },
  }))
  // Copy the text of a referenced element (used in the secret dialog, where the value is dynamic).
  Alpine.data('copyFrom', () => ({
    done: false,
    async copy(ev) {
      const { source, what } = ev.currentTarget.dataset
      const src = document.getElementById(source)
      const ok = !!src && (await copyText(src.textContent.trim()))
      announce(ok ? 'Copied ' + (what || 'text') + ' to the clipboard.' : 'Could not copy. Select the text and copy it manually.',
        ok ? 'polite' : 'assertive')
      this.done = ok
      if (ok) setTimeout(() => { this.done = false }, 2000)
    },
  }))
}
