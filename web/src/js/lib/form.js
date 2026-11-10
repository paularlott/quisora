// AJAX form controller for modal and inline forms. Compose into a page component with mix():
// state: form (values), errors (message per field), invalid (aria-invalid per field), busy. Errors that belong to no
// field go to an error toast.
// Template contract: each control has id="f-<name>", the error element id="e-<name>" (class field-error, always in
// the DOM and referenced by aria-describedby), and binds :aria-invalid="invalid.<name>".
import { ApiError } from './api.js'
import { announce, dismissToast, toast } from './announce.js'
import { focusWhenShown } from './focus.js'
import { editWatchMixin } from './live.js'
import { mix } from './mix.js'
import { sync as syncOtp } from './otp.js'

export function formMixin() {
  return mix({
    form: {}, errors: {}, invalid: {}, busy: false, codeToast: 0,

    resetForm(values) {
      this.form = { ...values }
      this.clearErrors()
      this.busy = false
    },
    clearErrors() {
      this.errors = {}; this.invalid = {}
      if (this.clearListErrors) this.clearListErrors()
      if (this.codeToast) { dismissToast(this.codeToast); this.codeToast = 0 }
    },

    setErrors(err) {
      if (!(err instanceof ApiError)) err = new ApiError(0, { error: String(err && err.message || err) })
      this.clearErrors()
      const field = this.errorKey ? this.errorKey(err.field) : err.field
      if (this.listError && this.listError(err)) return // shown on a row of a list editor (lib/listfield.js)
      const known = field && document.getElementById('f-' + field)
      if (known && known.matches('[data-otp]')) {
        // A wrong authentication code: the boxes empty and keep focus for the next try, and the message is an error
        // toast (an inline message would resize the step or dialog under the boxes). It goes when the next code is
        // tried, so wrong codes never pile up.
        this.invalid = { [field]: 'true' }
        this.form[field] = ''
        this.codeToast = toast(err.message, 'error')
        this.$nextTick(() => {
          const el = document.getElementById('f-' + field)
          if (!el) return
          delete el.dataset.submitted
          syncOtp(el) // the focus ring goes back to the first box
          el.focus()
        })
      } else if (known) {
        // Field errors stay next to the field (WCAG 3.3.1): message, aria-invalid, focus.
        this.errors = { [field]: err.message }
        this.invalid = { [field]: 'true' }
        focusWhenShown('f-' + field)
        announce(err.message, 'assertive')
      } else {
        // Errors about the whole action (permission, conflict, network, server) are error toasts, which stay until
        // dismissed.
        toast(err.message, 'error')
      }
    },

    // run wraps a submit: sets busy, clears errors, maps failures to inline field errors. Resolves to the result or
    // null when it failed.
    async run(fn) {
      if (this.busy || this.editGone) return null
      this.busy = true
      this.clearErrors()
      try {
        return await fn()
      } catch (e) {
        if (e && e.name === 'AbortError') return null
        this.setErrors(e)
        return null
      } finally {
        this.busy = false
      }
    },
    get busyAttr() { return this.busy ? 'true' : 'false' },
    // Save is off while busy, and when the record being edited was deleted by someone else (see live.js).
    get saveDisabled() { return this.busy || this.editGone },
  }, editWatchMixin())
}

// Helpers for list-valued text areas.
export const lines = (s) => (s || '').split(/[\r\n]+/).map((x) => x.trim()).filter(Boolean)
export const words = (s) => (s || '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)
