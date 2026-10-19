// Six-digit authentication code fields ([data-otp], the "otp-field" partial). One real input — so screen readers
// announce a single field, paste works and the OS can autofill one-time codes — drawn as six boxes. The input keeps
// digits only (at most six), the boxes show which digit comes next, and the form submits itself once all six are in
// (the field's help text says so, WCAG 3.2.2).
const LEN = 6

// sync redraws the boxes for the input's value; call it after setting the value from a script.
export function sync(input) {
  const wrap = input.closest('.otp')
  if (!wrap) return
  const n = input.value.length
  wrap.querySelectorAll('.otp-box').forEach((box, i) => {
    box.classList.toggle('is-filled', i < n)
    box.classList.toggle('is-current', i === Math.min(n, LEN - 1))
  })
}

export default function () {
  // Capture phase: clean the value before Alpine's x-model reads it.
  document.addEventListener('input', (e) => {
    const el = e.target
    if (!(el instanceof HTMLInputElement) || !el.matches('[data-otp]')) return
    const clean = el.value.replace(/\D/g, '').slice(0, LEN)
    if (clean !== el.value) el.value = clean
    sync(el)
    if (clean.length < LEN) { delete el.dataset.submitted; return }
    if (el.dataset.submitted === clean || !el.form) return
    el.dataset.submitted = clean
    // after x-model has stored the value
    setTimeout(() => el.form.requestSubmit(), 0)
  }, true)
  // Values set by scripts (a cleared form, a fresh dialog) don't fire input: re-sync the boxes on focus.
  document.addEventListener('focusin', (e) => {
    const el = e.target
    if (el instanceof HTMLInputElement && el.matches('[data-otp]')) {
      if (el.value.length < LEN) delete el.dataset.submitted
      sync(el)
    }
  })
}
