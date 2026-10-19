// Chip editor logic for the "tag-field" partial: a chip list with a text input, used for tags and for application
// roles. Compose into a form component with mix() next to formMixin(). One component may hold several such fields;
// each lives in form.<name> (insertion order while editing, the server sorts them) and the partial marks its root
// with data-chips="<name>" and data-noun="tag" | "role".
//   type and press Enter, comma or space -> the value is added      Backspace in the empty input -> removes the last
//   each chip has a remove button named "Remove <noun> <value>"     errors show inline (#e-<name>) and are announced
// Templates read chips.<name>, hasChips.<name> and bind the input to chipText.<name>.
import { announce } from './announce.js'

// Same rule as the server (internal/model/tags.go).
export const TAG_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,62}[A-Za-z0-9])?$/
export const MAX_TAGS = 50
const FIELDS = ['tags', 'roles']

export function tagError(t, noun = 'tag') {
  return `“${t}” is not a valid ${noun}: use letters, digits and . _ : / - (1–64 characters, starting and ending with a letter or digit).`
}

const plural = (n, noun) => (n === 1 ? `1 ${noun}` : `${n} ${noun}s`)

// fieldOf finds the chip field an event belongs to.
function fieldOf(el) {
  const root = el.closest('[data-chips]')
  return { name: root ? root.dataset.chips : 'tags', noun: root ? root.dataset.noun || 'tag' : 'tag' }
}

export function tagsMixin() {
  return {
    chipText: { tags: '', roles: '' },
    get chips() {
      const out = {}
      for (const k of FIELDS) out[k] = (this.form[k] || []).map((v) => ({ value: v, removeLabel: `Remove ${k === 'roles' ? 'role' : 'tag'} ${v}` }))
      return out
    },
    get hasChips() {
      const out = {}
      for (const k of FIELDS) out[k] = (this.form[k] || []).length > 0
      return out
    },
    // Kept for templates and tests that speak of the tags field alone.
    get tagChips() { return this.chips.tags },
    get hasTagChips() { return this.hasChips.tags },

    setChipError(name, msg) {
      this.errors = { ...this.errors, [name]: msg }
      this.invalid = { ...this.invalid, [name]: 'true' }
      announce(msg, 'assertive')
    },
    clearChipError(name) {
      if (!this.errors[name]) return
      const errs = { ...this.errors }
      const inv = { ...this.invalid }
      delete errs[name]
      delete inv[name]
      this.errors = errs
      this.invalid = inv
    },
    resetChipText() { this.chipText = { tags: '', roles: '' } },

    // Add one value; returns false (and shows the error) when it is not acceptable.
    addChip(name, noun, raw) {
      const t = raw.trim()
      if (!t) return true
      const list = this.form[name] || []
      if (!TAG_RE.test(t)) { this.setChipError(name, tagError(t, noun)); return false }
      if (list.includes(t)) { announce(`${noun === 'role' ? 'Role' : 'Tag'} ${t} is already added.`); return true }
      if (list.length >= MAX_TAGS) { this.setChipError(name, `At most ${MAX_TAGS} ${noun}s are allowed.`); return false }
      this.form[name] = [...list, t]
      this.clearChipError(name)
      announce(`Added ${noun} ${t}. ${plural(this.form[name].length, noun)}.`)
      return true
    },
    // Commit whatever is typed in a field's input; false when it was invalid (the text stays for correction).
    commitChips(name, noun) {
      const parts = (this.chipText[name] || '').split(/[\s,]+/).filter(Boolean)
      for (let i = 0; i < parts.length; i++) {
        if (!this.addChip(name, noun, parts[i])) { this.chipText = { ...this.chipText, [name]: parts.slice(i).join(' ') }; return false }
      }
      this.chipText = { ...this.chipText, [name]: '' }
      return true
    },

    onTagKey(ev) {
      const el = ev.currentTarget
      const { name, noun } = fieldOf(el)
      if (ev.isComposing) return
      if (ev.key === 'Enter') {
        if (el.value.trim() === '') return // an empty field lets Enter submit the form
        ev.preventDefault()
        this.chipText = { ...this.chipText, [name]: el.value }
        this.commitChips(name, noun)
      } else if (ev.key === ',' || ev.key === ' ') {
        ev.preventDefault()
        if (el.value.trim() !== '') { this.chipText = { ...this.chipText, [name]: el.value }; this.commitChips(name, noun) }
      } else if (ev.key === 'Backspace' && el.value === '' && (this.form[name] || []).length > 0) {
        const list = this.form[name]
        const gone = list[list.length - 1]
        this.form[name] = list.slice(0, -1)
        this.clearChipError(name)
        announce(`Removed ${noun} ${gone}. ${plural(this.form[name].length, noun)}.`)
      }
    },
    // Pasted or dropped text with separators becomes several values; the last, unfinished word stays in the input.
    onTagInput(ev) {
      const { name, noun } = fieldOf(ev.currentTarget)
      const v = ev.currentTarget.value
      this.chipText = { ...this.chipText, [name]: v }
      if (this.errors[name]) this.clearChipError(name)
      if (!/[\s,]/.test(v)) return
      const finished = /[\s,]$/.test(v)
      const parts = v.split(/[\s,]+/).filter(Boolean)
      const rest = finished ? '' : parts.pop() || ''
      for (const p of parts) {
        if (!this.addChip(name, noun, p)) { this.chipText = { ...this.chipText, [name]: [p, ...parts.slice(parts.indexOf(p) + 1), rest].join(' ').trim() }; return }
      }
      this.chipText = { ...this.chipText, [name]: rest }
    },
    onTagBlur(ev) {
      const { name, noun } = fieldOf(ev.currentTarget)
      if ((this.chipText[name] || '').trim() !== '') this.commitChips(name, noun)
    },
    removeTag(ev) {
      const { name, noun } = fieldOf(ev.currentTarget)
      const t = ev.currentTarget.dataset.tag
      this.form[name] = (this.form[name] || []).filter((x) => x !== t)
      this.clearChipError(name)
      announce(`Removed ${noun} ${t}. ${plural(this.form[name].length, noun)}.`)
      const el = document.getElementById('f-' + name)
      if (el) el.focus()
    },
    clickTagField(ev) {
      if (ev.target !== ev.currentTarget) return
      const el = document.getElementById('f-' + fieldOf(ev.currentTarget).name)
      if (el) el.focus()
    },
    // Focus the first chip field with an error (else the tags field), e.g. after tagsReady() refused.
    focusTagInput() {
      const name = FIELDS.find((k) => this.errors[k]) || 'tags'
      const el = document.getElementById('f-' + name)
      if (el) el.focus()
    },
    // Call before submitting: folds in the words being typed. False = invalid, do not submit.
    tagsReady() {
      let ok = true
      for (const name of FIELDS) {
        if (!(name in this.form) || (this.chipText[name] || '').trim() === '') continue
        if (!this.commitChips(name, name === 'roles' ? 'role' : 'tag')) ok = false
      }
      return ok
    },
  }
}
