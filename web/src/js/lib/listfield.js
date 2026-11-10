// List editor logic for the "list-field" partial: one value per row (a text input plus a delete button), an Add button,
// Enter in a row adds a row below it. Compose into a form component with mix() next to formMixin(). A list lives in
// form.<name> as an array of rows; build them with listRows(values) and read them back with listValues(rows).
//   row = { id, value, label, removeLabel, inputId, errId, error, invalid }
//   - a required list always shows at least one (possibly empty) row; an optional one (the partial's "optional",
//     listRows(values, item, true)) starts with none and shows just its Add button; empty rows are ignored on save
//   - each row's error is shown under the row (aria-invalid + aria-describedby); setListError maps a server message
//     that starts with the offending value to its row
//   - removing a row moves focus to the previous row (or the next, or the Add button when nothing is left)
// The partial passes the list name and the item name ("Redirect URI") through data-list / data-item on the fieldset.
import { announce } from './announce.js'
import { focusWhenShown } from './focus.js'

let seq = 0

const trimmed = (s) => (s || '').trim()

function describe(rows, item) {
  rows.forEach((r, i) => {
    r.label = `${item} ${i + 1}`
    r.removeLabel = trimmed(r.value) ? 'Remove ' + trimmed(r.value) : `Remove row ${i + 1}`
  })
  return rows
}

// Rows for a list of values (one empty row when there are none, unless optional). item is the singular name, e.g.
// "Redirect URI".
export function listRows(values, item, optional = false) {
  const rows = (values || []).map((v) => newRow(v))
  if (rows.length === 0 && !optional) rows.push(newRow(''))
  return describe(rows, item)
}

function newRow(value) {
  const id = ++seq
  return { id, value, label: '', removeLabel: '', inputId: 'f-row-' + id, errId: 'e-row-' + id, error: '', invalid: undefined }
}

// The non-empty, trimmed values of a list of rows, without duplicates.
export function listValues(rows) {
  const out = []
  for (const r of rows || []) {
    const v = trimmed(r.value)
    if (v && !out.includes(v)) out.push(v)
  }
  return out
}

export function listFieldMixin() {
  return {
    // Which form list does this event belong to, and where is the row?
    _listOf(el) {
      const set = el.closest('[data-list]')
      const name = set.dataset.list
      const rows = this.form[name]
      return { name, item: set.dataset.item, rows, at: rows.findIndex((r) => r.id === Number(el.dataset.row)), set }
    },
    _focusRow(row) { focusWhenShown(() => document.getElementById(row.inputId)) },

    listInput(ev) {
      const { rows, at, item } = this._listOf(ev.currentTarget)
      if (at < 0) return
      rows[at].value = ev.currentTarget.value
      if (rows[at].error) { rows[at].error = ''; rows[at].invalid = undefined }
      describe(rows, item)
    },
    // Add an empty row after index `after` (the end by default) and focus it.
    _listInsert(name, item, after) {
      const rows = this.form[name]
      const row = newRow('')
      const at = after === undefined ? rows.length : after + 1
      rows.splice(at, 0, row)
      describe(rows, item)
      this._focusRow(row)
      announce(`Added row ${at + 1} to ${item} list. ${rows.length} rows.`)
    },
    listAdd(ev) {
      const set = ev.currentTarget.closest('[data-list]')
      this._listInsert(set.dataset.list, set.dataset.item)
    },
    listEnter(ev) {
      if (ev.isComposing) return
      ev.preventDefault() // Enter in a row never submits the form
      const { name, item, rows, at } = this._listOf(ev.currentTarget)
      if (at < 0 || trimmed(rows[at].value) === '') return
      this._listInsert(name, item, at)
    },
    listRemove(ev) {
      const { name, item, rows, at, set } = this._listOf(ev.currentTarget)
      if (at < 0) return
      const gone = trimmed(rows[at].value) || `row ${at + 1}`
      rows.splice(at, 1)
      let focus = rows[at - 1] || rows[at]
      if (rows.length === 0 && !set.hasAttribute('data-optional')) rows.push(newRow(''))
      describe(rows, item)
      if (focus) this._focusRow(focus)
      else focusWhenShown(() => set.querySelector('[data-list-add]'))
      const none = rows.length === 0 || (rows.length === 1 && trimmed(rows[0].value) === '')
      announce(`Removed ${gone}. ${none ? 'No entries' : rows.length + ' rows'}.`)
    },

    // Show a server message on the row it is about: the message starts with the offending value. Returns false when
    // no row matches (the caller shows it on the list as a whole).
    setListError(name, message) {
      let hit = null
      for (const r of this.form[name] || []) {
        const v = trimmed(r.value)
        if (v && message.startsWith(v + ' ') && (!hit || v.length > trimmed(hit.value).length)) hit = r
      }
      if (!hit) return false
      hit.error = message
      hit.invalid = 'true'
      this._focusRow(hit)
      announce(message, 'assertive')
      return true
    },
    // Put one row's own error (for client-side checks) and focus it.
    setRowError(row, message) {
      row.error = message
      row.invalid = 'true'
    },
    clearListErrors() {
      for (const v of Object.values(this.form)) {
        if (Array.isArray(v)) for (const r of v) if (r && typeof r === 'object' && 'errId' in r) { r.error = ''; r.invalid = undefined }
      }
    },
  }
}
