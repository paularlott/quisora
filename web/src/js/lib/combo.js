// Autocomplete fields (ARIA 1.2 combobox with a listbox popup), several per component. Each field edits form[name]
// while its input shows a label ("English (United Kingdom)" for en-GB). Type to filter, Up/Down (Home/End) move,
// Enter chooses, Escape closes the list (not the dialog), Tab or leaving the field closes it. Markup: the
// "combo-field" template partial; state lives in combo[name] so the templates only read properties (Alpine CSP).
//
//   comboMixin({
//     locale:   { options: () => Promise<[{ value, label, detail }]>, free: true },  // a fixed list; free: typed text is
//                                                                                // kept as the value when nothing matches
//     manager_id: { search: (q) => Promise<[{ value, label, detail }]> },        // looked up as the user types
//   })
// comboSet(name, value, label) fills a field (label looked up in a fixed list when omitted). comboPending(name) is
// true when text was typed that is not a choice (a search field, which only takes chosen values).
import { get } from './api.js'

const DELAY = 200
const MAX = 60

let profileOptionsP = null
// profileOptions loads the languages, time zones and user types the fields offer (cached for the page).
export function profileOptions() {
  if (!profileOptionsP) profileOptionsP = get('/api-internal/account/profile-options').catch((e) => { profileOptionsP = null; throw e })
  return profileOptionsP
}

const zoneLabel = (z) => z.replaceAll('_', ' ')
export const localeSource = { free: true, options: () => profileOptions().then((o) => o.locales.map((l) => ({ value: l.tag, label: l.name, detail: l.tag }))) }
export const zoneSource = { free: true, options: () => profileOptions().then((o) => o.time_zones.map((z) => ({ value: z, label: zoneLabel(z) }))) }
export const userTypeSource = { free: true, options: () => profileOptions().then((o) => o.user_types.map((t) => ({ value: t, label: t }))) }

function blank() {
  return { q: '', open: false, active: -1, items: [], options: [], expanded: 'false', activeId: '', listOpen: false, none: false, status: '', seq: 0, label: '' }
}

export function comboMixin(defs) {
  const combo = {}
  for (const name of Object.keys(defs)) combo[name] = blank()
  return {
    combo, _comboAll: {}, _comboTimers: {},

    _comboDef(name) { return defs[name] },
    _comboSync(name) {
      const c = this.combo[name]
      c.options = c.items.map((it, i) => ({ ...it, key: it.value + '|' + i, optId: `combo-${name}-${i}`, index: i, name,
        selected: i === c.active ? 'true' : 'false', cls: i === c.active ? 'picker-option is-active' : 'picker-option', hasDetail: !!it.detail }))
      c.listOpen = c.open && c.items.length > 0
      c.expanded = c.listOpen ? 'true' : 'false'
      c.activeId = c.active >= 0 && c.items[c.active] ? `combo-${name}-${c.active}` : ''
      c.none = c.open && c.items.length === 0 && c.q.trim() !== ''
    },
    async _comboList(name) {
      if (!this._comboAll[name]) this._comboAll[name] = await defs[name].options()
      return this._comboAll[name]
    },
    // comboSet shows value in the field (and sets form[name]).
    async comboSet(name, value, label) {
      const c = this.combo[name]
      this.form[name] = value || ''
      if (label === undefined && value && defs[name].options) {
        try {
          const hit = (await this._comboList(name)).find((o) => o.value === value)
          label = hit ? hit.label : value
        } catch { label = value }
      }
      Object.assign(c, { q: value ? label || value : '', label: value ? label || value : '', open: false, active: -1, items: [], status: '' })
      this._comboSync(name)
    },
    comboPending(name) {
      const c = this.combo[name]
      return !defs[name].options && c.q.trim() !== '' && c.q !== c.label
    },
    comboInput(ev) {
      const name = ev.target.dataset.combo
      const c = this.combo[name]
      const q = c.q.trim()
      if (q === '') this.form[name] = ''
      clearTimeout(this._comboTimers[name])
      if (defs[name].options) {
        this._comboFilter(name)
      } else {
        if (q === '') { c.items = []; c.open = false; this._comboSync(name); return }
        this._comboTimers[name] = setTimeout(() => this._comboSearch(name), DELAY)
      }
    },
    async _comboFilter(name) {
      const c = this.combo[name]
      const q = c.q.trim().toLowerCase()
      let all
      try { all = await this._comboList(name) } catch (e) { c.status = e.message; return }
      if (defs[name].free) { // an exact name or value is taken as it is typed, a partial one only once chosen
        const exact = all.find((o) => o.label.toLowerCase() === q || o.value.toLowerCase() === q)
        this.form[name] = exact ? exact.value : c.q.trim()
      }
      const starts = [], contains = []
      for (const o of all) {
        const l = o.label.toLowerCase(), v = o.value.toLowerCase()
        if (q === '' || l.startsWith(q) || v.startsWith(q) || l.includes(' (' + q)) starts.push(o)
        else if (l.includes(q) || v.includes(q)) contains.push(o)
      }
      const hits = starts.concat(contains)
      c.items = hits.slice(0, MAX)
      c.open = true
      c.active = -1
      c.status = hits.length === 0 ? 'Nothing matches.' : `${hits.length} results${hits.length > MAX ? `, first ${MAX} shown` : ''}. Use the up and down arrow keys to move through them.`
      this._comboSync(name)
    },
    async _comboSearch(name) {
      const c = this.combo[name]
      const seq = ++c.seq
      try {
        const items = await defs[name].search.call(this, c.q.trim())
        if (seq !== c.seq) return
        c.items = items.slice(0, MAX)
        c.open = true
        c.active = -1
        c.status = items.length === 0 ? 'Nothing matches.' : `${items.length} results. Use the up and down arrow keys to move through them.`
        this._comboSync(name)
      } catch (e) {
        if (seq === c.seq) c.status = e.message
      }
    },
    _comboChoose(name, i) {
      const c = this.combo[name]
      const it = c.items[i]
      if (!it) return
      this.form[name] = it.value
      Object.assign(c, { q: it.label, label: it.label, open: false, active: -1, status: `Selected ${it.label}.` })
      this._comboSync(name)
    },
    comboKey(ev) {
      const name = ev.target.dataset.combo
      const c = this.combo[name]
      const n = c.items.length
      switch (ev.key) {
        case 'ArrowDown':
          ev.preventDefault()
          if (!c.open) { if (defs[name].options) this._comboFilter(name); else if (c.q.trim()) c.open = true; break }
          if (n) c.active = (c.active + 1) % n
          break
        case 'ArrowUp':
          ev.preventDefault()
          if (c.open && n) c.active = c.active <= 0 ? n - 1 : c.active - 1
          break
        case 'Home': case 'End':
          if (c.open && n) { ev.preventDefault(); c.active = ev.key === 'Home' ? 0 : n - 1 }
          break
        case 'Enter':
          if (c.open && (c.active >= 0 || n === 1)) { ev.preventDefault(); this._comboChoose(name, c.active >= 0 ? c.active : 0); return }
          break
        case 'Escape':
          if (c.open) { ev.preventDefault(); ev.stopPropagation(); c.open = false; c.active = -1 } // the list, not the dialog
          break
        case 'Tab':
          c.open = false; c.active = -1
          break
      }
      this._comboSync(name)
      if (c.open && c.active >= 0) {
        this.$nextTick(() => { const el = document.getElementById(c.activeId); if (el) el.scrollIntoView({ block: 'nearest' }) })
      }
    },
    comboClick(ev) {
      const el = ev.currentTarget
      this._comboChoose(el.dataset.combo, Number(el.dataset.index))
    },
    comboBlur(ev) {
      const name = ev.target.dataset.combo
      setTimeout(() => { const c = this.combo[name]; c.open = false; c.active = -1; this._comboSync(name) }, 120)
    },
  }
}
