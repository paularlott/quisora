// Search-as-you-type picker: an ARIA 1.2 combobox whose results (a listbox) float over the form below it. Type to
// search, Up/Down (and Home/End) move through the results, Enter chooses, Escape closes the list (not the dialog),
// Tab or leaving the field closes it. Each result line shows a label, a detail line and a kind badge (User, Group).
// Markup: the "picker" template partial. Compose with mix():
//   pickerMixin({ search(q) -> Promise<[{ type, id, label, detail, kind }]>, chosen(item), clearOnChoose, removeLast })
//   - search runs 200 ms after typing stops; results whose search started earlier than the latest are dropped
//   - chosen is called with the item; with clearOnChoose the field empties for the next search (e.g. adding several
//     members), otherwise it shows the chosen label and pickChoice holds the item until the text is changed
//   - removeLast (the "picker-chips" partial) is called on Backspace in the empty input, to take back the last chip
const DELAY = 200

export function pickerMixin(cfg) {
  return {
    pickQ: '', picks: [], pickActive: -1, pickOpen: false, pickSeq: 0, pickStatus: '', pickChoice: null, pickMore: false, _pickTimer: null,

    get pickListOpen() { return this.pickOpen && this.picks.length > 0 },
    get pickExpanded() { return this.pickListOpen ? 'true' : 'false' },
    get pickActiveId() { return this.pickActive >= 0 && this.picks[this.pickActive] ? this.picks[this.pickActive].optId : '' },
    get pickOptions() {
      return this.picks.map((p, i) => ({ ...p, index: i, selected: i === this.pickActive ? 'true' : 'false', cls: i === this.pickActive ? 'picker-option is-active' : 'picker-option' }))
    },
    get pickNone() { return this.pickOpen && this.picks.length === 0 && this.pickQ.trim() !== '' },

    resetPicker() {
      clearTimeout(this._pickTimer)
      this.pickSeq++
      Object.assign(this, { pickQ: '', picks: [], pickActive: -1, pickOpen: false, pickStatus: '', pickChoice: null, pickMore: false })
    },
    pickInput() {
      // typing after a choice starts a new search: the earlier choice no longer stands
      if (this.pickChoice && this.pickQ !== this.pickChoice.label) this.pickChoice = null
      clearTimeout(this._pickTimer)
      if (this.pickQ.trim() === '') { this.pickSeq++; this.picks = []; this.closePicks(); return }
      this._pickTimer = setTimeout(() => this.runPickSearch(), DELAY)
    },
    async runPickSearch() {
      const seq = ++this.pickSeq
      const q = this.pickQ.trim()
      try {
        const res = await cfg.search.call(this, q)
        if (seq !== this.pickSeq) return
        const items = Array.isArray(res) ? res : res.items
        this.pickMore = !Array.isArray(res) && !!res.more
        const was = this.pickActive >= 0 && this.picks[this.pickActive] ? this.picks[this.pickActive].key : ''
        this.picks = items.map((p) => ({ ...p, key: p.type + ':' + p.id, optId: 'pick-' + p.type + '-' + p.id }))
        this.pickActive = was ? this.picks.findIndex((p) => p.key === was) : -1 // keep the highlight when still listed
        this.pickOpen = true
        const more = this.pickMore ? ' Type more to narrow the list.' : ''
        this.pickStatus = this.picks.length === 0 ? 'Nothing matches.' : `${this.picks.length} results. Use the up and down arrow keys to move through them.${more}`
      } catch (e) {
        if (seq === this.pickSeq) this.pickStatus = e.message
      }
    },
    closePicks() { this.pickOpen = false; this.pickActive = -1 },
    choosePick(i) {
      const p = this.picks[i]
      if (!p) return
      this.closePicks()
      if (cfg.clearOnChoose) {
        this.pickQ = ''
        this.picks = []
        this.pickChoice = null
      } else {
        this.pickChoice = p
        this.pickQ = p.label
        this.pickStatus = `Selected ${(p.kind || '').toLowerCase()} ${p.label}.`
      }
      cfg.chosen.call(this, p)
    },
    pickKey(ev) {
      const n = this.picks.length
      switch (ev.key) {
        case 'ArrowDown':
          ev.preventDefault()
          if (!this.pickOpen) { if (this.pickQ.trim()) this.pickOpen = true; return }
          if (n) this.pickActive = (this.pickActive + 1) % n
          break
        case 'ArrowUp':
          ev.preventDefault()
          if (this.pickOpen && n) this.pickActive = this.pickActive <= 0 ? n - 1 : this.pickActive - 1
          break
        case 'Home': case 'End':
          if (this.pickOpen && n) { ev.preventDefault(); this.pickActive = ev.key === 'Home' ? 0 : n - 1 }
          break
        case 'Enter':
          if (this.pickOpen) {
            ev.preventDefault()
            if (this.pickActive >= 0) this.choosePick(this.pickActive)
            else if (n === 1) this.choosePick(0)
          } else if (!this.pickChoice) ev.preventDefault() // nothing chosen yet: Enter must not submit the form
          break
        case 'Escape':
          if (this.pickOpen) { ev.preventDefault(); ev.stopPropagation(); this.closePicks() } // the list, not the dialog
          break
        case 'Tab':
          this.closePicks()
          break
        case 'Backspace': // the "picker-chips" partial: the empty input takes back the last chip
          if (cfg.removeLast && this.pickQ === '') { ev.preventDefault(); cfg.removeLast.call(this) }
          break
      }
      if (this.pickOpen && this.pickActive >= 0) {
        this.$nextTick(() => { const el = document.getElementById(this.pickActiveId); if (el) el.scrollIntoView({ block: 'nearest' }) })
      }
    },
    pickClick(ev) { this.choosePick(Number(ev.currentTarget.dataset.index)) },
    pickBlur() { setTimeout(() => this.closePicks(), 120) },
    // A click on the chip box itself (not a chip's button) goes to its input, as in the tag field.
    pickFocus(ev) {
      if (ev.target !== ev.currentTarget) return
      const el = ev.currentTarget.querySelector('input')
      if (el) el.focus()
    },
  }
}
