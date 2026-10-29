// Server-side searchable, sortable, paged list. Compose into a page component with mix():
//   Alpine.data('adminUsers', () => mix(tableMixin(), formMixin(), {...}))
// Config comes from data-* attributes on the component root (CSP build: no inline objects):
//   data-api (list URL)  data-sort (default sort)  data-desc (1 = descending)  data-noun ("users")
//   data-live (space separated record kinds whose changes refresh the list)  data-live-text (announcement)
//   data-search (id of the search input, when it is not list-search)
import { get, qs } from './api.js'
import { announce } from './announce.js'
import { subscribe, liveRunner, announceUpdate, flashRows } from './live.js'

export function tableMixin() {
  return {
    items: [], total: 0, loading: true, loadError: '', q: '', sort: '', desc: false, offset: 0, limit: 10,
    extra: {}, scope: {}, apiUrl: '', noun: 'items', _timer: null, _seq: 0, _firstLoad: true,
    _root: null, _lastRes: '', _sigs: null, _live: null, _unlive: null, liveText: '',

    initTable() {
      const d = this.$el.dataset
      this.apiUrl = d.api
      this.noun = d.noun || 'items'
      this.sort = d.sort || ''
      this.desc = d.desc === '1'
      this._root = this.$el
      if (d.live) this.watchLive(d.live.split(/\s+/), d.liveText)
      return this.load()
    },
    transform(item) { return item },

    // load(announceResult, quiet). quiet = a live refresh: no loading state, errors ignored, nothing re-rendered when
    // the server's answer is unchanged, focus and scroll kept, changed rows tinted and a polite note spoken.
    async load(announceResult = false, quiet = false) {
      const seq = ++this._seq
      if (!quiet) { this.loading = true; this.loadError = '' }
      try {
        const res = await get(this.apiUrl + qs({ q: this.q, sort: this.sort, desc: this.desc, offset: this.offset, limit: this.limit, ...this.scope, ...this.extra }))
        if (seq !== this._seq) return
        // Walked past the end (e.g. after deleting the last row of the last page): step back.
        if (res.items.length === 0 && res.total > 0 && this.offset > 0) {
          this.offset = Math.max(0, (Math.ceil(res.total / this.limit) - 1) * this.limit)
          return this.load(false, quiet)
        }
        const raw = JSON.stringify(res)
        if (quiet && raw === this._lastRes) return
        const prev = this._sigs
        this._lastRes = raw
        this._sigs = new Map(res.items.map((i) => [i.id, JSON.stringify(i)]))
        const keep = quiet ? this.focusMark() : null
        this.items = res.items.map((i) => this.transform(i))
        this.total = res.total
        if (this.afterLoad) this.afterLoad(res)
        this.loading = false
        this.loadError = ''
        if (announceResult === true) announce(this.statusText)
        this._firstLoad = false
        if (quiet && prev) this.afterLive(prev, res, keep)
      } catch (e) {
        if (seq !== this._seq) return
        if (quiet) return
        this.loadError = e.message
        announce(e.message, 'assertive')
      } finally {
        if (seq === this._seq && !quiet) this.loading = false
      }
    },

    // ---- live updates ----
    watchLive(kinds, text) {
      this.liveText = text || (this.noun.charAt(0).toUpperCase() + this.noun.slice(1) + ' list updated')
      this._live = liveRunner(() => this.load(false, true))
      this._unlive = subscribe(kinds, () => this._live.trigger())
    },
    // Remember which control had focus so it can be given back if re-rendering rebuilt it.
    focusMark() {
      const a = document.activeElement
      if (!a || !this._root || !this._root.contains(a) || !a.closest('tbody')) return null
      return { id: a.dataset.id || '', label: a.getAttribute('aria-label') || '', href: a.getAttribute('href') || '', tag: a.tagName }
    },
    afterLive(prev, res, keep) {
      const changed = new Set()
      for (const i of res.items) if (prev.get(i.id) !== this._sigs.get(i.id)) changed.add(i.id)
      this.$nextTick(() => {
        if (keep && (document.activeElement === document.body || !document.activeElement)) {
          const cands = [...this._root.querySelectorAll('tbody ' + (keep.tag === 'A' ? 'a' : 'button'))]
          const el = cands.find((c) => (keep.id && c.dataset.id === keep.id && c.getAttribute('aria-label') === keep.label) || (keep.href && c.getAttribute('href') === keep.href))
          if (el) el.focus({ preventScroll: true })
        }
        const body = this._root && this._root.querySelector('table.table > tbody')
        if (body && changed.size) {
          const trs = [...body.children].filter((c) => c.tagName === 'TR')
          flashRows(res.items.map((it, n) => (changed.has(it.id) ? trs[n] : null)).filter(Boolean))
        }
      })
      announceUpdate(this.liveText)
    },

    onSearch() {
      clearTimeout(this._timer)
      this._timer = setTimeout(() => { this.offset = 0; this.load(true) }, 250)
    },
    clearSearch() {
      this.q = ''
      this.offset = 0
      this.load(true)
      const i = document.getElementById((this._root && this._root.dataset.search) || 'list-search')
      if (i) i.focus()
    },
    sortBy(ev) {
      const key = ev.currentTarget.dataset.key
      if (this.sort === key) this.desc = !this.desc
      else { this.sort = key; this.desc = false }
      this.offset = 0
      this.load(true)
    },
    next() { this.offset += this.limit; this.load(true) },
    prev() { this.offset = Math.max(0, this.offset - this.limit); this.load(true) },
    setLimit(ev) { this.limit = Number(ev.currentTarget.value); this.offset = 0; this.load(true) },
    setFilter(ev) {
      const el = ev.currentTarget
      this.extra = { ...this.extra, [el.dataset.filter]: el.value }
      this.offset = 0
      this.load(true)
    },
    rowFromEvent(ev) {
      const id = ev.currentTarget.dataset.id
      return this.items.find((i) => i.id === id)
    },

    // aria-sort per column: <th :aria-sort="sortState.name">
    get sortState() {
      const m = {}
      if (this.sort) m[this.sort] = this.desc ? 'descending' : 'ascending'
      return m
    },
    get hasItems() { return this.items.length > 0 },
    get showSkeleton() { return this.loading && this.items.length === 0 && !this.loadError },
    get filtered() { return this.q !== '' || Object.values(this.extra).some((v) => v !== '' && v != null) },
    get showEmpty() { return !this.loading && !this.loadError && this.total === 0 && !this.filtered },
    get showNoResults() { return !this.loading && !this.loadError && this.total === 0 && this.filtered },
    get showTable() { return this.items.length > 0 },
    get hasQuery() { return this.q !== '' },
    get from() { return this.total === 0 ? 0 : this.offset + 1 },
    get to() { return this.offset + this.items.length },
    get hasPrev() { return this.offset > 0 },
    get hasNext() { return this.offset + this.limit < this.total },
    get noPrev() { return this.offset <= 0 },
    get noNext() { return this.offset + this.limit >= this.total },
    get showPager() { return this.total > 0 },
    get summary() { return 'Showing ' + this.from + '–' + this.to + ' of ' + this.total },
    get pageLabel() { return 'Page ' + (Math.floor(this.offset / this.limit) + 1) + ' of ' + Math.max(1, Math.ceil(this.total / this.limit)) },
    get statusText() {
      if (this.loading) return 'Loading ' + this.noun + '…'
      if (this.total === 0) return this.q ? 'No ' + this.noun + ' match “' + this.q + '”.' : 'No ' + this.noun + '.'
      return this.total + ' ' + this.noun + (this.q ? ' match “' + this.q + '”' : '') + '. ' + this.pageLabel + '.'
    },
    get busyAttr() { return this.loading ? 'true' : 'false' },
  }
}
