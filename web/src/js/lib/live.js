// Live updates: ONE EventSource per page to /api/v1/events, shared by every component on the page.
// Components subscribe to the record kinds they show; the stream says only "something of this kind changed", and
// they refetch through the normal API. Accessibility rules enforced here:
//   - nothing in this module moves focus;
//   - refreshes wait while a dialog is open or the user is typing in a field (liveRunner);
//   - a polite announcement at most once every 5 s (announceUpdate);
//   - the user can pause live updates (WCAG 2.2.2); the choice is remembered in localStorage;
//   - the stream is closed when the page is hidden/unloaded and re-opened (with a full resync) when it comes back.
import { announce } from './announce.js'
import { get, ApiError } from './api.js'

const KEY = 'quisora-live'
const listeners = new Set() // {kinds: Set|null, fn}
const stateFns = new Set()
let es = null
let timer = null
let attempts = 0
let connected = false
let syncNext = false // the next `ready` must be followed by a full resync (events may have been missed)
let enabled = readPref()

function readPref() { try { return localStorage.getItem(KEY) !== '0' } catch { return true } }
function writePref(v) { try { localStorage.setItem(KEY, v ? '1' : '0') } catch { /* private mode */ } }

function streamUrl() {
  const m = document.querySelector('meta[name="live-org"]')
  return '/api/v1/events' + (m && m.content ? '?org=' + encodeURIComponent(m.content) : '')
}

function emit(ev) {
  for (const l of [...listeners]) {
    if (ev.kind === '*' || !l.kinds || l.kinds.has(ev.kind)) {
      try { l.fn(ev) } catch (e) { console.error(e) }
    }
  }
}

function setConnected(c) {
  if (connected === c) return
  connected = c
  stateFns.forEach((f) => f())
}

function schedule() {
  clearTimeout(timer)
  const delay = Math.min(30000, 1000 * 2 ** Math.min(attempts++, 5)) * (0.75 + Math.random() * 0.5)
  timer = setTimeout(open, delay)
}

function open() {
  if (es || !enabled || listeners.size === 0 || typeof EventSource === 'undefined') return
  es = new EventSource(streamUrl())
  es.addEventListener('ready', () => {
    attempts = 0
    setConnected(true)
    if (syncNext) { syncNext = false; emit({ kind: '*', op: 'resync' }) }
  })
  es.addEventListener('change', (e) => { try { emit(JSON.parse(e.data)) } catch { /* ignore malformed */ } })
  es.addEventListener('resync', () => emit({ kind: '*', op: 'resync' }))
  es.onerror = () => {
    setConnected(false)
    syncNext = true
    // CLOSED = the server refused (HTTP error): reconnect ourselves with backoff. Otherwise the browser retries.
    if (es && es.readyState === EventSource.CLOSED) { es.close(); es = null; schedule() }
  }
}

function close() {
  clearTimeout(timer)
  if (es) { es.close(); es = null }
  syncNext = true
  setConnected(false)
}

// subscribe(['user'], fn) -> unsubscribe. fn receives {kind, id, op}; a resync arrives as {kind: '*', op: 'resync'}.
export function subscribe(kinds, fn) {
  const l = { kinds: kinds && kinds.length ? new Set(kinds) : null, fn }
  listeners.add(l)
  open()
  stateFns.forEach((f) => f())
  return () => { listeners.delete(l); if (listeners.size === 0) close(); stateFns.forEach((f) => f()) }
}

export const isLive = () => enabled
export const isConnected = () => connected
// isWatching: something on this page shows live data (a page with none never connects)
export const isWatching = () => listeners.size > 0
export function setLive(v) {
  enabled = !!v
  writePref(enabled)
  if (enabled) { syncNext = true; open() } else close()
  stateFns.forEach((f) => f())
}
export function onLiveState(fn) { stateFns.add(fn); return () => stateFns.delete(fn) }

window.addEventListener('pagehide', () => { clearTimeout(timer); if (es) { es.close(); es = null } connected = false; syncNext = true })
window.addEventListener('pageshow', (e) => { if (e.persisted) open() })

// ---- idle rules ----------------------------------------------------------------------------------------------
let lastInput = 0
document.addEventListener('input', () => { lastInput = Date.now() }, true)

export const dialogOpen = () => !!document.querySelector('dialog[open]')
export function typingNow() {
  const a = document.activeElement
  return !!a && a.matches && a.matches('input:not([type=checkbox]):not([type=radio]), textarea') && Date.now() - lastInput < 2000
}
export const busyNow = () => dialogOpen() || typingNow()

// liveRunner(fn): trigger() runs fn ~300 ms after the last trigger, but only while the page is idle (no dialog open, no
// typing); otherwise it keeps waiting and runs once the page is idle again.
export function liveRunner(fn, wait = 300) {
  let t = null
  const tick = () => { t = null; if (busyNow()) { t = setTimeout(tick, 500); return } fn() }
  return {
    trigger() { clearTimeout(t); t = setTimeout(tick, wait) },
    cancel() { clearTimeout(t); t = null },
  }
}

// A polite announcement at most once every 5 s.
let lastSpoken = 0
export function announceUpdate(text) {
  const n = Date.now()
  if (n - lastSpoken < 5000) return
  lastSpoken = n
  announce(text)
}

// Briefly tint changed table rows (a single fade; plain tint under prefers-reduced-motion; never flashes).
export function flashRows(rows) {
  for (const r of rows) {
    r.classList.add('row-live')
    setTimeout(() => r.classList.remove('row-live'), 2600)
  }
}

// fetch that reports a missing record as null.
export async function getOrNull(url) {
  try { return await get(url) } catch (e) { if (e instanceof ApiError && e.status === 404) return null; throw e }
}

// Watch the record open in an edit dialog. When it changes elsewhere a non-modal notice appears inside the dialog (a
// status region, focus stays put); when it is deleted the notice says so and Save is disabled (saveDisabled).
export const CHANGED_TEXT = 'This was changed by someone else — saving will show the latest version.'
export const DELETED_TEXT = 'This was deleted by someone else, so it can no longer be saved.'

export function editWatchMixin() {
  return {
    editNotice: '', editGone: false, _ew: null,
    get hasEditNotice() { return this.editNotice !== '' },
    // watchEdit({kinds, record, fetchOne}) — fetchOne() resolves to the current record or null when it is gone.
    watchEdit({ kinds, record, fetchOne }) {
      this.stopWatchEdit()
      this.editNotice = ''
      this.editGone = false
      const sig = (r) => (r ? String(r.updated || '') : null)
      const base = sig(record)
      let t = null
      const check = async () => {
        try {
          const cur = await fetchOne()
          if (cur === null) { this.editGone = true; this.editNotice = DELETED_TEXT; return }
          if (sig(cur) !== base) this.editNotice = CHANGED_TEXT
        } catch { /* offline: say nothing */ }
      }
      const un = subscribe(kinds, () => { clearTimeout(t); t = setTimeout(check, 300) })
      this._ew = () => { clearTimeout(t); un() }
    },
    stopWatchEdit() {
      if (this._ew) { this._ew(); this._ew = null }
      this.editNotice = ''
      this.editGone = false
    },
  }
}

export default function (Alpine) {
  // The "Live updates" pause switch (WCAG 2.2.2).
  Alpine.data('liveSwitch', () => ({
    on: isLive(), online: isConnected(), watching: isWatching(),
    init() {
      const sync = () => { this.on = isLive(); this.online = isConnected(); this.watching = isWatching() }
      onLiveState(sync)
      queueMicrotask(sync) // components that subscribe start after the header
    },
    flip() { setLive(!this.on) },
    get paused() { return !this.on },
    get pressed() { return this.on ? 'false' : 'true' },
    get btnClass() { return this.on ? 'live-btn' : 'live-btn is-paused' },
    get titleText() { return this.on ? 'Pause live updates' : 'Live updates paused: click to resume' },
    // For screen readers (the button is an icon). On a page with nothing live (the account page) there is no
    // connection to report: just say it is on.
    get stateText() { return !this.on ? 'Paused' : !this.watching ? 'On' : this.online ? 'Connected' : 'Connecting…' },
  }))
}
