// Live updates (the admin console): the server's change stream, /api/events, shared by every component on the page
// and by every tab of the browser showing the same organization. Components subscribe to the record kinds they show;
// the stream says only "something of this kind changed", and they refetch through the normal API.
//
// One connection per browser per stream URL: a tab that wants live updates asks for a Web Lock named after the URL;
// the tab holding it opens the EventSource and forwards what it receives (changes, resyncs, `ended`, and whether it
// is connected) on a BroadcastChannel of the same name. The other tabs listen there and do not connect. When the
// holder goes (closed, hidden into the back/forward cache, paused, or nothing on it live any more) it releases the
// lock and a waiting tab takes over, starting with a resync. Without Web Locks or BroadcastChannel each tab has its
// own connection.
//
// Accessibility rules enforced here:
//   - nothing in this module moves focus;
//   - refreshes wait while a dialog is open or the user is typing in a field (liveRunner);
//   - a polite announcement at most once every 5 s (announceUpdate);
//   - the user can pause live updates (WCAG 2.2.2); the choice is remembered in localStorage, for every tab.
import { announce } from './announce.js'
import { get, ApiError } from './api.js'

const KEY = 'quisora-live'
const RESYNC = { kind: '*', op: 'resync' }
const shared = typeof BroadcastChannel !== 'undefined' && !!(navigator.locks && navigator.locks.request)
const listeners = new Set() // {kinds: Set|null, fn}
const stateFns = new Set()
let enabled = readPref()
let connected = false
// the holder's connection (every tab's, without sharing)
let es = null
let timer = null
let attempts = 0
let syncNext = false // the next `ready` (a follower: the next "connected") must bring a full resync
// sharing between tabs
let channel = null
let lockCtl = null // aborts our lock request; set while we wait for or hold the lock
let unlock = null // releases the lock we hold
let holding = false
let heard = false // another tab held the lock: if we take over, events may have been missed

function readPref() { try { return localStorage.getItem(KEY) !== '0' } catch { return true } }
function writePref(v) { try { localStorage.setItem(KEY, v ? '1' : '0') } catch { /* private mode */ } }

function streamUrl() {
  const m = document.querySelector('meta[name="live-org"]')
  return '/api/events' + (m && m.content ? '?org=' + encodeURIComponent(m.content) : '')
}

function emit(ev) {
  for (const l of [...listeners]) {
    if (ev.kind === '*' || !l.kinds || l.kinds.has(ev.kind)) {
      try { l.fn(ev) } catch (e) { console.error(e) }
    }
  }
}

// tell the other tabs (the holder only)
function tell(m) { if (holding && channel) channel.postMessage(m) }

function setConnected(c) {
  tell({ t: 'state', connected: c })
  if (connected === c) return
  connected = c
  stateFns.forEach((f) => f())
}

function resync() { emit(RESYNC); tell({ t: 'resync' }) }

// The server ended the stream: the session ended, the account was disabled, the viewer lost the role or the token was
// revoked. Reloading shows what they may still see (the sign-in page when nothing).
function ended() { stop(); if (enabled) location.reload() }

// A follower hears from the holder.
function heardFromHolder({ data: m }) {
  if (holding) { if (m.t === 'hello') tell({ t: 'state', connected }); return }
  if (m.t === 'hello') return // another follower
  heard = true
  if (m.t === 'change') emit(m.ev)
  else if (m.t === 'resync') emit(RESYNC)
  else if (m.t === 'ended') ended()
  else if (m.t === 'state') {
    setConnected(m.connected)
    if (m.connected && syncNext) { syncNext = false; emit(RESYNC) } // we were away (paused, hidden): catch up
  }
}

function schedule() {
  clearTimeout(timer)
  const delay = Math.min(30000, 1000 * 2 ** Math.min(attempts++, 5)) * (0.75 + Math.random() * 0.5)
  timer = setTimeout(open, delay)
}

function open() {
  if (es || !enabled || listeners.size === 0 || (shared && !holding) || typeof EventSource === 'undefined') return
  es = new EventSource(streamUrl())
  es.addEventListener('ready', () => {
    attempts = 0
    setConnected(true)
    if (syncNext) { syncNext = false; resync() }
  })
  es.addEventListener('change', (e) => {
    let ev
    try { ev = JSON.parse(e.data) } catch { return /* ignore malformed */ }
    emit(ev)
    tell({ t: 'change', ev })
  })
  es.addEventListener('resync', resync)
  es.addEventListener('ended', () => { tell({ t: 'ended' }); ended() })
  es.onerror = () => {
    setConnected(false)
    syncNext = true
    // CLOSED = the server refused (HTTP error): reconnect ourselves with backoff. Otherwise the browser retries.
    if (es && es.readyState === EventSource.CLOSED) { es.close(); es = null; schedule() }
  }
}

// start: live updates wanted (not paused, something on the page live): connect, or join the tab that is connected.
function start() {
  if (!enabled || listeners.size === 0) return
  if (!shared) { open(); return }
  if (lockCtl) return
  const name = 'quisora-live:' + streamUrl()
  channel = new BroadcastChannel(name)
  channel.onmessage = heardFromHolder
  channel.postMessage({ t: 'hello' }) // the holder, if any, says whether it is connected
  const ctl = (lockCtl = new AbortController())
  navigator.locks.request(name, { signal: ctl.signal }, () => {
    if (lockCtl !== ctl) return undefined // stopped meanwhile
    holding = true
    if (heard) syncNext = true // taking over: what changed while nobody held the stream is not known
    open()
    return new Promise((resolve) => { unlock = resolve })
  }).catch(() => { /* aborted: we stopped waiting */ })
}

// stop: close the connection or leave the other tabs' (releasing the lock, so a waiting tab takes over at once).
function stop() {
  clearTimeout(timer)
  if (es) { es.close(); es = null }
  setConnected(false)
  syncNext = true
  if (lockCtl) { lockCtl.abort(); lockCtl = null }
  if (unlock) { unlock(); unlock = null }
  holding = false
  heard = false
  if (channel) { channel.close(); channel = null }
}

// subscribe(['user'], fn) -> unsubscribe. fn receives {kind, id, op}; a resync arrives as {kind: '*', op: 'resync'}.
export function subscribe(kinds, fn) {
  const l = { kinds: kinds && kinds.length ? new Set(kinds) : null, fn }
  listeners.add(l)
  start()
  stateFns.forEach((f) => f())
  return () => { listeners.delete(l); if (listeners.size === 0) stop(); stateFns.forEach((f) => f()) }
}

export const isLive = () => enabled
export const isConnected = () => connected
// isWatching: something on this page shows live data (a page with none never connects)
export const isWatching = () => listeners.size > 0
function apply(v) {
  enabled = v
  if (enabled) start(); else stop()
  stateFns.forEach((f) => f())
}
export function setLive(v) { writePref(!!v); apply(!!v) }
export function onLiveState(fn) { stateFns.add(fn); return () => stateFns.delete(fn) }

// pausing or resuming in one tab applies to the others
window.addEventListener('storage', (e) => { if (e.key === KEY && readPref() !== enabled) apply(readPref()) })
window.addEventListener('pagehide', stop)
window.addEventListener('pageshow', (e) => { if (e.persisted) start() })

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

// refetchOnReturn(fn): pages without live updates (the account page) refetch what they show when the tab comes back
// (shown again, focused, or restored from the back/forward cache): fn runs through liveRunner, at most once every 5 s,
// and not while live updates are paused.
const returners = new Set()
let lastReturn = Date.now() // the page has just loaded what it shows
export function refetchOnReturn(fn) { returners.add(liveRunner(fn)) }
function returned() {
  if (!enabled || returners.size === 0 || document.visibilityState !== 'visible' || Date.now() - lastReturn < 5000) return
  lastReturn = Date.now()
  returners.forEach((r) => r.trigger())
}
document.addEventListener('visibilitychange', returned)
window.addEventListener('focus', returned)
window.addEventListener('pageshow', (e) => { if (e.persisted) returned() })

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
