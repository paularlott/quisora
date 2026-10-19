// Theme toggle. The preference lives in localStorage ("quisora-theme": light | dark | system); theme-boot.js applied it
// before first paint. The switch toggles between light and dark; "Match system" clears the explicit choice.
const KEY = 'quisora-theme'
const mq = window.matchMedia('(prefers-color-scheme: dark)')

function readPref() {
  const el = document.documentElement
  return el.getAttribute('data-theme-pref') || 'system'
}
function apply(pref) {
  const el = document.documentElement
  el.setAttribute('data-theme-pref', pref)
  el.setAttribute('data-theme', pref === 'system' ? (mq.matches ? 'dark' : 'light') : pref)
}
function save(pref) {
  try { pref === 'system' ? localStorage.removeItem(KEY) : localStorage.setItem(KEY, pref) } catch { /* private mode */ }
  apply(pref)
}

export default function (Alpine) {
  Alpine.store('theme', {
    current: document.documentElement.getAttribute('data-theme') || 'light',
    pref: readPref(),
    sync() {
      this.current = document.documentElement.getAttribute('data-theme') || 'light'
      this.pref = readPref()
    },
    set(p) { save(p); this.sync() },
    toggle() { this.set(this.current === 'dark' ? 'light' : 'dark') },
  })
  const sync = () => Alpine.store('theme').sync()
  mq.addEventListener('change', () => setTimeout(sync))
  window.addEventListener('storage', () => setTimeout(sync))

  Alpine.data('themeSwitch', () => ({
    get checked() { return Alpine.store('theme').current === 'dark' ? 'true' : 'false' },
    get label() { return 'Dark theme' },
    toggle() { Alpine.store('theme').toggle() },
  }))
  Alpine.data('systemTheme', () => ({
    get active() { return Alpine.store('theme').pref === 'system' },
    use() { Alpine.store('theme').set('system') },
  }))
}
