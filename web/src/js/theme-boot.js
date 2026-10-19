// Runs in <head> before first paint (external file: the CSP forbids inline scripts). Resolves the theme preference
// (localStorage "quisora-theme": light | dark | system, else the site default from <html data-default-theme>) and sets
// <html data-theme="light|dark">. The preference itself stays in data-theme-pref.
(function () {
  var d = document.documentElement
  var KEY = 'quisora-theme'
  var mq = window.matchMedia('(prefers-color-scheme: dark)')
  d.classList.add('js')
  function stored() { try { return localStorage.getItem(KEY) } catch (e) { return null } }
  function pref() {
    var p = stored()
    if (p === 'light' || p === 'dark' || p === 'system') return p
    p = d.getAttribute('data-default-theme')
    return p === 'light' || p === 'dark' ? p : 'system'
  }
  function apply() {
    var p = pref()
    d.setAttribute('data-theme', p === 'system' ? (mq.matches ? 'dark' : 'light') : p)
    d.setAttribute('data-theme-pref', p)
  }
  apply()
  if (mq.addEventListener) mq.addEventListener('change', apply)
  window.addEventListener('storage', apply)
})()
