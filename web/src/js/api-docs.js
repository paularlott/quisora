// The API reference at /api-docs/: Redoc 3, bundled from node_modules into the binary, renders the OpenAPI document
// the server serves at /api/openapi.json (built from web/openapi/openapi.yaml). Nothing loads from outside the server.
import { init } from 'redoc/bundles/redoc.standalone.js'
import '../css/api-docs.css'

// Follow the app's light/dark choice when the user has made one (Redoc keeps its own in redoc.colorMode).
try {
  const pref = localStorage.getItem('quisora-theme')
  if (pref === 'light' || pref === 'dark') localStorage.setItem('redoc.colorMode', pref)
} catch { /* storage unavailable: Redoc follows the system setting */ }

init('/api/openapi.json', {
  disableTelemetry: true, // Redoc would otherwise report page views to Redocly
  router: 'hash', // the server serves only /api-docs/ itself, so in-page links stay in the fragment
}, document.getElementById('redoc'))
