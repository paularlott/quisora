// Builds web/dist, which the Go binary embeds (web/embed.go): the app's script, stylesheet and pre-paint theme script,
// the static logos, the OpenAPI document (/api/openapi.json) and the API reference (/api-docs/). Everything is bundled
// from node_modules; no page loads anything from a CDN, so the server works on a network without internet access.
import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'
import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const here = import.meta.dirname

// emptyOutDir clears web/dist, including the committed placeholder that lets the Go packages compile before a build.
const keepPlaceholder = {
  name: 'keep-dist-placeholder',
  writeBundle(opts) { writeFileSync(resolve(opts.dir, '.gitkeep'), '') },
}

// Redoc's "API docs by Redocly" badge loads the Redocly logo from cdn.redoc.ly. The skin (src/css/api-docs.css) hides
// the badge, but a hidden image is still fetched, so point it at a blank one. Its icon sets are fetched from
// cdn.redocly.com by joining a base URL and an icon's name: an empty data: URL as the base makes any such URL inline
// data, fetched from nowhere. So the API reference makes no outside request. The build fails if Redoc changes any of
// this, so the plugin is reviewed on a Redoc upgrade.
const blank = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>')
const redocURLs = {
  'https://cdn.redoc.ly/redoc/logo-mini-full.svg': blank,
  'https://cdn.redoc.ly/redoc/logo-mini.svg': blank,
  'https://cdn.redocly.com/icons/fa/7.0.0': 'data:,',
  'https://cdn.redocly.com/icons/code/5.24.0': 'data:,',
  // the telemetry collector (switched off in src/js/api-docs.js, and the CSP's connect-src blocks it): nowhere to send to
  'https://otel.cloud.redocly.com/v1/traces': 'data:,',
}
const redocOffline = {
  name: 'redoc-offline',
  transform(code, id) {
    if (!id.includes('/node_modules/redoc/bundles/')) return
    let out = code
    for (const [url, local] of Object.entries(redocURLs)) {
      if (!out.includes(url)) this.error(`redoc no longer references ${url}: review the redoc-offline plugin`)
      out = out.replaceAll(url, local)
    }
    return { code: out, map: null }
  },
}

// dist/openapi.json, served at /api/openapi.json: Redocly CLI bundles the description (openapi/openapi.yaml and any
// file it references) into one JSON document.
const openapiYaml = resolve(here, 'openapi/openapi.yaml')
const openapiJson = {
  name: 'openapi-json',
  buildStart() { this.addWatchFile(openapiYaml) },
  generateBundle() {
    const redocly = resolve(here, 'node_modules/.bin/redocly')
    const json = execFileSync(redocly, ['bundle', openapiYaml, '--ext', 'json'], {
      cwd: here, encoding: 'utf8', maxBuffer: 64 << 20, stdio: ['ignore', 'pipe', 'inherit'],
      env: { ...process.env, REDOCLY_TELEMETRY: 'off', REDOCLY_SUPPRESS_UPDATE_NOTICE: 'true' },
    })
    this.emitFile({ type: 'asset', fileName: 'openapi.json', source: JSON.stringify(JSON.parse(json)) })
  },
}

export default defineConfig({
  root: here,
  base: '/',
  publicDir: 'src/static', // copied as is to the root of dist (the default logos)
  plugins: [tailwindcss(), redocOffline, openapiJson, keepPlaceholder],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    manifest: 'manifest.json', // the Go renderer (internal/web/render.go) maps entries to their hashed files
    target: 'es2022',
    modulePreload: false,
    chunkSizeWarningLimit: 4096, // the API reference bundles Redoc (about 2 MB)
    rolldownOptions: {
      input: {
        main: resolve(here, 'src/js/main.js'),
        // runs in <head> before first paint as a classic script: it must import nothing, so no chunk is split off it
        'theme-boot': resolve(here, 'src/js/theme-boot.js'),
        style: resolve(here, 'src/css/main.css'),
        'api-docs': resolve(here, 'api-docs/index.html'),
      },
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
})
