import { defineConfig } from '@playwright/test'

const PORT = process.env.UIDEMO_PORT || '18443'
export const BASE = `https://localhost:${PORT}`
// SKIN=<name or absolute path> runs the suite against a skin, the demo's primary organization's (web/skins/README.md)
const SKIN = process.env.SKIN ? ` -skin ${JSON.stringify(process.env.SKIN)}` : ''

// The audit runs against the demo server (in-memory store seeded with demo data): go run ./tools/uidemo
export default defineConfig({
  testDir: './tests',
  testMatch: '**/*.spec.mjs',
  timeout: 60_000,
  workers: 2,
  reporter: [['list']],
  use: { baseURL: BASE, ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } },
  // The skins tests change the primary organization's skin for a while, and every page that follows it (the console,
  // organizations without their own) wears that skin meanwhile: a page another test audits then would be measured
  // against the default skin's backdrops in another skin. So they run on their own, after every other test. (Running
  // skins.spec.mjs alone runs the others first: add --no-deps to skip them.)
  projects: [
    { name: 'pages', testIgnore: '**/skins.spec.mjs' },
    { name: 'skins', testMatch: '**/skins.spec.mjs', dependencies: ['pages'] },
  ],
  webServer: {
    command: `go run ./tools/uidemo -addr 127.0.0.1:${PORT}${SKIN}`,
    cwd: '..',
    url: `${BASE}/healthz`,
    ignoreHTTPSErrors: true,
    reuseExistingServer: !process.env.CI && !process.env.SKIN,
    timeout: 120_000,
  },
})
