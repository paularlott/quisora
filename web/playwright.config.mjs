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
  // Some tests change settings every page of an organization follows for a while: the skins tests the primary
  // organization's skin (a page audited meanwhile would wear another skin than its backdrops are for), the picture
  // setting tests whether people may change their own picture (a test of that page meanwhile would find no controls).
  // So they run on their own, after every other test. (Running one of those files alone runs the others first: add
  // --no-deps to skip them.)
  projects: [
    { name: 'pages', testIgnore: ['**/skins.spec.mjs', '**/pictures-org.spec.mjs'] },
    // one after the other, so neither sees the other's setting either
    { name: 'pictures-org', testMatch: '**/pictures-org.spec.mjs', dependencies: ['pages'] },
    { name: 'skins', testMatch: '**/skins.spec.mjs', dependencies: ['pictures-org'] },
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
