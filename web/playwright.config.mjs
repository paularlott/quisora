import { defineConfig } from '@playwright/test'

const PORT = process.env.UIDEMO_PORT || '18443'
export const BASE = `https://localhost:${PORT}`

// The audit runs against the demo server (in-memory store seeded with demo data): go run ./internal/admin/cmd/uidemo
export default defineConfig({
  testDir: './tests',
  testMatch: '**/*.spec.mjs',
  timeout: 60_000,
  workers: 2,
  reporter: [['list']],
  use: { baseURL: BASE, ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } },
  webServer: {
    command: `go run ./internal/admin/cmd/uidemo -addr 127.0.0.1:${PORT}`,
    cwd: '..',
    url: `${BASE}/healthz`,
    ignoreHTTPSErrors: true,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
