// Invitation sign-up page in each organization setup: password + passkey, passkey only, providers only, and the
// invalid-link state. The first two use /__demo/invite?as=<seeded user> (uidemo); the providers-only state creates an
// organization with both methods off through the admin API, so the shared demo data stays untouched.
const providersOnly = async (page) => {
  const url = await page.evaluate(async () => {
    const csrf = document.querySelector('meta[name="csrf-token"]').content
    const call = async (method, path, body) => {
      const r = await fetch(path, { method, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(body) })
      if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${await r.text()}`)
      return r.json()
    }
    const name = 'sso' + Date.now() + Math.floor(Math.random() * 1000)
    await call('POST', '/api/orgs', { name, display_name: 'SSO Only Ltd', settings: { password_login: false, passkey_login: false } })
    const u = await call('POST', `/api/orgs/${name}/users`, { username: 'sam', email: 'sam@sso.example', given_name: 'Sam', family_name: 'Provider', invite: {} })
    return u.invite.url
  })
  await page.goto(url, { waitUntil: 'load' })
}

export const INVITE_PAGES = [
  { name: 'invite-password-passkey', path: '/__demo/invite?as=iris', as: 'none' },
  { name: 'invite-passkey-only', path: '/__demo/invite?as=quinn', as: 'none' },
  { name: 'invite-providers-only', path: '/admin/orgs', as: 'super', steps: [providersOnly] },
  { name: 'invite-invalid', path: '/invite?token=not-a-real-token', as: 'none' },
  // the page an emailed verification link opens (the address is confirmed only by its button)
  { name: 'verify-email', path: '/verify-email?token=demo-token', as: 'none' },
]

// A browser without WebAuthn: the page says so instead of offering a passkey button. The init script lasts for the
// whole browser context, so this state goes last (see pages.mjs).
export const INVITE_NO_PASSKEY = {
  name: 'invite-passkey-unsupported', path: '/__demo/invite?as=quinn', as: 'none', steps: [async (page) => {
    await page.context().addInitScript(() => { delete window.PublicKeyCredential })
    await page.reload({ waitUntil: 'load' })
    await page.getByText('This browser or device cannot create passkeys.').waitFor()
  }],
}
