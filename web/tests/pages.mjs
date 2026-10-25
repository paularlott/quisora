import { apiCall, uniq } from './helpers.mjs'

// Every page under audit. `as` picks the demo identity; `steps` open dialogs or otherwise prepare the page.
const A = '/admin/orgs/acme'
const open = (name) => async (p) => { await p.getByRole('button', { name }).first().click(); await p.waitForTimeout(450) }
const waitRows = async (p) => { await p.waitForSelector('tbody tr', { timeout: 5000 }) }

const userStep = [waitRows, async (p) => { await p.getByRole('link', { name: 'Alan Turing' }).click(); await p.waitForSelector('text=Profile') }]

// Reload the account page with the security summary altered (the demo user has a password and no Authenticator App).
export const accountStub = (security) => async (p) => {
  await p.route('**/api-internal/account', async (route) => {
    if (route.request().method() !== 'GET') return route.fallback()
    const res = await route.fetch()
    const body = await res.json()
    body.security = { ...body.security, ...security }
    await route.fulfill({ response: res, json: body })
  })
  await p.reload({ waitUntil: 'load' })
  await p.waitForTimeout(800)
  await p.locator('#security').scrollIntoViewIfNeeded(); await p.evaluate(() => window.scrollBy(0, -80))
}

// Scroll the email addresses card into view once its list has loaded.
const emailsStep = async (p) => {
  await p.getByRole('list', { name: 'Email addresses' }).waitFor()
  await p.locator('#emails-h').scrollIntoViewIfNeeded(); await p.evaluate(() => window.scrollBy(0, -80)); await p.waitForTimeout(300)
}
const userEmailsStep = [waitRows, async (p) => { await p.getByRole('link', { name: 'Alan Turing' }).click(); await p.getByRole('list', { name: 'Email addresses' }).waitFor() }, emailsStep]

// secondFactorStep reaches the authenticator-code step with the password step's answer stubbed (a passkey, a code by
// email and recovery codes as the other ways).
const secondFactorStep = async (p) => {
  await p.route('**/api-internal/login/password', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ step: 'totp', ticket: 'n1.stub', alternatives: ['passkey', 'email_code', 'recovery'], email: 'a•••@acme.example' }) }))
  await p.route('**/api-internal/login/email/send', (r) => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ email: 'a•••@acme.example' }) }))
  await p.locator('#f-email').fill('alan@acme.example')
  await p.getByRole('button', { name: 'Continue' }).click()
  await p.locator('#f-password').fill('stubbed password')
  await p.locator('#f-password').press('Enter')
  await p.getByRole('button', { name: 'Try another way' }).first().waitFor()
}

export const PAGES = [
  { name: 'orgs', path: '/admin/orgs', as: 'super', steps: [waitRows] },
  // the navigation drawer, open over the users list on a phone-sized screen (super admin: every navigation group)
  { name: 'nav-drawer', path: `${A}/users`, as: 'super', steps: [async (p) => { await p.setViewportSize({ width: 390, height: 780 }); await p.reload({ waitUntil: 'load' }) }, waitRows, open('Open navigation menu')] },
  { name: 'orgs-edit', path: '/admin/orgs', as: 'super', dialog: true, steps: [waitRows, open('Edit Acme Corporation')] },
  // Master key rotation status (with the demo's -rotation flag, a rotation halfway through).
  { name: 'master-key', path: '/admin/system/master-key', as: 'super', steps: [async (p) => { await p.getByRole('heading', { name: 'Nodes' }).waitFor() }] },
  { name: 'orgs-new', path: '/admin/orgs', as: 'super', steps: [waitRows, open('New organization')], dialog: true },
  { name: 'org', path: A, as: 'admin', steps: [async (p) => { await p.getByText('Session lifetime').waitFor() }] },
  { name: 'org-signout', path: A, as: 'admin', dialog: true, steps: [async (p) => { await p.getByText('Session lifetime').waitFor() }, open('Sign everyone out…')] },
  { name: 'users', path: `${A}/users`, as: 'admin', steps: [waitRows] },
  { name: 'users-new', path: `${A}/users`, as: 'admin', steps: [waitRows, open('New user')], dialog: true },
  { name: 'user', path: `${A}/users`, as: 'admin', steps: [waitRows, async (p) => { await p.getByRole('link', { name: 'Alan Turing' }).click(); await p.waitForSelector('text=Profile') }] },
  { name: 'user-lockout', path: `${A}/users`, as: 'admin', dialog: true, steps: [waitRows, async (p) => { await p.getByRole('link', { name: 'Alan Turing' }).click(); await p.waitForSelector('text=Profile') }, open('Lock out…')] },
  // The tag editor: chips added from the keyboard, plus its inline error for an invalid tag.
  { name: 'users-new-tags', path: `${A}/users`, as: 'admin', dialog: true, steps: [waitRows, open('New user'), async (p) => {
      await p.locator('#f-tags').fill('dept:finance,vip ')
      await p.locator('#f-tags').type('-bad'); await p.keyboard.press('Enter')
      await p.locator('#e-tags').filter({ hasText: 'is not a valid tag' }).waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'users-edit-tags', path: `${A}/users`, as: 'admin', dialog: true, steps: [waitRows, open('Edit Alan Turing')] },
  // Work details open (Alan has some), and the language autocompleter showing its list.
  { name: 'users-edit-work', path: `${A}/users`, as: 'admin', dialog: true, steps: [waitRows, open('Edit Alan Turing'), async (p) => {
      await p.locator('#f-work_title').waitFor({ state: 'visible' })
      await p.locator('#f-locale').fill('Eng')
      await p.getByRole('listbox', { name: 'Language' }).waitFor(); await p.waitForTimeout(300)
    }] },
  { name: 'users-edit-manager', path: `${A}/users`, as: 'admin', dialog: true, steps: [waitRows, open('Edit Alan Turing'), async (p) => {
      await p.locator('#f-manager_id').fill('ada')
      await p.getByRole('listbox', { name: 'Manager' }).waitFor(); await p.waitForTimeout(300)
    }] },
  { name: 'users-filtered-by-tag', path: `${A}/users`, as: 'admin', steps: [waitRows, async (p) => {
      await p.getByRole('button', { name: 'Show users tagged vip' }).first().click(); await p.waitForTimeout(600)
    }] },
  { name: 'users-new-invite', path: `${A}/users`, as: 'admin', dialog: true, steps: [waitRows, open('New user'), async (p) => {
      const id = 'invitee' + Date.now() + Math.floor(Math.random() * 1e6)
      await p.locator('#f-email').fill(id + '@acme.example')
      await p.locator('#f-given_name').fill('Invitee')
      await p.getByRole('button', { name: 'Create user' }).click()
      await p.getByRole('dialog', { name: 'Invitation link' }).waitFor()
      await p.waitForTimeout(450)
    }] },
  { name: 'user-disabled', path: `${A}/users`, as: 'admin', steps: [waitRows, async (p) => { await p.getByRole('link', { name: 'Dennis Ritchie' }).click(); await p.waitForSelector('text=Left the company') }] },
  { name: 'users-edit-disable', path: `${A}/users`, as: 'admin', dialog: true, steps: [waitRows, open('Edit Alan Turing'), async (p) => {
    await p.locator('#f-active').uncheck(); await p.locator('#f-status_reason').fill('On leave'); await p.locator('#f-status_reason').scrollIntoViewIfNeeded() }] },
  { name: 'user-emails', path: `${A}/users`, as: 'admin', steps: userEmailsStep },
  { name: 'user-sessions', path: `${A}/users`, as: 'admin', steps: [...userEmailsStep, async (p) => {
      await p.getByRole('heading', { name: 'Sessions' }).scrollIntoViewIfNeeded(); await p.waitForTimeout(300)
    }] },
  { name: 'user-connections', path: `${A}/users`, as: 'admin', steps: [...userEmailsStep, async (p) => {
      await p.getByRole('heading', { name: 'Sign-in providers' }).scrollIntoViewIfNeeded(); await p.waitForTimeout(300)
    }] },
  { name: 'user-app-remove', path: `${A}/users`, as: 'admin', dialog: true, steps: [...userEmailsStep, async (p) => {
      await p.getByRole('button', { name: 'Remove access for Customer portal' }).click()
      await p.getByRole('dialog', { name: 'Remove access?' }).waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'user-provider-disconnect', path: `${A}/users`, as: 'admin', dialog: true, steps: [...userEmailsStep, async (p) => {
      await p.getByRole('button', { name: 'Disconnect Acme SSO' }).click()
      await p.getByRole('dialog', { name: 'Disconnect provider?' }).waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'user-emails-add', path: `${A}/users`, as: 'admin', steps: [...userEmailsStep, async (p) => {
      await p.getByRole('button', { name: 'Add email' }).click(); await p.locator('#f-em_address').waitFor(); await p.waitForTimeout(300)
    }] },
  { name: 'user-emails-remove', path: `${A}/users`, as: 'admin', dialog: true, steps: [...userEmailsStep, async (p) => {
      await p.getByRole('button', { name: 'Remove alan.turing@bletchley.example' }).click()
      await p.getByRole('dialog', { name: 'Remove email address' }).waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'user-remove-password', path: `${A}/users`, as: 'admin', dialog: true, steps: [...userStep, async (p) => {
      await p.getByRole('button', { name: 'Remove password' }).click(); await p.getByRole('alertdialog').or(p.getByRole('dialog', { name: 'Remove password?' })).first().waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'user-invite', path: `${A}/users`, as: 'admin', dialog: true, steps: [...userStep, async (p) => {
      await p.getByRole('button', { name: 'New invitation link' }).click(); await p.waitForTimeout(450)
    }] },
  { name: 'user-invite-link', path: `${A}/users`, as: 'admin', dialog: true, steps: [...userStep, async (p) => {
      await p.getByRole('button', { name: 'New invitation link' }).click(); await p.waitForTimeout(300)
      await p.getByRole('button', { name: 'Generate link' }).click(); await p.locator('#invite-url').waitFor(); await p.waitForTimeout(450)
    }] },
  // An edit dialog whose record another administrator changed: the non-modal notice inside the dialog.
  { name: 'users-edit-notice', path: `${A}/users`, as: 'admin', dialog: true, steps: [waitRows, async (p) => {
      const id = uniq('notice')
      const u = await apiCall(p, 'POST', '/api/orgs/acme/users', { username: id, email: id + '@acme.example', given_name: 'Notice', family_name: id })
      await p.getByRole('searchbox', { name: 'Search users' }).fill(id)
      await p.getByRole('button', { name: 'Edit Notice ' + id }).click()
      await p.waitForTimeout(450)
      await apiCall(p, 'PATCH', `/api/orgs/acme/users/${u.id}`, { family_name: 'Renamed ' + id })
      await p.locator('.edit-notice .alert').waitFor({ timeout: 4000 })
      await p.waitForTimeout(300)
    }] },
  { name: 'users-super', path: `${A}/users`, as: 'super', steps: [waitRows] },
  { name: 'groups', path: `${A}/groups`, as: 'admin', steps: [waitRows] },
  { name: 'groups-members', path: `${A}/groups`, as: 'admin', steps: [waitRows, open('Members of Engineering')], dialog: true },
  { name: 'groups-members-picker', path: `${A}/groups`, as: 'admin', dialog: true, steps: [waitRows, open('Members of Engineering'), async (p) => {
      await p.locator('#f-member').fill('a'); await p.locator('#member-picks [role=option]').first().waitFor()
      await p.keyboard.press('ArrowDown'); await p.waitForTimeout(300)
    }] },
  // A manager: the members of a group, and plain users only to add; no group is created, changed or deleted.
  { name: 'groups-manager', path: `${A}/groups`, as: 'manager', dialog: true, steps: [waitRows, async (p) => {
      for (const name of ['New group', 'Edit Engineering', 'Delete Engineering']) {
        if (await p.getByRole('button', { name }).count()) throw new Error(`a manager sees ${name}`)
      }
    }, open('Members of Engineering'), async (p) => {
      await p.locator('#f-member').fill('a'); await p.locator('#member-picks [role=option]').first().waitFor()
    }] },
  { name: 'groups-new-tags', path: `${A}/groups`, as: 'admin', dialog: true, steps: [waitRows, open('New group'), async (p) => {
      await p.locator('#f-tags').fill('team:a,team:b '); await p.locator('#f-tags').type('x y!'); await p.keyboard.press('Enter')
      await p.locator('#e-tags').filter({ hasText: 'is not a valid tag' }).waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'groups-edit-tags', path: `${A}/groups`, as: 'admin', dialog: true, steps: [waitRows, open('Edit Engineering')] },
  { name: 'tenants', path: `${A}/tenants`, as: 'admin', steps: [waitRows] },
  { name: 'tenants-new', path: `${A}/tenants`, as: 'admin', steps: [waitRows, open('New tenant')], dialog: true },
  { name: 'tenants-new-org-mfa', path: '/admin/orgs/northwind/tenants', as: 'super', steps: [waitRows, open('New tenant')], dialog: true },
  { name: 'tenants-edit', path: `${A}/tenants`, as: 'admin', steps: [waitRows, open('Edit Staff tools')], dialog: true },
  { name: 'tenant', path: `${A}/tenants/staff`, as: 'admin', steps: [waitRows] },
  { name: 'tenant-customers', path: `${A}/tenants/customers`, as: 'admin', steps: [waitRows] },
  { name: 'tenant-empty', path: `${A}/tenants/partners`, as: 'admin', steps: [async (p) => { await p.getByText('No clients in this tenant yet').waitFor() }] },
  { name: 'tenant-super', path: `${A}/tenants/staff`, as: 'super', steps: [waitRows] },
  { name: 'tenant-edit-rules', path: `${A}/tenants/staff`, as: 'admin', steps: [waitRows, open('Edit sign-in rules')], dialog: true },
  { name: 'tenant-client-new', path: `${A}/tenants/staff`, as: 'admin', steps: [waitRows, open('New client')], dialog: true },
  { name: 'tenant-client-edit', path: `${A}/tenants/staff`, as: 'admin', steps: [waitRows, open('Edit Internal tool 1')], dialog: true },
  // device sign-in ticked: the switch for managers and administrators appears
  { name: 'tenant-client-device', path: `${A}/tenants/staff`, as: 'admin', dialog: true, steps: [waitRows, open('New client'), async (p) => {
    await p.getByRole('checkbox', { name: /Device sign-in/ }).check()
    await p.getByRole('switch', { name: /Managers and administrators may approve device sign-ins/ }).scrollIntoViewIfNeeded()
  }] },
  { name: 'tenant-client-secret', path: `${A}/tenants/staff`, as: 'admin', dialog: true, steps: [waitRows, async (p) => {
      await p.getByRole('button', { name: 'Rotate secret of Internal tool 2' }).click()
      await p.getByRole('button', { name: 'Rotate secret', exact: true }).click()
      await p.getByRole('dialog', { name: 'New client secret' }).waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'tenant-client-delete', path: `${A}/tenants/staff`, as: 'admin', dialog: true, steps: [waitRows, async (p) => {
      await p.getByRole('button', { name: 'Delete Internal tool 3' }).click()
      await p.getByRole('dialog', { name: 'Delete client?' }).waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'providers', path: `${A}/providers`, as: 'admin', steps: [waitRows] },
  { name: 'providers-new', path: `${A}/providers`, as: 'admin', steps: [waitRows, open('New provider')], dialog: true },
  { name: 'audit', path: `${A}/audit`, as: 'admin', steps: [waitRows] },
  { name: 'audit-org-super', path: `${A}/audit`, as: 'super', steps: [waitRows] },
  { name: 'audit-all', path: '/admin/audit', as: 'super', steps: [waitRows] },
  { name: 'system', path: '/admin/system', as: 'super', steps: [waitRows] },
  { name: 'system-signout', path: '/admin/system', as: 'super', dialog: true, steps: [waitRows, open('Sign everyone out…')] },
  { name: 'keys-rotate', path: '/admin/system', as: 'super', dialog: true, steps: [waitRows, open('Rotate now')] },
  { name: 'secret-stores-read', path: '/admin/system', as: 'super', dialog: true, steps: [waitRows, open('Read secret stores now')] },
  { name: 'error-404', path: '/admin/nowhere', as: 'admin' },
  { name: 'users-manager', path: `${A}/users`, as: 'manager', steps: [waitRows] },
  // An administrator, as a manager sees them: a directory entry (name, role, status), read-only.
  { name: 'user-directory', path: `${A}/users`, as: 'manager', steps: [waitRows, async (p) => { await p.getByRole('link', { name: 'Ada Lovelace' }).click(); await p.waitForSelector('text=their role is above yours') }] },
]

// Pages owned by the login module (anonymous and account pages).
PAGES.push(
  { name: 'landing', path: '/', as: 'none' },
  // the device sign-in page (RFC 8628), and with a code that is not valid
  { name: 'device', path: '/device', as: 'none' },
  { name: 'device-error', path: '/device?user_code=BBBB-BBBB', as: 'none' },
  // the consent screen of a device sign-in (the demo's device client), with its warning and the code
  { name: 'device-consent', path: '/account', as: 'user', steps: [async (p) => {
    const id = await (await p.request.get('/__demo/device-client')).text()
    const res = await p.request.post('/oauth/device_authorization', { form: { client_id: id, scope: 'openid profile' } })
    const { user_code: code } = await res.json()
    await p.goto('/device?user_code=' + encodeURIComponent(code))
    await p.getByText('Signing in a device').waitFor()
  }] },
  { name: 'landing-picker', path: '/?next=%2Foauth%2Fauthorize%2Fresume', as: 'none' },
  { name: 'login-org', path: '/login/acme', as: 'none' },
  // the second-factor step (the password step's answer stubbed): "Try another way", then a recovery code
  { name: 'login-another-way', path: '/login/acme', as: 'none', steps: [secondFactorStep, async (p) => {
    await p.getByRole('button', { name: 'Try another way' }).first().click()
    await p.getByRole('heading', { name: 'Try another way' }).waitFor()
  }] },
  { name: 'login-recovery-code', path: '/login/acme', as: 'none', steps: [secondFactorStep, async (p) => {
    await p.getByRole('button', { name: 'Try another way' }).first().click()
    await p.getByRole('button', { name: 'Use a recovery code' }).click()
    await p.locator('#f-rcode').waitFor()
  }] },
  { name: 'login-email-code', path: '/login/acme', as: 'none', steps: [secondFactorStep, async (p) => {
    await p.getByRole('button', { name: 'Try another way' }).first().click()
    await p.getByRole('button', { name: 'Email a code to a•••@acme.example' }).click()
    await p.locator('#f-mcode').waitFor()
  }] },
  { name: 'account', path: '/account', as: 'user', steps: [async (p) => { await p.waitForTimeout(800); await p.locator('#security').scrollIntoViewIfNeeded(); await p.evaluate(() => window.scrollBy(0, -80)) }] },
  // The user menu: a floating glass panel over the page, open for the audit (contrast budget of --glass-bg-panel).
  { name: 'account-usermenu', path: '/account', as: 'user', steps: [async (p) => {
      await p.getByRole('button', { name: /Account menu/ }).click(); await p.locator('#user-menu').waitFor(); await p.waitForTimeout(450)
    }] },
  // An error toast stays until dismissed, so the audit sees it: the toast panel's contrast budget (--glass-bg-toast).
  { name: 'account-toast', path: '/account', as: 'user', steps: [async (p) => {
      await p.evaluate(() => window.Alpine.store('toasts').push('Could not save your changes.', 'error'))
      await p.locator('.toast-error').waitFor(); await p.waitForTimeout(450)
    }] },
  // Email addresses: the list (a verified and an unverified linked address), the inline add input, the remove confirmation.
  { name: 'account-emails', path: '/account', as: 'user', steps: [emailsStep] },
  { name: 'account-password', path: '/account', as: 'user', dialog: true, steps: [async (p) => {
      await p.getByRole('button', { name: /Change… password/ }).click(); await p.getByRole('dialog', { name: 'Change password' }).waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'account-zone-open', path: '/account', as: 'user', steps: [async (p) => {
      await p.locator('#f-zoneinfo').fill('lond')
      await p.getByRole('listbox', { name: 'Time zone' }).waitFor(); await p.waitForTimeout(300)
    }] },
  { name: 'account-totp-setup', path: '/account', as: 'user', dialog: true, steps: [async (p) => {
      await p.getByRole('button', { name: /Set up… Authenticator App/ }).click(); await p.getByRole('dialog', { name: 'Set up Authenticator App' }).waitFor()
      await p.waitForSelector('#totp-dialog img[src^="data:"]'); await p.waitForTimeout(450)
    }] },
  { name: 'account-totp-on', path: '/account', as: 'user', steps: [accountStub({ totp: true })] },
  { name: 'account-no-password', path: '/account', as: 'user', steps: [accountStub({ has_password: false })] },
  { name: 'account-totp-remove', path: '/account', as: 'user', dialog: true, steps: [accountStub({ totp: true }), async (p) => {
      await p.getByRole('button', { name: /Remove… Authenticator App/ }).click(); await p.getByRole('dialog', { name: 'Remove Authenticator App' }).waitFor(); await p.waitForTimeout(450)
    }] },
  { name: 'account-admin', path: '/account', as: 'admin', steps: [async (p) => { await p.waitForTimeout(800) }] },
  { name: 'logout', path: '/logout', as: 'user' },
)

// Invitation sign-up page states (see pages-invite.mjs).
import { INVITE_PAGES, INVITE_NO_PASSKEY } from './pages-invite.mjs'
PAGES.push(...INVITE_PAGES)

// The live-updates switch in its paused state (last: the choice is remembered per browser).
PAGES.push({ name: 'tenant-live-paused', path: `${A}/tenants/staff`, as: 'admin', steps: [waitRows, async (p) => { await p.getByRole('button', { name: 'Pause live updates' }).click(); await p.waitForTimeout(200) }] })
// Client dialog list editors (see pages-clients.mjs).
import { CLIENT_PAGES } from "./pages-clients.mjs"
PAGES.push(...CLIENT_PAGES)
PAGES.push(INVITE_NO_PASSKEY)
