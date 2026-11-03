# Signing in to Quisora

How people sign in to Quisora, and the rules that protect their accounts. (How applications sign people in through
Quisora is in [Connecting applications](../oauth/README.md).)

## The guides

| | |
| --- | --- |
| [Passkeys](passkeys.md) | Fingerprint, face or device PIN instead of a password; a passkey counts as two factors |
| [Upstream providers](providers.md) | "Continue with" Google, Microsoft, GitHub, GitLab, Auth0 or your own single sign-on |
| [Recovery codes](recovery-codes.md) | One-time codes for when the second factor is not at hand |
| [Codes by email](email-codes.md) | A second factor by email, for organizations that allow it |
| [SSH certificates](../ssh/README.md) | Signing in to servers with a short-lived certificate, after a second-factor sign-in |
| [Emergency sign-out and lock-out](../emergency-sign-out.md) | Ending everyone's sessions at once, or one person's access |

## Where people sign in

Organizations are self-contained: each has its own address space, `/o/<org>/`, where `<org>` is the organization's id
(22 letters and digits, in which case matters: the form every link Quisora makes uses) or its
name (a name can never be an id, and `o` is reserved).
The sign-in page is `/o/<org>/login`, with `/o/<org>/account`, `/o/<org>/invite`, `/o/<org>/reset`,
`/o/<org>/verify-email` and `/o/<org>/logout` beside it; the links in invitation, reset and verification emails are
`/o/<org id>/…`. `https://id.example.com/` signs no one in: it tells a signed-out visitor to start from their application or
their organization's sign-in link, as does a page that does not exist, or an organization's when there is no such
organization (a 404). It carries the primary organization's logo and colour, if it has them. Signed in, it is the
account page. Administrators of the primary organization sign in at `/admin`.

A browser keeps one session per organization (a cookie of its own for each): being signed in to one organization is not
being signed in to another. The console (`/admin`) and the management API (`/api`) are the server's, not an
organization's: they use the session of the organization they administer if the browser has one, otherwise the primary
organization's (super admins), otherwise any other.

## Ways to sign in

Each organization chooses its methods (super admins: **Organizations** → **Edit** → **Sign-in methods**), and each
tenant can narrow them for its applications, never widen them:

- **Password** (with **Allow password reset**: a reset link by email). Users choose their passwords themselves,
  through an invitation; administrators never set them.
- **Passkeys**: as the whole sign-in, or as the second factor after a password. [More](passkeys.md).
- **Upstream providers**: each tenant offers all of the organization's providers or a chosen few.
  [More](providers.md).

New users get an **invitation link** (shown to the administrator, or emailed when the server sends email), valid for 7
days and once, with which they set a password, create a passkey, or both. A user has one invitation at a time: a new
one replaces the last. The link keeps working until the set-up completes, so a failure part-way (a network error, a
password the policy refuses) is simply tried again. An accepted invitation replaces every way the user signed in
before, all at once (a passkey, connected provider, API token or session from before stops working at the moment it
is accepted), so it is also how someone who lost everything gets back in.

## Second factors

**Require a second factor** on the organization (or a tenant, for its applications) makes every password or provider
sign-in also give one:

- an **authenticator app** (a 6-digit code: TOTP);
- a **passkey** after the password;
- a [code by email](email-codes.md), where the organization allows it, for users with neither of the first two;
- a [recovery code](recovery-codes.md), in place of either of the first two.

A user without a second factor sets one up during the sign-in (an authenticator app, with a passkey offered), or, where
codes by email are allowed, gets one by email instead. **Try another way** at the second-factor step lists what else
the account can use. Managers, administrators and super admins always need a second factor, whatever the settings,
and the console refuses a session without one. Wrong passwords and codes count towards a temporary lock-out of the
account.

Applications can also ask for a second factor for one sign-in (`acr_values=urn:quisora:acr:mfa`): see [signing users
in](../oauth/sign-in.md#requiring-a-second-factor).

## A credential change ends what is in flight

Every account has a **security generation**: a counter that moves on whenever a way into the account changes — the
password is set, changed, removed or reset; an authenticator app is set up, replaced or removed; a passkey is added,
removed or disabled (a suspected copy); recovery codes are made or dropped; a sign-in provider is connected or
disconnected; the account is disabled or enabled again (a lock-out, an accepted invitation). Everything in progress
for the account is bound to the generation it started under and stops working when the generation moves on; the
person starts again, with the account's credentials as they are now:

- **a sign-in between its steps** — a password verified and the authenticator code, passkey, emailed code or recovery
  code still to come, or the second-factor set-up for an account without one. The emergency sign-out lever ends these
  too. A code that is right for a sign-in that has died is refused all the same;
- **a second-factor set-up** begun at sign-in or on the account page: an authenticator secret shown before the change
  is not confirmed against the account after it;
- **a passkey ceremony** begun for the account (adding one, confirming with one);
- **a re-authentication** ("Confirm it is you"), unless the change was this very browser's own: setting up an
  authenticator app from one browser makes every other browser's confirmation ask again, now for the code;
- **an invitation or password reset link**: a reset link mailed before the password was changed, or an invitation
  issued before the user set up a passkey, opens nothing. (A verification link only proves an address, and works
  while that address is still on the account.)

Setting up a second factor at sign-in is only ever for an account that has none. Two browsers holding the same
password cannot each set one up: the first to finish moves the generation on, and the second is sent back to sign in,
where the factor that won now stands between it and a session. The write that sets a factor is a compare-and-swap on
the user (confirmed by a majority of the cluster), so two finishing at the same moment still end with exactly one.

A change of role, address or end date is not a credential change: each step judges those afresh from the account as
it is (whether a second factor is required, whether codes by email are allowed, whether the account is still enabled),
so an invitation for someone who was promoted after it went out is judged on the invitation rules, not simply dead.

## Sessions

Browser sessions last `session.ttl` from sign-in (7 days) and end after `session.idle` unused (24 hours). An
organization may set shorter ones on its settings, never longer. Managers and above get `session.privileged_ttl` (12
hours) and `session.privileged_idle` (1 hour) when those are shorter. The primary organization's settings (methods,
second factor, session lifetimes) cover the super admins, so only super admins change them.

Users see their sessions of the organization on their account page and can end any of them; administrators can end a user's sessions
from the user's page. Changing a password signs the user out of every other browser and device.

## Confirming it is you

**Sensitive changes** need a recent re-authentication (signed in or confirmed within 5 minutes; the console asks with
its **Confirm it is you** dialog), and a personal API token can never make them, through the management API or SCIM (a
[service account](../SERVICE-ACCOUNTS.md) is not asked: it makes only what its scopes allow, with `manage_admins` for
administrators):

- deleting an organization;
- rotating the signing keys;
- changing the primary organization's sign-in settings;
- making someone an administrator or super admin, or creating one;
- demoting, disabling or deleting another administrator or super admin (management API only: a directory offboarding
  an administrator through SCIM still can, within the service's rules: it never touches a super admin);
- removing another user's password or authenticator app;
- issuing an invitation for a manager or administrator (an accepted invitation replaces every way they sign in).

**Account changes** (a passkey, the authenticator app, recovery codes, the primary address, connecting a sign-in
provider, an API token) need a re-authentication too, or a sign-in within 5 minutes that used the account's own second
factor. A sign-in through a provider trusted for the second factor does not count when the account has one of its own,
and an account whose second factor is a passkey confirms with the passkey, not the password alone. A
[recovery code](recovery-codes.md#confirming-it-is-you) stands in for a lost authenticator app or passkey here too.

## Protecting administrators

- **Resetting an administrator's sign-in is a super admin's change.** Sending an established manager or administrator
  a new invitation, removing their password or authenticator app, lowering their role, or changing their primary email address (where
  password resets go) needs a super admin. A manager or administrator who has not signed in yet gets the next
  invitation only from whoever issued the current one, or from a super admin. So one administrator cannot take over
  another's account.
- **Not linked by email.** Upstream providers never link a manager's or administrator's account by its email address:
  they connect the provider themselves ([providers](providers.md#who-signs-in-as-whom)).
- **No codes by email** and **no trusted provider second factor** for them: they always give their own.
- **Who may remove a super admin.** Nobody demotes, disables, locks out, end-dates or deletes themselves (nor changes their
  own end date), and only a super admin does any of that to a super admin: an administrator, a manager or a service account
  cannot. The system never does either (the sweep that disables accounts past their end date skips super admins; their end
  date still stops sign-in). These are rules about who acts on whom, not a count: there is no guarantee that a super admin
  always remains. Two super admins removing each other at the same moment on different nodes can leave none, as can an end
  date passing on the last one; `quisora invite --break-glass --super-admin primary <email>` recovers (see below).
  Organizations need no administrator of their own: super admins administer every one, so an organization's last
  administrator can be demoted or removed.
- **Locked out of the console entirely**: the [break-glass procedure](../SECURITY.md#incident-response).
