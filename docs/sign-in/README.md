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
| [Emergency sign-out and lock-out](../emergency-sign-out.md) | Ending everyone's sessions at once, or one person's access |

## Ways to sign in

Each organization chooses its methods (super admins: **Organizations** → **Edit** → **Sign-in methods**), and each
tenant can narrow them for its applications, never widen them:

- **Password** (with **Allow password reset**: a reset link by email). Users choose their passwords themselves,
  through an invitation; administrators never set them.
- **Passkeys**: as the whole sign-in, or as the second factor after a password. [More](passkeys.md).
- **Upstream providers**: each tenant offers all of the organization's providers or a chosen few.
  [More](providers.md).

New users get an **invitation link** (shown to the administrator, or emailed when the server sends email), valid for 7
days and once, with which they set a password, create a passkey, or both. An accepted invitation replaces every way
the user signed in before, so it is also how someone who lost everything gets back in.

## Second factors

**Require a second factor** on the organization (or a tenant, for its applications) makes every password or provider
sign-in also give one:

- an **authenticator app** (a 6-digit code: TOTP);
- a **passkey** after the password;
- a [code by email](email-codes.md), where the organization allows it;
- a [recovery code](recovery-codes.md), in place of either of the first two.

A user without a second factor sets one up during the sign-in (an authenticator app, with a passkey offered), or, where
codes by email are allowed, gets one by email instead. **Try another way** at the second-factor step lists what else
the account can use. Managers, administrators and super admins always need a second factor, whatever the settings,
and the console refuses a session without one. Wrong passwords and codes count towards a temporary lock-out of the
account.

Applications can also ask for a second factor for one sign-in (`acr_values=urn:quisora:acr:mfa`): see [signing users
in](../oauth/sign-in.md#requiring-a-second-factor).

## Sessions

Browser sessions last `session.ttl` from sign-in (7 days) and end after `session.idle` unused (24 hours). An
organization may set shorter ones on its settings, never longer. Managers and above get `session.privileged_ttl` (12
hours) and `session.privileged_idle` (1 hour) when those are shorter. The primary organization's settings (methods,
second factor, session lifetimes) cover the super admins, so only super admins change them.

Users see their sessions on their account page and can end any of them; administrators can end a user's sessions
from the user's page. Changing a password signs the user out of every other browser and device.

## Confirming it is you

**Sensitive changes** need a recent re-authentication (signed in or confirmed within 5 minutes; the console asks with
its **Confirm it is you** dialog), and an API token can never make them, through the management API or SCIM:

- deleting an organization;
- rotating the signing keys;
- changing the primary organization's sign-in settings;
- making someone an administrator or super admin, or creating one;
- demoting, disabling or deleting another administrator or super admin (management API only: a directory offboarding
  an administrator through SCIM still can, within the service's guards on the last super admins);
- removing another user's password;
- issuing an invitation for a manager or administrator (an accepted invitation replaces every way they sign in).

**Account changes** (a passkey, the authenticator app, recovery codes, the primary address, connecting a sign-in
provider, an API token) need a re-authentication too, or a sign-in within 5 minutes that used the account's own second
factor. A sign-in through a provider trusted for the second factor does not count when the account has one of its own,
and an account whose second factor is a passkey confirms with the passkey, not the password alone.

## Protecting administrators

- **Resetting an administrator's sign-in is a super admin's change.** Sending an established manager or administrator
  a new invitation, removing their password, lowering their role, or changing their primary email address (where
  password resets go) needs a super admin. A manager or administrator who has not signed in yet gets the next
  invitation only from whoever issued the current one, or from a super admin. So one administrator cannot take over
  another's account.
- **Not linked by email.** Upstream providers never link a manager's or administrator's account by its email address:
  they connect the provider themselves ([providers](providers.md#who-signs-in-as-whom)).
- **No codes by email** and **no trusted provider second factor** for them: they always give their own.
- **Super admins the server keeps.** Demoting, disabling, deleting or end-dating a super admin is refused when fewer
  usable super admins than the server needs would remain: one on a single node or nodes sharing a database, two in a
  gossip cluster (a change one node made but the majority has not confirmed yet must never leave none). Make someone
  else a super admin first. Organizations need no administrator of their own: super admins administer every one, so an
  organization's last administrator can be demoted or removed.
- **Locked out of the console entirely**: the [break-glass procedure](../SECURITY.md#incident-response).
