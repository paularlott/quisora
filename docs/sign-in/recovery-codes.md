# Recovery codes

Recovery codes stand in for a user's second factor (their authenticator app, or a passkey used after the password)
when it is not at hand: a lost or broken phone, a security key left at home. Each code signs in once. They do not
replace a forgotten password: that is a password reset or an invitation.

## Making them

**Your account → Password and Authenticator App → Recovery codes → Create codes…** Users can make them once they have an authenticator app
or a passkey (before that the row says to set one up first). Quisora asks them to confirm it is them if they have not
signed in within the last 5 minutes, then shows ten codes once, with **Copy** and **Download** (a
`recovery-codes.txt`), and the advice to keep them apart from the phone: in a password manager, or printed and locked
away. **I have saved them** closes the dialog; the codes are not shown again.

The row then shows how many are left (a warning when three or fewer are), and **Create new codes…** replaces them:
the old ones stop working at once, used or not. Making or dropping codes is a credential change: it moves the
account's [security generation](README.md#a-credential-change-ends-what-is-in-flight) on, so a sign-in waiting for
a second factor when the codes were remade starts again, even with one of the new codes. Using a code is not: it
finishes the sign-in it was typed into and is marked used, nothing more.

Quisora keeps only hashes of the codes, and a code used on one node is refused on every other.

A user whose authenticator app was [imported with them](../API-TOKENS.md#importing-users-with-their-passwords-authenticator-apps-and-provider-links-import)
has none yet: the row shows a warning, and the same button makes them.

## Using one

At the second-factor step of a sign-in, **Try another way** lists what the account has instead of the authenticator
code: its passkey, and **Use a recovery code** while some are left (an account with an authenticator app or a passkey
is not offered a [code by email](email-codes.md)). The code can be typed loosely: lower case, without the dash, `O` for `0` all work.

A recovery code counts as a second factor: the session's `amr` is `pwd otp mfa`. Wrong codes count towards the
account's lock-out, as wrong authenticator codes do.

Once in, the user should set up their second factor again (a new phone, a new passkey) on the account page and, if
few codes are left, make new ones.

## When someone else uses one

Every use is audited (`login.recovery_code`) and emailed to the user, with the number of codes left, so a code
someone else got hold of is noticed at its first use. A use the user did not make means someone has their password
and their codes: [lock the account out](../emergency-sign-out.md#locking-out-one-person) and send a new invitation.

## When they go

- **Create new codes** ends the old ones.
- Removing the account's last second factor removes its codes: they would have nothing to stand in for.
- An invitation (which replaces every way the user signs in) and a lock-out remove them.

## A user with no codes and no second factor

They cannot sign in on their own: **Try another way** says to ask an administrator for a new invitation. An
administrator makes one on the user's page (**New invitation link**); accepting it sets up a password or passkey and a second
factor again. Only a super admin can send a manager or administrator a new invitation link.

## Reference

| | |
| --- | --- |
| Number | 10 per set |
| Use | Once each, in place of the second factor |
| Stored | As hashes |
| Audit | `login.recovery_code` (and an email to the user) |
| Account API | `POST /api-internal/account/recovery-codes` (the account page; needs a recent re-authentication) |
