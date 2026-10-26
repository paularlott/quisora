# Passkeys

A passkey signs a user in with their fingerprint, face or device PIN instead of a password. It is a key pair made by
their device or password manager: the private key never leaves it, and Quisora keeps only the public key. Passkeys
cannot be phished (they only work on Quisora's own address), reused or guessed. One sign-in with a passkey counts as
two factors: something the user has (the device) and something they are or know (the fingerprint or PIN).

## Turning them on

Passkeys are on by default. The organization's **Passkeys** switch (super admins: **Organizations** → **Edit**) and
each tenant's **Passkey** switch decide whether users may *sign in* with a passkey; a tenant cannot turn it on where
the organization has it off. A passkey used as the second factor after a password works either way.

Passkeys need nothing in the configuration. They are tied to the host name of `server.public_url` (the WebAuthn
"relying party"), with the site's name (`ui.site_name`) shown in the browser's prompts, so:

- `server.public_url` must be a host name, not an IP address: with an IP address passkeys are unavailable (the
  server logs `passkeys disabled`, and the pages say *Passkeys are not available on this server.*);
- changing the host name makes every existing passkey stop working: users must add new ones.

## Adding a passkey

- **On the account page:** **Passkeys → Add passkey**. The user names it (the browser suggests one, such as "Chrome
  on Mac"), and their device asks them to confirm. If they have not signed in within 5 minutes with their second
  factor, Quisora asks them to confirm it is them first. Up to 20 passkeys per account.
- **When accepting an invitation:** **Create a passkey** (where the organization allows passkey sign-in), instead of
  or as well as a password.
- **When a second factor is required and the user has none:** **Use a passkey instead** at the set-up step.

Every passkey must verify the user (a PIN, fingerprint or face): a security key without a PIN is refused with *the
authenticator did not verify the user (set up a PIN or biometrics on it)*. The same authenticator cannot be added
twice to one account. Quisora asks for no attestation: it does not restrict which makes of authenticator can be used.

Adding or removing a passkey moves the account's [security generation](README.md#a-credential-change-ends-what-is-in-flight)
on: a sign-in step, set-up, re-authentication or link begun before it stops working. The set-up step at sign-in is
only for an account with no second factor: once one passkey is added, every other browser holding the password is
sent back to sign in with it, and a ceremony begun before the account changed does not finish.

The account page lists each passkey with its kind (a **synced** passkey, kept in a password manager or a platform's
keychain and on every device of the user's; or a **device-bound** one, such as a security key), when it was added
and when it was last used. Users can rename one, or delete it (after confirming it is them): deleting ends the
sessions that signed in with it. Quisora refuses to delete the last passkey of an account that needs it: when a
second factor is required and there is no authenticator app (*Set up an Authenticator App first*), or when it is the
only way to sign in at all.

## Signing in with a passkey

- **On its own:** the sign-in page's **Sign in with a passkey** button, or the passkey offered by the browser's
  autofill in the email field. No password and no further second factor are asked: the session's `amr` is
  `["hwk","user"]` (a device-bound key) or `["swk","user"]` (a synced one), which counts as a second factor for
  applications and the console.
- **As the second factor after a password:** an account with a passkey and no authenticator app is asked *"Your
  organization asks for your passkey as well as your password"* (**Confirm with your passkey**). One with an
  authenticator app is offered **Use your passkey instead** under **Try another way**. The session's `amr` is then
  `["pwd","swk","user","mfa"]` or similar.
- **To confirm it is them** before a sensitive change: **Use a passkey instead** in the "Confirm it is you" dialog. An
  account whose second factor is a passkey must confirm with it, not with the password alone.

A passkey of another organization is refused. [Recovery codes](recovery-codes.md) stand in for a passkey that is not
at hand.

## Copied authenticators

An authenticator's signature counter must go up with each use. When a sign-in shows it did not (against the passkey as
this node has it, or, when two sign-ins with the same authenticator are stored at the same moment, as the cluster has it:
the second one presents a counter at or below the stored one), the passkey may have been copied: Quisora disables it at once, ends every session that signed in with it, tells the applications
(back-channel logout), and records `passkey.clone`. The user sees it marked **Disabled** on their account page, with
the advice to delete it and change their password. (Synced passkeys do not use counters, so this applies to security
keys and other device-bound ones.)

A passkey marked **Cannot sign in** was added before user verification was required: delete it and add it again.

An account whose only second factor is a passkey that can no longer be used cannot sign in with its password alone:
*"Your passkey can no longer be used to sign in. Ask an administrator for a new invitation."* Quisora keeps the
unusable passkey as evidence that the account had a second factor, so that whoever has the password cannot simply
set up a new one.

## For administrators

The user's page in the console lists their passkeys (kind, added, last used, any problem) with **Remove**, for a lost
or replaced device: removing one stops it signing them in and ends the sessions that signed in with it. If it was
their only way to sign in, send them a **New invitation link**. Through the API:

```bash
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/users/<user id>/passkeys"
curl -X DELETE -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/users/<user id>/passkeys/<passkey id>"
```

The list never contains the credential or its public key.

- An accepted invitation replaces every way the user signed in, passkeys included (apart from one made while
  accepting it).
- A [lock-out](../emergency-sign-out.md#locking-out-one-person) removes them all.
- The console needs a sign-in with a second factor: a passkey sign-in is one.

## Audit

| Event | When |
| --- | --- |
| `account.passkey.add` | A user added a passkey (also while setting up their second factor at sign-in) |
| `account.passkey.delete` | A user deleted one of theirs |
| `user.passkey.remove` | An administrator removed one |
| `passkey.clone` | A copied authenticator was suspected; the passkey was disabled |
| `login.failure` | With reasons such as `passkey disabled or unverified` or `passkey for another organization` |

## What is stored

The public key, the credential's id, its name, the authenticator's model id (AAGUID), the signature counter, whether
it can be synced, and when it was added and last used. No attestation, no biometric data: fingerprints and faces never
leave the user's device.
