# Codes by email

An organization can let users give their second factor as a 6-digit code emailed to them. It is for people who will
not or cannot use an authenticator app or a passkey. It is **weaker** than either: whoever can read the user's
mailbox has the code, and where password resets are on, the password too. So it is off by default, never for
managers and administrators, and an organization should turn it on only where that risk is acceptable.

## Turning it on

Organization settings are a super admin's: **Organizations** → **Edit** on the organization → **Allow codes by email
as a second factor**, under **Sign-in methods**. Through the management API:

```bash
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"settings":{…the organization'"'"'s settings…,"email_codes":true}}' \
  "$QUISORA/api/orgs/acme"
```

`settings` is replaced as a whole: send every field, as read from `GET /api/orgs/acme`.

The server must be able to send email (`mail.smtp_host`, see [Email](../RUNNING.md#email)). Without it the switch is
disabled and says why, and the API refuses `email_codes: true` (`needs the server to send email`). If email is taken
away while the setting is on, it does nothing until email is back, and the switch can still be turned off.

## Who gets it

A user can receive codes by email when all of these hold:

- their organization allows it;
- their primary email address is verified;
- they are not a manager, administrator or super admin.

Everyone else signs in as before.

## How it works for users

- **Second factor required, and they have none of their own.** Instead of being asked to set up an authenticator app
  after their password, they get a code by email straight away: *"We emailed a 6-digit code to a•••@example.com. It
  expires in 10 minutes."* They type it, and they are in.
- **They have an authenticator app or a passkey.** Nothing changes, except that **Try another way** at the
  second-factor step also offers **Email a code to a•••@example.com**.

**Send a new code** asks for another; only the newest works.

## Limits

| | |
| --- | --- |
| Code | 6 digits, random |
| Lasts | 10 minutes, once, and only for the sign-in it was sent for |
| New codes | At most one every 30 seconds, and five per sign-in |
| Wrong codes | Count towards the account's lock-out, as wrong authenticator codes do |
| The session | `amr` is `pwd otp mfa`: it counts as a second factor for applications and for `acr_values=urn:quisora:acr:mfa` |

Codes are kept only as hashes, tied to the sign-in they were sent for.

## Audit

Every code sent is audited (`login.email_code.sent`), on the user, with the address it came from. One the user did
not ask for means someone has their password: reset it, and check who can read their mailbox.
