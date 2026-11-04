# Emergency sign-out and lock-out

Two levers for when something has gone wrong:

- **Emergency sign-out** ends every session of an organization, or of every organization, at once, on every node:
  for when an attacker may hold sessions or tokens and you do not know whose.
- **Lock out** does the same for one person, and also takes away every way they had to sign in: for a compromised
  account, or someone who has left.

What to do around them (finding out what an attacker did, what to rotate) is in the
[incident response](SECURITY.md#incident-response).

## Emergency sign-out

### From the console

- **One organization**: its **Overview** page → **Sign everyone out…** (its administrators and super admins; for
  the primary organization, which holds the super admins, super admins only).
- **Every organization**: **System overview** → the same button (super admins).

The dialog asks for a **Reason** (recorded in the audit log), whether to **End personal API tokens too**, and for the
organization's name (or `everyone`) to be typed. If you have not signed in or confirmed it is you in the last 5
minutes, it asks for that first.

### From the API

From a browser session (the console's own API). An API token cannot pull it, so a stolen token cannot be used to lock
everyone out:

```bash
curl -X POST -b cookies.txt -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"reason":"Suspected session theft","api_tokens":false}' \
  "$QUISORA/api/orgs/acme/sign-out"           # or /api/sign-out for every organization
```

### From the command line

For when the console cannot be used. It needs the master key and the same settings as `serve` (config file or
`QUISORA_*` environment):

```bash
quisora sign-out --org acme --reason "Suspected session theft"
quisora sign-out --all --reason "Suspected session theft" --api-tokens
```

It asks you to type the organization's name (or `everyone`) unless given `--yes`.

- **Shared database** (PostgreSQL, MySQL, MariaDB): it writes to the database while the servers run; they follow
  within seconds. It prints what it removed.
- **BadgerDB or SQLite on one node**: it asks the running server at `server.public_url` (or `--server`), signing the
  request with the master key, as `quisora invite` does; the server removes what it ended in the background. With the
  server stopped, it writes to the store itself and prints what it removed.
- **Gossip cluster**: it always asks a running node (`server.public_url` or `--server`), which writes the sign-out
  through the cluster like any other change, so the nodes, or a majority of them, must be running. Run it from any
  node's configuration. It never writes to a stopped node's database: a change made there would reach no other node.

A request through a server is good for two minutes and once, a server takes at most 10 a minute from one address, and
the audit log records it as the command (`command:sign-out`, from the address it came from). `--ca-file` adds
certificates to trust for the server, and `--insecure` skips the check.

### What ends, and what does not

Ended, at once, on every node:

- every browser session of the organizations affected (a browser holds one session per organization), including the
  console's (your own session stays);
- every refresh grant, so applications cannot get new tokens, and the access tokens issued from those grants stop
  working at userinfo and introspection;
- with the option, every personal API token, for good. (Turning off the organization's setting for who may make `api`
  tokens only stops them while it is off; see [API-TOKENS.md](API-TOKENS.md#who-may-make-api-tokens).)

The [SSH certificates](ssh/README.md#revocation) the organizations' tenants issued before it go on their revocation
lists within 30 seconds, and a server refuses them when it next fetches the list (a minute or two with the timer in
the guide), and a session already open on a server stays open. Host certificates are not affected. (Ending a single session,
or revoking one application's grant, does not revoke certificates already issued; signing a person out everywhere, a
lock-out or this does.)

Applications are told through back-channel logout, and the ended records are deleted in the background. Signing in
again works straight away: nothing about the accounts changes.

Not ended:

- tokens of applications acting for themselves ([client credentials](oauth/client-credentials.md)): rotate the
  client's secret or disable the client;
- access tokens already in the hands of applications that verify them themselves rather than through
  introspection, until they expire (`tokens.access_ttl`, 10 minutes by default). Shorten that setting if this
  window matters to you.

It is audited as `org.signout` (one organization) or `server.signout` (all), with the reason and the counts.

### How it works

Each organization, and the server as a whole, keeps a sign-out counter, and every session, grant and API token is
stamped with the counters when it is made. Pulling the lever increments a counter in one write, which the cluster
confirms like any other; from then on everything stamped before it is refused. So it does not depend on the nodes'
clocks, and it cannot be half done. The counters are part of backups and are kept on the primary organization, which never
changes, so nothing a sign-out ended comes back with a restore.

### In a gossip cluster

- **It needs a majority of the cluster.** The counter is a write like any other (to the organization's record, in the
  global partition), committed only when a majority of `cluster.size` has stored it. With fewer than a majority of the
  nodes up the lever is refused, nothing ends and nothing is half done: get a majority running and pull it again.
- **A node cut off from the majority cannot learn of a sign-out the others made, and serves nothing.** It is not ready:
  its pages, APIs and token, userinfo and introspection endpoints all answer 503 at once, so it honours no session, grant or
  API token the lever ended elsewhere; when it meets the others again it learns the counters and refuses what they ended.

## Locking out one person

On the user's page in the console: **Lock out…**, or through the API:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"reason":"Laptop stolen"}' "$QUISORA/api/orgs/acme/users/<user id>/lock-out"
```

It disables the account and, at once:

- signs them out everywhere: sessions and refresh grants end, and applications are told; the consent they gave
  applications is forgotten, so each asks again;
- removes every way they had to sign in: password, authenticator app, passkeys, recovery codes, linked providers;
- removes their personal API tokens and any unused invitation, reset and verification links;
- puts their [SSH certificates](ssh/README.md#revocation) on the revocation list, so servers refuse them within a
  minute or two (a session already open stays open).

The account itself stays, for the audit log. Enabling it again brings none of that back: send them a **New invitation
link** to set up their sign-in again. It is audited as `user.locked_out`, with the reason. You cannot lock yourself
out, and locking out a manager or administrator follows the rules for resetting their sign-in (a super admin's
change).

Use it for a compromised account (after which the owner gets a fresh start through an invitation) and for leavers.
