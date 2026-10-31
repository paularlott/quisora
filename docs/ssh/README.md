# SSH certificates

Quisora can act as the SSH certificate authority of a tenant. People sign in to Quisora with a second factor and get a
short-lived OpenSSH certificate for their key. Servers trust the tenant's CA key instead of a list of user keys, and the
certificate's principals (the person's username, `group:<name>` for each of their groups, `role:<role>` for each
application role) decide who may log in as which Linux account. Access is managed in Quisora: remove someone from a
group, disable them or sign them out, and their certificates stop working within a minute or two, with no key to remove
from any server.

Quisora signs **user certificates** for people and, if you turn it on, **host certificates** for servers, so that
people's ssh clients trust a server without asking about its key. It never sees a private key: it signs the public key
it is given.

```
Workstation                              Quisora                                   Server (sshd)
  │ quisora ssh login ───────────────▶  │ sign in, second factor                         │
  │ ◀─── certificate: principals, 8 h   │                                                │
  │                                     │ ◀── quisora ssh fetch, every minute ────────── │
  │                                     │ ──▶ CA public keys, revocation list (KRL) ───▶ │
  │ ssh ubuntu@server (key + certificate) ─────────────────────────────────────────────▶ │
  │         sshd checks: CA trusted? not revoked? in date? a principal listed in principals/ubuntu?
```

The public addresses are under the organization's issuer, `https://id.example.com/o/<org id>`; a tenant's SSH address, the
**discovery URL** the commands start from, is `https://id.example.com/o/<org id>/ssh/<tenant id>`. Use the tenant's
**id** (the console and the account page show it that way): the tenant's name works in the address too, but a tenant
that is renamed no longer answers to its old name, and a server still fetching from it gets `404` and goes on with its
last copy of the files, which stops its revocations without any other sign than a failing fetch.

**What to know before you start.**

- A certificate is checked when someone connects. Revoking one, or ending a person's access, stops new logins within a
  minute or two ([Revocation](#revocation)); it does not close sessions already open.
- The revocation list must always be present on the server, or sshd refuses every public-key login
  ([Why the revocation list must always be there](#why-the-revocation-list-must-always-be-there)).
- Quisora does not create Linux accounts. Each account people log in as must exist on the server
  ([Linux accounts](#linux-accounts-must-exist)).
- Always match certificates to accounts with `AuthorizedPrincipalsFile`, never with sshd's default (the principal must
  equal the login name), and do not map privileged accounts such as `root` by username: people who can create or rename
  users decide what a username is ([Principals](#principals)).
- A revoked or removed **host** certificate is refused only by clients that set `RevokedHostKeys`; sshd's `RevokedKeys`
  covers user logins only ([Host certificates](#host-certificates)).
- Certificates already issued go on working while Quisora is down, but nobody can get a new one. Keep a way into your
  servers that does not depend on Quisora ([If Quisora is not reachable](#if-quisora-is-not-reachable)).
- Someone can start a device sign-in on their own machine and send a victim the code. If the victim enters it, the
  attacker gets a certificate with the victim's principals ([Risks](#risks)).

## Turning it on for a tenant

In the console: the organization → **Tenants** → the tenant's **SSH** column (or the tenant → **Manage SSH certificates**) →
the tenant's SSH page (`/admin/orgs/<org>/tenants/<tenant>/ssh`) → **Enable SSH certificates**. The tenant page itself has
only a summary card that says whether SSH is on, and the **Tenants** list an **SSH** column (On or Off) that opens the page.
The first time, Quisora makes the tenant's user CA key (and a host CA key if host certificates are on) and an
application named **SSH**, which people sign in through to get certificates. It is a public, first-party client with the
authorization code and device sign-in grants, listed on the tenant's **Clients** page. It uses bearer access tokens, not
DPoP ([Known limits](#known-limits)). Do not disable or delete it. While it is disabled or missing nobody can get a
certificate, and every certificate goes on the revocation list (reason `app_unavailable`) until it is back. While SSH is on,
Quisora's housekeeping makes a new application within a minute when it was deleted (saving the settings does it at once),
and the certificates count again: **deleting the application does not cut anyone off. To cut access, turn SSH off.**
**Edit SSH settings** changes the settings below.

Through the management API, with a [personal API token](../API-TOKENS.md) that has the `admin` scope, or a
[service account](../SERVICE-ACCOUNTS.md) with the `ssh` scope. `{tenant}` is the tenant's name or id:

```bash
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled": true, "cert_ttl": 28800, "principal_groups": true}' \
  "$QUISORA/api/orgs/acme/tenants/prod/ssh"
```

Settings you leave out keep their values. The answer is the settings, the CA keys (`keys`, each with its `fingerprint`
and `state`) and the addresses people and servers use (`endpoints`: `discovery`, `ca_pub`, `known_hosts`, `krl`,
`host_sign`); `GET` on the same address shows them again. A setting out of range answers `422` with the field named,
such as `ssh.cert_ttl`.

While SSH is on, at least one of the three principal settings must be on (`422`, field `ssh.principal_username`).
The lists (`source_addresses`, `host_patterns`) hold at most 32 entries: a longer list is refused before it is read.

### Turning it off, and removing a tenant

Turning SSH off **revokes every certificate of the tenant**. Signing stops (`404` from the sign endpoint, and the
account page does not offer the tenant), and the discovery document answers `"enabled": false`, but the CA keys, the
known hosts and the revocation list stay published. The list then revokes every CA key of the tenant outright, which
revokes everything they signed, user and host certificates alike (sshd checks a certificate's CA key against the list
too, so a server whose CA file still names the keys distrusts them), and names the user certificates that have not
expired (reason `ssh_off`). Servers drop them when they next fetch the list, within the revocation delay
([How soon](#how-soon)). Servers that run `quisora ssh fetch` need no change. The CA keys are kept, and the tenant's
SSH application is disabled (by the system, `client.update` in the audit log), so no one can sign in to it either.
Turning SSH on again enables the application and makes the certificates valid again unless they were revoked otherwise
(a certificate revoked by hand, or because its user lost access, stays revoked). A tenant that never had SSH enabled
answers `404` everywhere.

Host certificates are revoked by the same list, but only clients that set `RevokedHostKeys` honour it
([Clients and host certificate revocation](#clients-and-host-certificate-revocation)).

A **tenant cannot be deleted while SSH is on** (`409`: turn SSH off first), and neither can an organization that has
such a tenant, with or without `cascade`. The order is:

1. Turn SSH off.
2. Wait until the servers have fetched the list that revokes everything: the fetch interval plus the list's 30 seconds
   in the cache, so a few minutes with the timer below. On a server, `ssh-keygen -Q -f /etc/ssh/quisora.krl
   /etc/ssh/quisora_user_ca.pub` prints `REVOKED` once it has. After the tenant is deleted there is no list left to
   fetch, and a server that had not fetched yet goes on trusting the CA keys it has until the certificates expire.
3. Delete the tenant. Its SSH application is deleted with it, by the system (`client.delete` in the audit log), and so is
   any other SSH application Quisora made for the tenant and no longer uses; any other application still blocks the
   deletion. Its CA keys and certificate records are removed in the background. If SSH is turned on again between the
   check and the deletion, the deletion fails (`409`, someone else changed it) rather than go ahead.
4. Take the tenant's set-up away: on every server remove the sshd drop-in (`TrustedUserCAKeys`, `RevokedKeys`,
   `AuthorizedPrincipalsFile`) and the fetch timer and service, then `sshd -t`, reload sshd, and delete the files;
   on every client remove the `RevokedHostKeys` and `GlobalKnownHostsFile` lines, then the host files. Take the
   configuration line out **before** the file it names: sshd and ssh refuse every login or connection when a
   `RevokedKeys` or `RevokedHostKeys` file is missing.

### Who may get a certificate

Anyone who could sign in to the tenant's applications: when the tenant is open to everyone in the organization,
everyone; when it is members-only, the people and groups on its access list whose entry covers the SSH application,
within their end dates. To keep SSH to the operations team on a members-only tenant, give only that group access (an
access entry can be limited to chosen applications, so the SSH application can be the only one it covers). An entry
limited that way names the application by its client id: **do not delete the SSH application** to stop certificates.
While SSH is on Quisora makes a new one within a minute (logged as a warning, and audited `client.create` by `system`
with the client id it `replaces`), which has a new client id: entries that named the old one do not cover it, so their
people lose access, and since a lost access is written down, their certificates stay revoked. Turn SSH off instead; to
give the new application to such entries, edit them. On top of that, a certificate is refused unless:

- the sign-in used a second factor (password and an authenticator app or an emailed one-time code, or a passkey that
  verified the user) and is no older than **Sign-in age**;
- the sign-in the request comes from has not ended: a session signed out everywhere, a credential reset or an emergency
  sign-out since it began refuses it (`session_ended`);
- the account is usable (not disabled, locked out, or past its end date);
- the tenant's SSH application is enabled (`app_unavailable`; Quisora disables it while SSH is off and enables it again
  with SSH);
- the person is not a manager or administrator, unless the tenant allows it ([Managers and administrators](#managers-and-administrators));
- there is at least one principal to put in it;
- the person has fewer than 100 user certificates for the tenant that have not expired, **revoked ones included**: a
  revoked certificate stays on the revocation list until it expires, so revoking does not make room (`too_many`: the
  refusal says when the first of them expires);
- the public key is an ed25519, ECDSA (P-256, P-384 or P-521) or RSA key of at least 2048 bits, or a security key
  (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`). DSA keys, short RSA keys and keys that are
  already certificates are refused.

An emailed code is a second factor like the others here. Where that is too weak for your servers, limit the tenant's
sign-in methods ([sign-in](../sign-in/README.md#ways-to-sign-in)), for example to passkeys.

### The settings

In the console the lifetimes are in minutes; in the API they are in seconds.

| Console | API (`PATCH`) | Default | What it does |
| --- | --- | --- | --- |
| **Enable SSH certificates** | `enabled` | off | Off: no signing, and every certificate and CA key is revoked until it is on again ([turning it off](#turning-it-off-and-removing-a-tenant)). |
| **Certificate lifetime** | `cert_ttl` | 28800 (8 hours) | 300 to 86400 seconds. People may ask for a shorter one. A certificate never outlasts the account's end date. |
| **Sign-in age** | `max_auth_age` | 3600 (1 hour) | 60 to 86400 seconds: how recent the sign-in must be when a certificate is asked for. |
| **Principals** → **Username** | `principal_username` | on | The user's username is a principal. At least one of the three must be on. |
| **Names of the user's groups** | `principal_groups` | on | `group:` and the name of each of the user's groups are principals, such as `group:ops`. |
| **Application roles** | `principal_roles` | off | `role:` and each role the tenant's access list gives the user are principals, such as `role:deploy` (a members-only tenant). |
| **What a session may use** → **Terminal (pty)** | `permit_pty` | on | The certificate's `permit-pty` extension. |
| **~/.ssh/rc** | `permit_user_rc` | on | `permit-user-rc`. |
| **Port forwarding** | `permit_port_forwarding` | off | `permit-port-forwarding`. |
| **Agent forwarding** | `permit_agent_forwarding` | off | `permit-agent-forwarding`. |
| **X11 forwarding** | `permit_x11_forwarding` | off | `permit-X11-forwarding`. |
| **Source addresses** | `source_addresses` | none | Addresses or CIDR ranges the certificate works from ([Source addresses](#source-addresses)). At most 32. |
| **Managers and administrators may get certificates** | `allow_privileged` | off | See [below](#managers-and-administrators). |
| **Rotate the user CA key every (days)** | `rotation_days` | 0 | 8 to 3650, or 0 to rotate by hand only ([CA key rotation](#ca-key-rotation)). |
| **Sign host certificates** | `host_certs` | off | Lets servers get host certificates. Needs `host_patterns`. |
| **Host certificate lifetime (days)** | `host_ttl_days` | 90 | 1 to 365. |
| **Host names allowed** | `host_patterns` | none | Patterns host names must match, such as `*.example.com` or `db1.internal`. At most 32. |

`client_id` in the answer is the SSH application's id; it is not set by hand.

**Tightening applies to certificates already issued; loosening does not.** A certificate that is still valid and
grants more than the settings would give now is put on the revocation list (reason `settings_changed`): one whose lifetime
is longer than **Certificate lifetime**, one with an extension that is no longer on, and, when source addresses are set,
one made with other addresses. People get a new certificate by signing in again. A longer lifetime, an extension turned
on, or source addresses removed change only the certificates made afterwards. The revocation follows the settings, so
putting the setting back brings those certificates back. Lowering the lifetime therefore revokes every live certificate
that was made with the longer one, within a minute or two.

### Principals

A user certificate carries the principals the settings give the person, sorted:

| Source | Setting | Principal | Example |
| --- | --- | --- | --- |
| The username | `principal_username` | the username as it is | `alice` |
| Each group the user is in | `principal_groups` | `group:` and the group's name | `group:ops` |
| Each application role the tenant's access list gives the user | `principal_roles` | `role:` and the role | `role:deploy` |

The name part (the username, the group's name, the role) is used only if it is 1 to 64 letters, digits, `.`, `_`, `@`
or `-`: a group called `Site Reliability` (with a space) gives no principal, and neither does a username with a `+` or
a non-ASCII letter. Names are case-sensitive. A person can ask for a subset, in the prefixed form
(`quisora ssh login --principal group:ops`).

**Why there are prefixes.** A username can never contain a colon, so no username can equal a `group:` or `role:`
principal. Managers can create and rename users. Had a group's principal been the bare name, a manager could have made
a user named `ops`, and that user would carry the principal that `/etc/ssh/principals/ubuntu` gives to the group. Now
the only way to carry `group:ops` is to be in the group `ops`.

**The username principal is only as strong as who may name users.** It equals the person's login name, and managers
(and administrators) can create and rename users. So:

- Always set `AuthorizedPrincipalsFile` (the [setup](#setting-up-an-ubuntu-server) does). Without it sshd accepts any
  certificate from a trusted CA that carries the login name as a principal, so a user named `root` or `ubuntu` would be
  let in as that account.
- Do not map privileged accounts by username: no `/etc/ssh/principals/root` that lists a username, and none for an
  account that can become root. Give them a `group:` principal, and keep the membership of such groups small and
  reviewed. Managers can add people to groups, which is the same as granting them every login the group's principal is
  listed for.
- Delete the Linux account of someone who leaves. A new user given the same username would otherwise reach it.

A certificate that cannot get any principal is refused. Turning a principal source off, or removing someone from a
group, is not ignored by certificates already issued: they are revoked if they carry a principal the person would not get
now ([Revocation](#revocation)), and so does renaming a user or a group. Adding someone to a group changes nothing until
they get a new certificate.

## Setting up an Ubuntu server

Nothing is needed beyond `openssh-server` (already there on Ubuntu Server), and the `quisora` binary or `curl`. Nothing
on the server needs Quisora's configuration or its master key: the server only reads three public addresses. The steps
are for Debian and Ubuntu; [other distributions](#other-distributions) differ in two names.

Take the discovery URL from the console (the tenant's SSH page has a **Set up servers and people** section with these
commands, the URL filled in) or from `endpoints.discovery` in the API:

```bash
export URL=https://id.example.com/o/<org id>/ssh/<tenant id>
```

**1. Install the binary.** Copy `quisora` (built with `task build`, a single static file) to the server:

```bash
sudo install -m 0755 quisora /usr/local/bin/quisora
```

No binary? `curl` does the same job, with fewer checks: [see the end of this section](#without-the-quisora-binary).

**2. Fetch the CA key and the revocation list once, by hand.**

```bash
sudo quisora ssh fetch "$URL"
# updated /etc/ssh/quisora_user_ca.pub (user CA keys)
# updated /etc/ssh/quisora.krl (revocation list)
```

**3. Check the CA key's fingerprint against the console.** This is the one moment the server trusts what it is
given, so compare it out of band: the fingerprint in the **CA keys** table of the tenant's SSH page (or `keys[].fingerprint` from the
API) must be the one on the server.

```bash
ssh-keygen -lf /etc/ssh/quisora_user_ca.pub
# 256 SHA256:Hq7… quisora:acme/prod:user:<key id> (ED25519)
```

If the tenant is mid-rotation the file holds more than one key, one line each.

**4. Tell sshd to trust it.** Ubuntu's `sshd_config` includes `/etc/ssh/sshd_config.d/*.conf`, so a drop-in leaves the
main file alone. `/etc/ssh/sshd_config.d/50-quisora.conf`:

```
TrustedUserCAKeys /etc/ssh/quisora_user_ca.pub
RevokedKeys /etc/ssh/quisora.krl
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

`AuthorizedPrincipalsFile` is how a certificate is matched to a Linux account: sshd logs the person in as `<account>`
only if one of the certificate's principals is a line of `/etc/ssh/principals/<account>`. An account with no such file
cannot be logged in to with a certificate. It does not affect keys in `authorized_keys`, which keep working. Never leave
it out: it is what stops the username principal from being a login name ([Principals](#principals)).

**5. Say who may log in as which account.** One file per Linux account, one principal per line, in the prefixed form:

```bash
sudo mkdir -p /etc/ssh/principals
echo group:ops | sudo tee /etc/ssh/principals/ubuntu   # members of the group "ops" may log in as ubuntu
echo alice | sudo tee /etc/ssh/principals/alice        # the user "alice" may log in as alice
```

Use `group:` (or `role:`) principals for shared and privileged accounts and usernames for personal, unprivileged ones.
Keep the list in your configuration management; Quisora does not write to the server.

**6. Check the configuration and reload sshd.** Keep your current session open until a second one works.

```bash
sudo sshd -t && sudo systemctl reload ssh
sudo sshd -T | grep -iE 'trustedusercakeys|revokedkeys|authorizedprincipalsfile'
```

sshd reads the CA file and the revocation list again at every login, so later `fetch` runs need no reload.

**7. Keep the files current with a systemd timer.** The CA key changes when it is rotated, and the revocation list
whenever a certificate is revoked or someone's access ends, so fetch every minute.
`/etc/systemd/system/quisora-ssh-fetch.service`:

```
[Unit]
Description=Fetch the SSH CA keys and revocation list from Quisora
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/quisora ssh fetch https://id.example.com/o/<org id>/ssh/<tenant id>
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/etc/ssh
```

`/etc/systemd/system/quisora-ssh-fetch.timer`:

```
[Unit]
Description=Fetch the SSH CA keys and revocation list every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=1min
AccuracySec=5s
RandomizedDelaySec=15s

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quisora-ssh-fetch.timer
systemctl list-timers quisora-ssh-fetch.timer
journalctl -u quisora-ssh-fetch.service -n 20
```

`RandomizedDelaySec=` spreads the servers over a few seconds instead of all of them asking in the same second after a
boot or a minute tick. It matters when many servers share one address ([Servers behind one address](#servers-behind-one-address)).
It adds up to 15 seconds to the revocation delay.

**What `quisora ssh fetch` does.** It exits 0 when the files are current and 1 when not (a failed run shows in
`systemctl --failed`). It fetches the user CA keys, the host CA lines and the revocation list, checks all three, and then
replaces each file that changed with a temporary file beside it and a rename. If the server cannot be reached, or
answers with something that is not a public key list or a revocation list, it changes nothing: **the last good copy stays
in use**. It installs the revocation list only if

- it parses strictly, and `ssh-keygen -Q -l -f` reads it too when `ssh-keygen` is installed (sshd refuses every login
  when it cannot read its list);
- it has a certificates section for at least one CA key the tenant publishes (a list made for another tenant protects
  nothing, so the CA keys and the host CA lines are always fetched along with it, whether or not they are written). A
  section for a key that is not published is ignored: an answer that is 30 seconds old, or an old `ca.pub` from a proxy,
  has that after a rotation, and refusing it would stop the CA file from being updated too;
- it is not older than the one in place, unless it revokes something the one in place does not. The list's version is
  the clock of the node that made it, which can run ahead and be set back, so an older list that revokes more (a
  serial, key id or key the installed one lacks) is installed all the same, and so is any list when the installed one's
  version is more than 10 minutes in this server's future. An older list that revokes nothing more (a node that kept an
  answer for 30 seconds) is not installed: `fetch` prints `note: the server's revocation list (version …) is older than
  the one in … (version …) and revokes nothing more: keeping the installed one`, updates the other files and exits 0.

The CA key and known hosts files are written only when their content changed. The revocation list carries the time it
was made, so a new copy differs from the old one nearly every time: `fetch` writes it whenever the bytes differ, and
**the file's modification time shows when the last successful fetch was**, but it prints `updated` for the list only when
what it revokes changed ([Monitoring](#monitoring)). Add `--known-hosts-file <path>` to also write the host CA lines,
`--ca-file` and `--krl-file` to use other paths (an empty value, `--ca-file=`, leaves that file alone), and
`--ca-cert <pem>` if Quisora is served with a private CA's certificate.

Then try it from a workstation ([Signing in from a workstation](#signing-in-from-a-workstation)).

### Other distributions

| | Debian, Ubuntu | RHEL, Fedora and relatives |
| --- | --- | --- |
| sshd's service | `ssh` (`systemctl reload ssh`) | `sshd` (`systemctl reload sshd`) |
| Where the three lines go | `/etc/ssh/sshd_config.d/50-quisora.conf` | Fedora and RHEL 9 include `/etc/ssh/sshd_config.d/*.conf` (look for the `Include` line in `/etc/ssh/sshd_config`), so a drop-in works. RHEL 8's `sshd_config` has no such line: add the three lines to `/etc/ssh/sshd_config` itself, above any `Match` block (a line below one applies only to it). |

sshd uses the first value it finds for an option. If the main file sets one of these options (`AuthorizedPrincipalsFile` in
particular) before the line that includes the drop-ins, that value wins and the drop-in's is ignored: check the result
with `sshd -T`. Use the right service name in the unit and the commands above.

### Servers behind one address

The public addresses are limited per client address and tenant: 16 000 units a minute, where an answer with a
document costs 4 units and one that is `304 Not Modified` or refused costs 1. The tenant is counted by its id, so
naming it by its id or its name in the URL is one budget; the addresses of tenants that do not exist share one more
budget for each client address. One `quisora ssh fetch` run asks for four documents (the discovery document, `ca.pub`, `krl` and `known_hosts`) and the command does not send `If-None-Match`,
so each run costs 16 units: **about a thousand servers a minute behind one address** (a NAT gateway, a proxy) before
`429`. A fetch refused that way fails and keeps the old files, so it costs freshness, not access. For a larger fleet behind
one address:

- keep `RandomizedDelaySec=` in the timer, so the servers do not all ask in the same second;
- fetch less often (every two or three minutes), which lengthens the revocation delay by that much;
- or fetch through a proxy or a mirror of your own that revalidates with `ETag` (a revalidation costs 1 unit).

A user running `quisora ssh login` from the same office uses a few more of the same budget.

### Why the revocation list must always be there

`RevokedKeys` applies to every public-key login on the server, not only to certificates. If the file is missing or
cannot be read, sshd cannot tell whether a key is revoked and refuses the login (it logs `Error checking
authentication key … in revoked keys file`): that includes your own `authorized_keys` login. Three consequences:

- Run the first `fetch` (step 2) before the drop-in is in place, and keep a second session open when you reload sshd.
- An empty revocation list is valid and is what a tenant with nothing revoked gets, so there is always something to
  fetch while SSH is on.
- Never delete the file to "reset" it. `fetch` keeps the previous copy through any outage, which is why a Quisora
  outage does not stop certificates that were already issued from working. The cost is that during an outage
  revocations are not picked up: they arrive with the first successful fetch.

### If Quisora is not reachable

"A Quisora outage does not lock anyone out" is true only for **certificates already issued**: they go on working until
they expire (at most **Certificate lifetime**, 8 hours by default, 24 at most), and servers keep the last good copy of the
CA keys and the list. Nobody can get a **new** certificate while Quisora, or the sign-in it needs (a provider, the
mail server for emailed codes), is down, so once the lifetimes run out nobody can log in with one. Revocations made
meanwhile are not picked up, either. Plan a way in that does not depend on it:

- **An emergency key.** Put an offline ed25519 key in `authorized_keys` of one named account on each server, for use
  only when Quisora is down (a passphrase-protected key, or a hardware key, kept in a safe, not in a person's agent).
  `authorized_keys` keeps working beside certificates, and `AuthorizedPrincipalsFile` does not touch it. `RevokedKeys`
  **does** apply to it, so the revocation list file must still exist and be readable: a server that has lost it refuses the
  emergency key too.
- **Or console access** to the machines: the cloud provider's serial console, a hypervisor console or an out-of-band
  controller, with a local password that you have tested.
- **Do not make Quisora's own hosts depend only on Quisora certificates**: the servers that run Quisora, its database and
  its network path need a login that works when Quisora does not, or nobody can fix it.
- Use the emergency login in a drill, and alert on its use (sshd's log shows the key's fingerprint).
- A longer **Certificate lifetime** (24 hours at most) rides through a longer outage, and lengthens the time a stolen
  certificate stays good by as much. It is not a substitute for the emergency login.

### Linux accounts must exist

Quisora decides who may present a certificate for which principal; it does not create the account on the server. A
person whose certificate is accepted by sshd but whose account does not exist is refused like any unknown user.
Create accounts with your configuration management, or by hand:

```bash
sudo adduser --disabled-password --gecos "" alice
```

On Ubuntu, sshd runs with `UsePAM yes`, which lets a passwordless account log in with a certificate. If sshd says an
account is locked, set its password field to `*`: `sudo usermod -p '*' alice`.

Shared accounts need no more: one account (`ubuntu`, `deploy`) whose principals file lists the groups that may use it.
Everyone who logs in as it is still named in the audit log (the certificate's key id is `<username>@<org>/<user id>`)
and in sshd's log ([Reading sshd's log](#reading-sshds-log)).

### Without the quisora binary

Two `curl` calls do the work. This script (`/usr/local/sbin/quisora-ssh-fetch`) keeps the last good copy, checks that
the revocation list parses with `ssh-keygen`, and revalidates with the `ETag` it saved, so an unchanged document is a
`304` that costs 1 unit instead of 4. On a `304` it touches the file it keeps, so the file's age still says when the
last fetch succeeded ([Monitoring](#monitoring)). Run it from the same timer, with `ExecStart` changed:

```bash
#!/bin/sh
set -eu
URL=https://id.example.com/o/<org id>/ssh/<tenant id>
STATE=/var/lib/quisora-ssh-fetch # the ETags of the files installed
mkdir -p "$STATE"
tmp=$(mktemp -d /etc/ssh/.quisora.XXXXXX)
trap 'rm -rf "$tmp"' EXIT

# get NAME: fetches $URL/NAME into $tmp/NAME, sending the ETag of the copy installed; prints the status (200 or 304)
get() {
  tag=$(cat "$STATE/$1.etag" 2>/dev/null || true)
  curl -fsS --max-time 20 ${tag:+-H "If-None-Match: $tag"} -D "$tmp/$1.h" -o "$tmp/$1" -w '%{http_code}' "$URL/$1"
}
# put NAME FILE STATUS: installs a new document at FILE with its ETag, or touches FILE after a 304
put() {
  if [ "$3" = 304 ]; then touch "$2"; return; fi
  chmod 644 "$tmp/$1"
  mv -f "$tmp/$1" "$2"
  sed -n 's/^[Ee][Tt][Aa][Gg]: *//p' "$tmp/$1.h" | tr -d '\r' > "$STATE/$1.etag"
}

ca=$(get ca.pub)
krl=$(get krl)
[ "$ca" = 304 ] || grep -q '^ssh-' "$tmp/ca.pub"
[ "$krl" = 304 ] || ssh-keygen -Q -l -f "$tmp/krl" > /dev/null
put ca.pub /etc/ssh/quisora_user_ca.pub "$ca"
put krl /etc/ssh/quisora.krl "$krl"
```

Both documents are checked before either is installed, and a failed run (`curl` cannot reach Quisora, an answer that is
not valid) changes and touches nothing. It does not check that the list has a section for one of the tenant's CA keys,
does not refuse an older list, and does not fetch the host CA lines. Delete the saved ETags (`$STATE`) if you replace the
files by hand.

## Signing in from a workstation

Install `quisora` (the same binary; the `ssh` commands need no configuration), then:

```bash
quisora ssh login https://id.example.com/o/<org id>/ssh/<tenant id>
```

A browser opens on Quisora's sign-in page. Sign in with a second factor, and the command prints:

```
Signed in to acme/prod.
Principals: alice, group:ops
Valid until: 2026-10-31 18:04 AEDT (8h0m0s left)
Added to ssh-agent; it is removed when the certificate expires.
The public key and certificate are also in ~/.ssh/quisora/acme-prod{.pub,-cert.pub}, to name them in ~/.ssh/config
(IdentityFile ~/.ssh/quisora/acme-prod.pub, CertificateFile ~/.ssh/quisora/acme-prod-cert.pub, IdentitiesOnly yes).
```

Then `ssh ubuntu@server.example.com` as usual. The sign-in asks for a second factor and a sign-in no older than the
tenant's **Sign-in age**, so someone who signed in with a password only is asked for the second factor on the way. The
person's own account page shows the same command, with the URL filled in
([The account page](#the-account-page)).

| Option | What it does |
| --- | --- |
| `--device` | Sign in with a code on another device (the device flow), for a machine without a browser, such as a server you are logged in to. It asks for the same second factor and sign-in age as the browser sign-in ([On a machine without a browser](#on-a-machine-without-a-browser)). |
| `--no-browser` | Print the sign-in URL instead of opening it. The browser must be on this machine: the sign-in returns to a port on `127.0.0.1`. |
| `--no-agent` | Do not use ssh-agent: write the key and certificate to `~/.ssh/quisora` ([below](#the-agent-or-a-file)). |
| `--key <path>` | Get the certificate for this existing key (its `.pub`) and write it to `<path>-cert.pub`, instead of making a new key. |
| `--principal <name>` | Ask for these principals only, in the prefixed form such as `group:ops` (repeat it). The default is every principal the person may have. |
| `--ttl <duration>` | Ask for a shorter certificate, such as `2h` or `90m` (or seconds). The default is the tenant's lifetime; at least 60 seconds. |
| `--insecure`, `--ca-cert <pem>` | Do not verify Quisora's TLS certificate (development), or trust the CAs in this file. |

### The agent, or a file

By default `login` makes a new ed25519 key in memory and loads it with its certificate into `ssh-agent`
(`SSH_AUTH_SOCK`) for exactly as long as the certificate lasts, with the comment `quisora:<org>/<tenant>`. The private
key never touches the disk and the agent drops it when the certificate expires. A new `login` replaces the tenant's
earlier certificate in the agent. It also writes the public key and the certificate, **without the private key**, to
`~/.ssh/quisora/<org>-<tenant>.pub` and `-cert.pub`, so that `~/.ssh/config` can name them ([ssh_config](#ssh_config)).
`quisora ssh status` lists that certificate file as `file (no key)`, to tell it from one with its key beside it.

`login` writes the key and certificate to files, `~/.ssh/quisora/<org>-<tenant>` (the key with mode 0600, beside `.pub` and
`-cert.pub`), and says how to use them (`ssh -i ~/.ssh/quisora/<org>-<tenant> <host>`), when:

- you give `--no-agent`;
- no agent is running (`SSH_AUTH_SOCK` is not set, or the socket does not answer): `warning: no ssh-agent: …: writing the
  key to a file instead`;
- the agent refuses the key: it is locked, or it does not accept imported keys, as the agents of 1Password and
  Secretive do: `warning: ssh-agent did not take the key (…; it may be locked, or not accept imported keys): writing the
  key to a file instead`. The certificate you signed in for is not thrown away;
- the system is **Windows**: the agent of Windows' OpenSSH is a named pipe, which `quisora` does not use, so it always
  writes files. Windows does not apply the 0600 mode, so what protects the private key is the access control of your
  user profile (`%USERPROFILE%\.ssh\quisora`): make sure no one else can read it. Use `ssh -i` with the path it prints.

With `--key`, nothing is made: the certificate is for the key you name, in the agent or not. Use it with a key that has a
passphrase, or a security key (`id_ed25519_sk`), when you do not want a key without a passphrase on the disk. OpenSSH
uses `<key>-cert.pub` automatically with `-i <key>`.

`quisora ssh status` lists the Quisora certificates in the agent and in `~/.ssh/quisora` with their principals and time
left, and `quisora ssh logout [<discovery URL>]` removes them (one tenant's, or all of them without the URL) from both.
To read a certificate: `ssh-keygen -L -f ~/.ssh/quisora/acme-prod-cert.pub`, or for the agent
`ssh-add -L | grep cert | ssh-keygen -L -f -`.

### On a machine without a browser

```bash
quisora ssh login --device https://id.example.com/o/<org id>/ssh/<tenant id>
```

It prints a URL and a code. Open the URL on any device, check that it shows the same code, sign in and allow it. The
command waits and then does the same as above. Anyone can start this on any machine, so only enter a code you started
yourself ([Risks](#risks)).

The command sends the same demands as the browser sign-in when it asks for the code: a second factor (`acr_values`) and a
sign-in no older than the tenant's **Sign-in age** (`max_age`). The device page meets them as any sign-in does
([device sign-in](../oauth/device.md)): a browser whose session is a password only is sent on to the second factor,
and one whose session is older than **Sign-in age** signs in again. There is nothing to sign out of first. The command
keeps asking until the code expires, ten minutes after it was made: it waits longer between asks when the server says so,
and when the network, a proxy or the server does not answer it says so once and tries again (`warning: the token endpoint
did not answer (…): trying again until the code expires`).

### ssh_config

```
# ~/.ssh/config
Host *.example.com
    User ubuntu
    # with the agent (the default): the key is in the agent; these name it
    IdentityFile ~/.ssh/quisora/acme-prod.pub
    CertificateFile ~/.ssh/quisora/acme-prod-cert.pub
    IdentitiesOnly yes
```

With the file form (no agent, `--no-agent`, or Windows), name the private key instead, and `ssh` finds
`acme-prod-cert.pub` beside it:

```
Host *.example.com
    User ubuntu
    IdentityFile ~/.ssh/quisora/acme-prod
    IdentitiesOnly yes
```

`ssh -v` shows `Offering public key: … ED25519-CERT` when the certificate is being used.

**Why `IdentitiesOnly yes`.** sshd allows only a few failed attempts a connection (`MaxAuthTries`, 6 by default) and counts
every key the client offers. A person whose agent holds many keys can use them all up before the certificate is
offered, and the connection closes with `Too many authentication failures`. `IdentitiesOnly yes` makes `ssh` offer only
the keys the configuration names, here the Quisora key. In agent mode that works because `login` leaves the `.pub` and
`-cert.pub` files: `ssh` asks the agent for the key in `acme-prod.pub` and pairs it with the certificate in
`acme-prod-cert.pub`. (`IdentitiesOnly yes` with no such file would offer nothing at all.) The files stay after the
certificate has expired, and the agent forgets the key then: `ssh` fails until the next `login`. `logout` removes them.
Agent forwarding is off in certificates by default; `ssh -A` has no effect unless the tenant turns it on.

## The account page

People who cannot install `quisora` can get a certificate from their account page, `/o/<org id>/account` → **SSH
certificates**. The section is shown only when a tenant with SSH on is open to them. It lists those tenants, the
principals the person would get and how long a certificate lasts, with the `quisora ssh login …` command to **Copy**.

A tenant that is open to them but would refuse them a certificate is listed under **Where you cannot get one**, with
why, rather than left out: a manager or administrator where **Managers and administrators** is off (*This tenant
gives no certificates to managers and administrators*), a session that signed in a way the tenant's sign-in rules do
not allow, or settings that give the person no principal. **Get a certificate** is off when no tenant is left to use.
A tenant the person has no access to is never named.

**Get a certificate** opens a form: the **Tenant** (when there is more than one) and the **Public key**, pasted from
`~/.ssh/id_ed25519.pub`. **Get certificate** shows the certificate, to **Copy** or **Download** as `id_ed25519-cert.pub`
(named for the key type). Save it next to the private key as that name and `ssh` uses it by itself, or run `ssh-add`
on the key. Never paste a private key.

It needs a second factor in the session (otherwise the page says *You signed in with a password only. To get a
certificate, sign out and sign in again with a one-time code or a passkey.*) and a confirmation that it is you within the
last 5 minutes (the page asks for the password or a passkey, as for an API token). The tenant's **Sign-in age** counts
from the later of the sign-in and a confirmation that used a second factor (an authenticator code or a passkey): an
account with no second factor of its own, whose second factor came from its sign-in through a provider, confirms with
the password alone, which lets the page go on but does not make an old sign-in count as new. The tenant's sign-in
methods apply as they do to the sign endpoint: a session that signed in with a method the tenant does not allow (say a
password, where the tenant allows only passkeys) is listed as one it cannot use and is refused (*this tenant does not
accept the way you signed in*). Requests share the [rate limits](#rate-limits) of the sign endpoint.

**Your certificates** lists the ones still valid, with their principals, expiry and status. The trash button is
**Revoke**: it revokes the person's own certificate, and they can get another at once (up to 60 revocations a minute for
each person: *Too many certificates revoked. Wait a minute and try again.*). A revoked or no longer valid certificate
shows why. Administrators revoke other people's from the console or the API: from the tenant's SSH page (the
**Certificates** table), or from the user's own page, whose **SSH certificates** card lists the certificates the user holds
that have not expired, across the tenants, with a **Revoke** button for each live one. Only administrators of the
organization (and super admins) see that card; managers do not. A person may have 100 certificates for a
tenant that have not expired, **revoked ones included**, since each stays on the revocation list until it expires:
past that a request is refused (*you have 100 certificates for this tenant that have not expired, the most it allows
(revoked ones count until they expire): wait until the first expires, at …*, audited as `too_many`), and revoking does
not make room.

## Host certificates

A host certificate lets people's ssh clients trust a server by its name without the "unknown host key" question, and
when the server's key changes, without a warning.

**1. Turn them on** for the tenant: **Sign host certificates**, with **Host names allowed** (`*.example.com`) and the
**Host certificate lifetime**. This makes a host CA key. A host name is signed only if it matches a pattern; the match
is `path.Match`-style on the lower-case name, and `*` also matches dots (`*.example.com` matches `a.b.example.com`).

**2. Make a service account** that may only sign host certificates, with the `ssh:host` scope (the organization's
**Service accounts** page, or the API: [service accounts](../SERVICE-ACCOUNTS.md)). The `ssh` scope alone is not enough,
and `ssh:host` can do nothing else:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "ssh-host-signer", "scopes": ["ssh:host"]}' "$QUISORA/api/orgs/acme/service-accounts"
```

The account can sign a certificate for **any** name that matches the tenant's host patterns, for any key, so a server that
holds its secret can vouch for any other host in those patterns. Keep the patterns as narrow as you can, keep the secret
readable by root only, rotate it when a server is lost, and consider signing from one trusted machine instead of from
every server.

**3. On each server**, as root, sign its host key. The secret goes in the environment, so it stays out of the process
list:

```bash
export QUISORA_CLIENT_ID=<the account's id>
export QUISORA_CLIENT_SECRET=<its secret>
quisora ssh host-sign "$URL" /etc/ssh/ssh_host_ed25519_key.pub --principal server.example.com
# Host certificate for server.example.com, valid until 2027-01-29 18:04 AEDT (2159h0m0s left).
# HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

The certificate is written beside the key, and the last line is what sshd needs. Without `--principal` the server's
fully qualified name is used. Options:

| Option | What it does |
| --- | --- |
| `--principal <name>` | A name the certificate is for (repeat it); each must match a host pattern of the tenant. |
| `--ttl <days>` | Ask for a certificate of this many days, `90` or `90d` (1 to 365; hours that make whole days, such as `2160h`, also work). The tenant refuses more than its **Host certificate lifetime**, which is also the default. |
| `--auth-method auto\|post\|basic` | How the service account authenticates at the token endpoint. A service account is registered for `client_secret_post` unless made otherwise, so `auto` (the default) tries that and, if the server answers `invalid_client`, once more with `client_secret_basic`. `post` or `basic` tries only that one. |
| `--token <token>` (`QUISORA_TOKEN`) | An access token with `ssh:host` instead of the client id and secret: the way for a service account that authenticates with a private key. |

Add the line to sshd and **reload sshd**, so that it serves the certificate (and does so again after every renewal,
below):

```
# /etc/ssh/sshd_config.d/50-quisora.conf
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

```bash
sudo sshd -t && sudo systemctl reload ssh
```

Through the API (`ttl_days` is optional and at most the tenant's lifetime):

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"public_key": "'"$(cat /etc/ssh/ssh_host_ed25519_key.pub)"'", "principals": ["server.example.com"], "ttl_days": 30}' \
  "$QUISORA/api/orgs/acme/tenants/prod/ssh/host-certificates"
```

**4. On every client**, trust the host CA, and set up revocation as below.

### Clients and host certificate revocation

The tenant publishes the host CA lines at `…/ssh/<tenant id>/known_hosts`
(`@cert-authority *.example.com ssh-ed25519 AAAA… quisora:acme/prod:host:<key id>`, one per host CA key). Do not paste
them into `/etc/ssh/ssh_known_hosts` by redirecting `curl`: a failed `curl` empties the file, and the file also holds
whatever else the machine trusts. Keep Quisora's lines in a file of their own and let `fetch` manage it.

**What revocation covers on a client.** sshd's `RevokedKeys` is for users logging in to a server. When **a client** checks a
server's host certificate it looks at its own `RevokedHostKeys`. Without it, the client trusts a host certificate until
it expires, whatever Quisora revokes: a host certificate revoked by hand, a removed host CA key, or SSH turned off. The
revocation list is the same list the servers fetch, so a client can use it:

```bash
sudo mkdir -p /etc/ssh/ssh_known_hosts.d
sudo quisora ssh fetch "$URL" --ca-file= --krl-file /etc/ssh/quisora-hosts.krl \
  --known-hosts-file /etc/ssh/ssh_known_hosts.d/quisora
```

`--ca-file=` (empty) skips the user CA file, which a client does not need. A machine that is both a server and a client
needs one fetch: add `--known-hosts-file /etc/ssh/ssh_known_hosts.d/quisora` to the server's command and point
`RevokedHostKeys` at `/etc/ssh/quisora.krl`. Then tell `ssh` about both files, in `/etc/ssh/ssh_config.d/50-quisora.conf`
(or in `/etc/ssh/ssh_config` where the system has no `ssh_config.d`):

```
RevokedHostKeys /etc/ssh/quisora-hosts.krl
GlobalKnownHostsFile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts.d/quisora
```

`GlobalKnownHostsFile` replaces the default, so the line names `/etc/ssh/ssh_known_hosts` as well. **`RevokedHostKeys`
makes `ssh` refuse every connection if the file is missing or unreadable** (`Error checking host key … in revoked keys
file`), as sshd does for `RevokedKeys`: run the `fetch` before you add the lines, keep the file, and run the fetch from a
timer like the server's (the same unit with this `ExecStart`, with `RandomizedDelaySec=`). The list also applies to a
host's plain host key, not only to certificates. For one person on a workstation, the same lines in `~/.ssh/config`
work with files in the home directory (`UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/quisora_known_hosts`).

Without the binary, use temporary files and a rename, never a redirect onto the live file (`/usr/local/sbin/quisora-ssh-fetch-hosts`):

```bash
#!/bin/sh
set -eu
URL=https://id.example.com/o/<org id>/ssh/<tenant id>
DIR=/etc/ssh/ssh_known_hosts.d
tmp=$(mktemp -d "$DIR/.quisora.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
curl -fsS --max-time 20 "$URL/known_hosts" -o "$tmp/known_hosts"
curl -fsS --max-time 20 "$URL/krl" -o "$tmp/krl"
if grep -qv '^@cert-authority ' "$tmp/known_hosts"; then echo "not a known_hosts list" >&2; exit 1; fi
ssh-keygen -Q -l -f "$tmp/krl" > /dev/null
chmod 644 "$tmp/known_hosts" "$tmp/krl"
mv -f "$tmp/known_hosts" "$DIR/quisora"
mv -f "$tmp/krl" /etc/ssh/quisora-hosts.krl
```

**The limits, plainly.**

- Only a client that fetches the list and sets `RevokedHostKeys` honours a host revocation, and only after its next fetch.
  A laptop that does neither trusts a host certificate until it expires, or until the `@cert-authority` line is gone from
  its file.
- Removing a host CA key takes its line out of `known_hosts`, and the list revokes the key outright, so a client that
  runs the fetch drops both at its next run. Turning SSH off leaves the lines in place and relies on the list.
- A stolen host private key, with its certificate, impersonates that host until the certificate expires or a client revokes it. So
  **keep host certificates short**: a few weeks at most, renewed automatically (below), rather than the 90-day default,
  if you cannot count on every client revoking.

### Renewing and rotating host keys

Host certificates last up to `host_ttl_days` and are not renewed by themselves: run `host-sign` again before they expire,
and reload sshd after each run, or sshd goes on serving the old certificate until it restarts. From a timer, for
instance weekly with a certificate of 30 days. `/etc/systemd/system/quisora-host-sign.service`:

```
[Unit]
Description=Renew this server's SSH host certificate
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/quisora/host-sign.env
ExecStart=/usr/local/bin/quisora ssh host-sign https://id.example.com/o/<org id>/ssh/<tenant id> /etc/ssh/ssh_host_ed25519_key.pub --principal server.example.com --ttl 30
ExecStartPost=/bin/systemctl reload ssh
```

`/etc/quisora/host-sign.env` holds `QUISORA_CLIENT_ID=…` and `QUISORA_CLIENT_SECRET=…`, owned by root with mode 0600. The
reload runs only if `host-sign` succeeded (use `sshd` for the unit name on RHEL and Fedora).
`/etc/systemd/system/quisora-host-sign.timer`:

```
[Unit]
Description=Renew this server's SSH host certificate every week

[Timer]
OnCalendar=weekly
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

To replace a server's host key, make the new key (`ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""` after
moving the old one away), run `host-sign` and reload sshd; clients with the `@cert-authority` line accept it without a
warning. To rotate the host CA key itself, see [CA key rotation](#ca-key-rotation).

## Revocation

The revocation list (KRL) of a tenant holds every certificate that has not expired and **would not be issued now**, and the
CA keys that must not be trusted. Nothing has to be told that a person's access ended: the list is worked out when it is
asked for. A certificate is on it for the first of these reasons that applies:

| Reason | When |
| --- | --- |
| `revoked` | An administrator revoked it by hand, or the person revoked their own. |
| `ca_key_removed` | The CA key that signed it was removed (user or host certificate). The list revokes the key itself, so the list does not need to name the certificate. |
| `user_deleted` | The user was deleted. |
| `user_disabled` | The user was disabled, locked out, is past their end date, or their organization is gone. |
| `sessions_ended` | The user's sessions were ended: signed out everywhere, or a credential reset. |
| `signed_out` | An [emergency sign-out](../emergency-sign-out.md) of the organization, or of the server, came after the certificate was issued. |
| `role_not_allowed` | The user is a manager or administrator and the tenant does not allow them certificates (it was turned off after the certificate was issued). |
| `app_unavailable` | The tenant's SSH application is disabled or missing. The certificates count again when it is back. |
| `access_removed` | The user lost access to the tenant's SSH application: removed from the access list, or the access ended. |
| `principals_changed` | A principal in the certificate is not one the user would get now: a username or group renamed, removal from a group or role, or a principal source turned off. The whole certificate goes, and a new one has the new principals. |
| `ssh_off` | SSH is turned off for the tenant: every certificate of it, host certificates too. |
| `settings_changed` | The certificate grants more than the settings would give now: a lifetime over **Certificate lifetime**, an extension that is no longer allowed, or other source addresses than the ones now set ([The settings](#the-settings)). |

Host certificates are revoked in three ways only: by hand (their serial is listed), with their CA key (removed), and with
every CA key while SSH is off. Settings that are not principals loosened (a longer lifetime, more extensions, no source
addresses) apply to certificates issued after the change.

**What the list holds.** One certificates section for each CA key that `ca.pub` or `known_hosts` publishes, with the serials
revoked among the certificates that key signed; and one explicit-key section that revokes CA keys outright: a key removed by
hand stays revoked for as long as any certificate it signed can still be presented (its record is kept as a tombstone, without
its private key, for the longest lifetime plus 10 minutes: **user keys 24 hours and 10 minutes, host keys 365 days and
10 minutes**), and **while SSH is off every CA key of the tenant** is revoked. sshd checks the CA key of a certificate
against the list as well, so a revoked CA key revokes everything it signed on every server that fetches the list, even a
certificate forged with a stolen key that no list names, and even where the CA file still names the key.

In the console the tenant's SSH page has a **Certificates** table that lists them a page at a time, as the users are
listed (10, 25, 50 or 100 to a page; **Show**: active, revoked, expired or all), with the reason, and **Revoke** revokes one
by hand. The search box finds certificates by the start of the user's username or name (as they are now), the start of the
certificate's key id (it begins with the username as issued), key fingerprint (`SHA256:…`) or serial, and by a principal
written whole (`paul`, `group:ops`, `web1.example.com`); case is ignored. Expired certificates are kept an hour; a revoked
one stays on the revocation list for ten minutes after it expires, for servers whose clocks run slow. Through the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$QUISORA/api/orgs/acme/tenants/prod/ssh/certificates?q=paul&status=active&limit=25" | jq '.items[] | {id, serial, key_id, principals, valid_before}'
curl -X POST -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/tenants/prod/ssh/certificates/<certificate id>/revoke"
# one user's certificates that have not expired, across the tenants (each says which tenant: tenant_id, tenant, tenant_name)
curl -s -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/users/<user id>/ssh-certificates" | jq '.items[] | {id, tenant, serial, principals, status}'
```

The list is newest first and takes `q` (the search), `offset` and `limit` (25 a page, at most 100), and answers
`{"items": […], "total": n}` where `total` counts every match, as the other lists do. The other filters are `user`,
`status` (`active`, `revoked`, `expired`, `all`) and `host` (`true` or `false`); `id` is the
certificate's record id, not its serial. Revoking one already revoked changes nothing. A user's certificates are listed
in full, for administrators of the organization and service accounts with the `ssh` scope (403 for anyone else).

**A lost access is written down.** When the list is made and finds a certificate revoked for `access_removed`,
`principals_changed` or `role_not_allowed`, the certificate is marked revoked (by `system`, with that reason, once), so
giving the person the access, group or role back does not bring their old certificates back: they get a new one. This
is best effort and happens when a list is built: the list revokes the certificate in any case, but access that is
restored before any list was built after the loss revokes nothing. The other reasons follow the person's or the tenant's
state and are not written: a disabled account that is enabled again, the SSH application enabled again, settings put
back, or SSH turned on again, makes its certificates count again.

### How soon

A node keeps the list it made for 30 seconds (a revocation, a change of a CA key or of the tenant clears it on every
node at once; a change of a user, a group or an access list reaches the list within those 30 seconds), the revocation
list, `ca.pub` and `known_hosts` are answered with `Cache-Control: no-cache` and an `ETag` so a cache must revalidate
them (a cache cannot hand out an old `ca.pub` beside a new list after a rotation), and servers fetch every minute if you
use the timer above (plus up to 15 seconds of `RandomizedDelaySec=`). So expect a revocation, or the end of someone's
access, to reach sshd within about two minutes. The discovery document may be cached for 60 seconds. It applies to new logins. A session someone already
has open stays open: end it on the server (`loginctl terminate-user`, or kill the sshd process) when that matters.

To cut a person off at once from everything, lock them out ([emergency sign-out and lock-out](../emergency-sign-out.md#locking-out-one-person)):
their certificates go on the list as `user_disabled`.

### What revocation does not cover

- **Ending one session, or revoking one grant, does not revoke certificates already issued.** A certificate counts while
  the user's sessions as a whole hold, so what ends it is signing the person out **everywhere**, a credential reset, a
  lock-out or an emergency sign-out, or revoking the certificate itself. Signing out of one browser, or removing one
  application from the account page, leaves the certificates asked for under it valid until they expire.
- Sessions already open on a server stay open.
- A host certificate revocation reaches only clients that use `RevokedHostKeys`
  ([Clients and host certificate revocation](#clients-and-host-certificate-revocation)).
- A server that has stopped fetching keeps its old list.

## CA key rotation

A tenant has a **user CA key**, which signs user certificates, and a **host CA key** when host certificates are on. Each
is an ed25519 key that Quisora keeps sealed with the master key. The SSH page's **CA keys** table shows each key's
fingerprint, state, when it signs and until when it is published: **Signing**, **Next** (published, not signing yet) and
**Retired** (no longer signs, certificates it signed still work).

A user key's successor is published at once and signs **seven days** later, so servers that fetch the CA list at least
once in a week trust it before it signs. The old key stops signing then, and stays published for another 25 hours, which
covers the longest certificate it signed (24 hours) and a server's next fetch. After that it leaves the list by itself.

- **Scheduled.** `rotation_days` (8 to 3650) makes the successor when the newest user key is `rotation_days` minus seven
  days old, so it signs when the key is `rotation_days` old. Quisora does this itself (audited as `ssh.ca.rotate` by the
  system). 0 rotates by hand only. Host keys are never rotated on a schedule.
- **By hand.** **Rotate user key** → **In seven days**, or `{"immediate": false}` in the API. It is refused while
  another rotation of the user key is under way. **Rotate host key** has no choice to make (below).
- **Immediately.** **Rotate user key** → **Immediately** (`{"immediate": true}`): the new key signs at once and the old one
  stops signing now, published for another 25 hours. It replaces a rotation under way. Servers that have not fetched
  the new key refuse new certificates until they do.
- **A host key** signs from the moment it is made, whichever you choose; the old host key stays published until you remove
  it, so existing host certificates keep working while you re-sign the hosts and refresh the clients' `known_hosts`.

```bash
curl -X POST -H "Authorization: Bearer $SA_TOKEN" -H "Content-Type: application/json" \
  -d '{"purpose": "user", "immediate": false}' "$QUISORA/api/orgs/acme/tenants/prod/ssh/rotate"
```

Rotation is not atomic across nodes. Two nodes that enable SSH or rotate a key in the same instant can each make a key,
and both are published. After a rotation, look at the **CA keys** table: it should show one key that signs and, for a
rotation in seven days, one **Next**. If there is an extra, remove it once it no longer signs.

**Removing a key.** A key that no longer signs can be removed (the trash button on its row, or
`DELETE /api/orgs/{org}/tenants/{id}/ssh/keys/{key id}`). It is no longer published, and **the revocation list revokes the
key itself**, so every server that fetches the list distrusts the key and everything it signed, certificates that no
list names included. Its record stays, as a tombstone without the private key, for as long as the longest certificate
it could have signed could be presented ([Revocation](#revocation)). A key that signs now, or has not started, cannot
be removed.

**A CA key may be compromised.** Anyone with the key can sign certificates for any principal, and a certificate they
make is on no list of serials, so the cure is to take the key away. Rotation alone is not enough: a retired key stays
published (25 hours for a user key; for a host key until you remove it), and everything it signed still works.

1. **Rotate immediately** (user key, or host key). The new key signs at once.
2. **Remove the old key.** This is the step that revokes it: the list now revokes the key itself, so servers drop it
   at their next fetch, about a minute, whether or not their CA file changed.
3. **Check a server**: `ssh-keygen -lf /etc/ssh/quisora_user_ca.pub` no longer shows the old fingerprint, and
   `ssh-keygen -Q -f /etc/ssh/quisora.krl <the old public key in a file>` prints `REVOKED`. Servers that do not run `fetch`
   need the new CA file by hand.
4. Everyone gets a new certificate: signing in again is enough.
5. For a host key, also re-sign the hosts with `host-sign` (and reload sshd) and refresh `known_hosts` on every client;
   clients that revoke host keys drop the old key at their next fetch.
6. Check the audit log for `ssh.cert.issue` with an unexpected user, and server logs for logins with a key id you do not
   know ([incident response](../SECURITY.md#incident-response)).

**Rotate and remove ask for a recent re-authentication.** The console asks for the password or a passkey if you have not
confirmed it is you in the last 5 minutes. A [service account](../SERVICE-ACCOUNTS.md) with the `ssh` scope does not
need it. A personal API token cannot rotate or remove keys at all (`403`, field `reauth`): a stolen token could otherwise
cut off every server. Changing the settings needs no re-authentication.

## Managers and administrators

By default managers and administrators are refused certificates, so the people who manage Quisora are not on your
servers by default: someone who takes over an administrator's account does not get a login on every server with it.
Turning **Managers and administrators may get certificates** (`allow_privileged`) on lets them. The same setting controls the SSH application's
device sign-in for them ("Managers and administrators may approve device sign-ins": [device sign-in](../oauth/device.md)),
and is kept in step by Quisora. Turning it off again puts their existing certificates on the revocation list
(`role_not_allowed`).

Keeping managers out of servers does not keep them out of what they control: managers create and rename users and add
people to groups, and so decide who carries which username and group principal ([Principals](#principals)).

## Source addresses

`source_addresses` is a list of addresses or CIDR ranges (`203.0.113.7`, `203.0.113.0/24`, `2001:db8::/32`): the
certificate then has the OpenSSH `source-address` critical option, and sshd refuses it from anywhere else. Use it
for a VPN or office range. It is fixed in a certificate when it is made, so lifting the restriction changes nothing for
certificates already issued; setting or changing the addresses revokes the live certificates made with other addresses
(`settings_changed`), and people get new ones. An address without a prefix length means that one address.

## Risks

**Device-code phishing.** Someone can start `quisora ssh login --device` on their own machine and send a victim the code
("enter this code to verify your account"). If the victim enters it and allows, the attacker's machine is signed in as
them and gets a certificate for their principals, which here means a login on servers. Quisora makes this hard, as
described for [device sign-in](../oauth/device.md): the device page and the consent screen warn about codes from someone
else, consent is always asked, codes last 10 minutes and work once, and a second factor is required. Managers and
administrators cannot be caught while **Managers and administrators may get certificates** is off. Tell people to enter
a code only if they started it themselves, and limit the damage with a short lifetime and
[source addresses](#source-addresses). If someone approved a code they were sent, revoke the certificate and sign the person out
everywhere ([incident response](../SECURITY.md#incident-response)).

**Where the private key is.** With the agent, the key is in the agent's memory and vanishes with the certificate. Anyone
who can reach the agent's socket as that user (or as root, or through a forwarded agent) can use the key while the
certificate is valid. With the file form, the private key stays on disk (`~/.ssh/quisora`, unencrypted, mode 0600, or
protected only by the profile's access control on Windows) long after the certificate has expired: the key is no use
without a certificate, but `logout` deletes it (it does not wipe the disk). For stronger protection use `--key` with a
passphrase-protected or security key.

**A certificate is valid until it expires.** There is no way to take back an open session or a certificate from a server
that has stopped fetching. Keep lifetimes as short as your people can stand (the default is 8 hours), and watch that
`quisora-ssh-fetch` keeps succeeding ([Monitoring](#monitoring)).

**The first fetch is trust on first use.** Compare the CA key's fingerprint with the console, as in the setup steps.

### Known limits

- Ending a single session, or revoking a single grant, does not revoke certificates already issued; sign the person out
  everywhere, pull an emergency sign-out or revoke the certificate ([What revocation does not cover](#what-revocation-does-not-cover)).
- Open sessions stay open, and a host revocation reaches only clients that set `RevokedHostKeys`.
- The SSH application uses ordinary bearer access tokens, not DPoP-bound ones. An access token that leaks in the minutes
  it lives (10 by default, `tokens.access_ttl`) can be used to ask for a certificate for another key, if the
  sign-in behind it is still within **Sign-in age**.
- CA key rotation is not atomic across nodes: a rare race can leave an extra published key, which you remove.
- An emailed one-time code counts as a second factor. Limit the tenant's sign-in methods if that is too weak.
- Certificates already issued outlast a Quisora outage, but no new one can be signed during it.
- A restore from a backup can undo revocations and bring back a removed CA key ([Backup and restore](#backup-and-restore)).

## Backup and restore

A backup holds the CA keys, the certificate records and the tenants' settings as they were when it was made. Restoring an
**older** backup therefore:

- can **republish a CA key that was removed since** (the tombstone is gone, the key is published again, and its private
  half is in the backup), so servers trust it again and the certificates it signed work again until they expire;
- **undoes revocations made since**: certificates revoked by hand, and the lost accesses written down, come back to
  life, and users removed, disabled or taken out of groups since come back as they were;
- **has no record of the certificates issued after the backup**: they are not on any list and cannot be revoked by serial,
  and work until they expire on servers that trust the key that signed them.

After a restore, for every tenant that uses SSH:

1. **Rotate the CA keys immediately** (user key, and the host key if host certificates are on).
2. **Remove the old keys**, all of them that were published before the restore. The list then revokes them outright, and
   with them every certificate they signed, whether or not Quisora knows it.
3. **Re-revoke** what was revoked since the backup (certificates, disabled users), and check the access lists and group
   memberships.
4. Everyone signs in again for a new certificate; re-sign the hosts and refresh the clients' `known_hosts` after a host key
   rotation.

## Monitoring

A server that has stopped fetching keeps its old list and, after a CA rotation, its old CA key, and only a failing check
shows it. Alert on both of these on every server (and client) that fetches:

- **The fetch service failing**: `systemctl is-failed quisora-ssh-fetch.service` (with the node exporter's systemd collector,
  `node_systemd_unit_state{name="quisora-ssh-fetch.service",state="failed"} == 1`). A failed run keeps the old files, and shows in
  `systemctl --failed` and in `journalctl -u quisora-ssh-fetch.service`.
- **The revocation list file getting old.** `fetch` writes the list whenever its bytes differ, which is nearly every
  run, so the file's modification time is the last successful fetch. Alert when it is older than 5 minutes:

  ```bash
  # succeeds only when the list was refreshed in the last 5 minutes (it fails when the file is missing, too)
  find /etc/ssh/quisora.krl -mmin -5 2>/dev/null | grep -q .
  ```

  Any check that reads a file's age does the same (Nagios, a cron job that pushes a metric, the textfile collector of
  the node exporter). The `curl` script of [Without the quisora binary](#without-the-quisora-binary) touches the list
  when Quisora answers `304` (unchanged), so the same check works for it. A run that is given a list older than the one installed keeps the file as it is, so one such run
  can leave it a minute older; 5 minutes leaves room for that.

On Quisora's side, a revocation list that cannot be made is logged at error level (`oidc: making an SSH revocation
list`, with the organization and tenant) and answered `503`, and the servers go on with their old list meanwhile: alert on
that line.

## What is recorded

| Audit event | When |
| --- | --- |
| `ssh.settings.update` | The SSH settings changed (with the fields that changed). |
| `ssh.ca.create` | A CA key was made: when SSH was first enabled, or host certificates were turned on (the key, its purpose and fingerprint). |
| `ssh.ca.rotate` | A CA key was rotated (`immediate`, `scheduled` for the automatic one, and the keys it retires). |
| `ssh.ca.remove` | A CA key was removed. |
| `ssh.cert.issue` | A user certificate was issued: the person, `serial`, `principals`, `fingerprint`, `valid_before`, `via` (`cli` or `account`) and `amr`. |
| `ssh.cert.refused` | A certificate was refused, with the `reason`, the tenant and `via`. At most one per person, tenant and reason a minute (`detail.suppressed` counts the others). |
| `ssh.cert.revoke` | A certificate was revoked: by hand (`serial`, `key_id`, and by whom), or by the system when the list found it revoked for a lost access (`access_removed`, `principals_changed`, `role_not_allowed`), with the `reason`. |
| `ssh.host.issue` | A host certificate was issued, with who signed it, `serial`, `principals`, `valid_before` and `key_id`. |
| `ssh.host.refused` | A host certificate was refused (`host_certs_off`, `no_host_key`, `bad_key`, `bad_principals`, `pattern`, `bad_ttl`). Throttled like `ssh.cert.refused`. |

The reasons of `ssh.cert.refused` are `not_enabled`, `no_user_key`, `wrong_client`, `mfa_required`, `auth_too_old`,
`method_not_allowed`, `user_unusable`, `session_ended`, `app_unavailable`, `no_access`, `privileged`, `bad_key`,
`no_principals`, `too_many`, `bad_principal` and `bad_ttl`. The refusals have the outcome `failure`. A run of
`mfa_required` or `no_access` from one person is usually a person who needs help. Each certificate records the session
epoch and sign-out stamp of the sign-in that asked for it, which is how `session_ended`, `sessions_ended` and `signed_out`
are decided. What Quisora cannot record is a login on a server: that is in sshd's log, which names the certificate by key
id and serial.

## Rate limits

| What | Limit |
| --- | --- |
| Signing user certificates (`POST …/sign` and the account page) | 20 a minute for each person and 60 a minute for each address, counting refused requests; one budget for both ways of asking (`429`, `slow_down`; the account page says to wait a minute). |
| Revoking your own certificates on the account page | 60 a minute for each person (`429`). |
| Signing host certificates | 120 a minute for each administrator or service account (`429`, with `Retry-After`). |
| Refusals recorded in the audit log | One per person, tenant and reason a minute. |
| Starting device sign-ins, wrong device codes | 30 a minute and 20 per 15 minutes for each address: [device sign-in](../oauth/device.md#the-users-side). |
| The discovery, CA keys, known hosts and revocation list addresses | 16 000 units a minute for each address and tenant, counted by the tenant's id whether the URL names it by id or name, with one more budget per address shared by the URLs that name no tenant (`429`): an answer with the document costs 4, a `304 Not Modified` or a refusal costs 1. A `quisora ssh fetch` run is four answers, 16 units, so about a thousand servers a minute behind one address ([Servers behind one address](#servers-behind-one-address)). The revocation list is made by one request at a time for a tenant, and the others wait for it. Answers are cached for 30 seconds on a node. |

## Troubleshooting

### Reading sshd's log

sshd's log is `/var/log/auth.log` (or `journalctl -u ssh`, `-u sshd` on RHEL and Fedora). Set `LogLevel VERBOSE` in
`sshd_config` to get the certificate on every line. A certificate that is accepted:

```
sshd[2210]: Accepted publickey for ubuntu from 203.0.113.7 port 51022 ssh2: ED25519-CERT SHA256:Fy3… ID alice@acme/<user id> (serial 8123456789012345678) CA ED25519 SHA256:Hq7…
```

`ID` is the certificate's key id, `<username>@<org name>/<user id>` (for a host certificate, `host:<name>@<org name>`),
`serial` is its serial, and the `CA` fingerprint is the one in the console's **CA keys** table. Find the certificate in the
console's **Certificates** table (the tenant's SSH page) by serial to see its principals, expiry and status.

### What went wrong

| In sshd's log, or what you see | Cause | What to do |
| --- | --- | --- |
| `Certificate does not contain an authorized principal` | None of the certificate's principals is a line of `/etc/ssh/principals/<account>`. | Look at the principals the person got (`quisora ssh status`, or the console) and the file. A group principal needs its prefix (`group:ops`, not `ops`). A principal source may be off, or a group name has a space or other character that is dropped. |
| `Failed publickey for …` with an `ID … (serial …) CA …` that is not Quisora's | The certificate is from another CA, or from a CA key that was removed. | Compare the `CA` fingerprint with the console, and run `fetch`. |
| `Authentication key … revoked by file /etc/ssh/quisora.krl` | The certificate, or the CA key that signed it, is on the revocation list. | The console's **Certificates** table gives the reason (a revoked CA key names the key's fingerprint, not a serial). The person gets a new one by signing in again, if they may. |
| `Error checking authentication key … in revoked keys file` | `/etc/ssh/quisora.krl` is missing or unreadable. | [Why the revocation list must always be there](#why-the-revocation-list-must-always-be-there): run `fetch`; check the timer. |
| From `ssh`: `Error checking host key … in revoked keys file` | The client's `RevokedHostKeys` file is missing or unreadable: every connection is refused. | Run the client's fetch; or take the `RevokedHostKeys` line out until the file is there. |
| `Certificate invalid: expired` | The certificate's lifetime is over. | `quisora ssh login` again. |
| `Certificate invalid: not yet valid` | The server's clock is behind. Certificates are valid from 5 minutes before they are signed, so skew beyond that shows. | Fix NTP on the server (and on the workstation, if it is ahead). |
| Nothing but `Permission denied (publickey)`, and no certificate in sshd's log | The client did not offer it: no agent, or `IdentitiesOnly` with nothing it can offer, or too many keys offered first (`Too many authentication failures`), or the agent dropped the expired key. | `ssh -v`; `quisora ssh status`; see [ssh_config](#ssh_config). |
| `User … not allowed because …`, or the account does not exist | The Linux account is missing or locked. | [Linux accounts must exist](#linux-accounts-must-exist). |
| `quisora ssh fetch` exits 1: `user CA keys: …` or `revocation list: …` | Quisora cannot be reached, or the answer is not valid. Nothing was changed. | Run it by hand to see the message; check the discovery URL. |
| `revocation list: it has no section for any of the CA keys the tenant publishes: is this the right tenant?` (from `fetch`) | The list is another tenant's (or a proxy answered with another tenant's list). Nothing was changed. | Check the URL. |
| `revocation list: ssh-keygen cannot read it, so sshd would refuse it: …` (from `fetch`) | OpenSSH's own parser rejected the file. Nothing was changed. | Run `ssh-keygen -Q -l -f` on a copy from the address; report it. |
| `note: the server's revocation list (version …) is older than the one in … (version …) and revokes nothing more: keeping the installed one` (from `fetch`) | A node answered with a list it made before the one installed, with nothing more revoked in it. Exit code 0; the other files were updated. | Nothing, unless it repeats. |
| `warning: SSH certificates are turned off for …` (from `fetch`) | SSH is off for the tenant: the files are still written, and the revocation list revokes every certificate and CA key. | Turn SSH on if that is not what you meant. |
| `SSH certificates are turned off for the tenant …` (from `login` or `host-sign`) | The same. | Ask the tenant's administrators. |
| `discovery: nothing at …: the URL is wrong, or SSH was never enabled for the tenant` | The address, or SSH was never on, or the tenant was renamed (a name in the URL) or deleted. | Copy the discovery URL from the console; use the tenant's id. |
| `a second factor is required: sign in with a one-time code or a passkey` | The sign-in was a password only. | Sign in with a second factor. |
| `the sign-in is too old to get a certificate: sign in again` | The sign-in is older than **Sign-in age**. | Sign in again. |
| `the sign-in this request comes from has ended: sign in again` | The session or grant behind the request was signed out everywhere, reset or signed out by an emergency sign-out since it began (`session_ended`). | Run `quisora ssh login` again. |
| `this tenant's SSH application is disabled or missing` | The SSH application was disabled or deleted (`app_unavailable`). | Enable it, or wait: while SSH is on, Quisora makes a new one within a minute (with a new client id: check access entries limited to the old one). |
| `this account has no access to this tenant's SSH` | The tenant is members-only and the person, or one of their groups, is not on its access list for the SSH application. | Add them under **Access**. |
| `managers and administrators cannot get SSH certificates from this tenant` | `allow_privileged` is off. | [Managers and administrators](#managers-and-administrators). |
| `there is no principal to put in a certificate for this account` | The principal sources that are on give this person nothing (no roles, groups without a valid name). | Turn **Username** or **Names of the user's groups** on. |
| `you have 100 certificates for this tenant that have not expired, the most it allows …` | 100 certificates that have not expired, revoked ones included (`too_many`). | Wait until the first expires (the message says when); revoking does not help. |
| `"x" is not one of yours; you may use …` | `--principal` named a principal the person does not get, or without its prefix (`ops` for `group:ops`). | Leave `--principal` out, or use one listed. |
| `this access token is not for the tenant's SSH application` | A token from another application was used. | Use `quisora ssh login`, which uses the right one. |
| `timed out after 5m0s waiting for the sign-in` | The browser did not come back to the command in 5 minutes: it is not on this machine, or it was not finished. | Use `--device` on a machine whose browser is elsewhere. |
| `the sign-in expired before it was approved: start again` (from `--device`) | The code was not approved in its 10 minutes. | Run it again. |
| `warning: the token endpoint did not answer (…): trying again until the code expires` (from `--device`) | The network, a proxy or the server did not answer; the command keeps asking until the code expires. | Nothing, unless it does not end. |
| `warning: no ssh-agent: …: writing the key to a file instead` | `SSH_AUTH_SOCK` is not set or the agent does not answer. | `eval "$(ssh-agent)"` and log in again, or use the file. |
| `warning: ssh-agent did not take the key (…): writing the key to a file instead` | The agent is locked, or does not accept imported keys (1Password, Secretive). | Unlock it, or use the file: `ssh -i ~/.ssh/quisora/<org>-<tenant>`. |
| `too many requests: wait a moment and try again` | The rate limit. | Wait a minute; for `fetch` see [Servers behind one address](#servers-behind-one-address). |
| `certificate request: the server's certificate is not valid: …` (from `login`), or the same with `host certificate request:` | The sign endpoint answered, but the certificate in the answer does not parse as an SSH certificate. It is not about TLS: something between you and Quisora (a proxy, a captive portal) changed the answer, or the server is not a Quisora of this version. | Run it again; try without the proxy; report it with the answer. |
| `the server signed a different key than the one sent`, `the server did not return a certificate`, `the server returned a certificate of the wrong type` | The answer was not the certificate that was asked for. | As above. |
| `discovery: Get "…": … x509: …` or another TLS error | Quisora's TLS certificate is not trusted here. | `--ca-cert <pem>` for a private CA. |
| `token request: … (tried client_secret_post, then client_secret_basic)` (from `host-sign`) | The service account's id or secret is wrong, or it authenticates another way (a private key). | Check the id and secret; use `--token` for a private-key account. |
| `--ttl "…": give a whole number of days …` (from `host-sign`) | Not a number of days of at least 1. | `--ttl 30`, `--ttl 30d`. |

## Reference

| | |
| --- | --- |
| Discovery | `GET /o/<org id>/ssh/<tenant>` (JSON: `issuer`, `enabled`, `client_id`, the OAuth endpoints, `sign_endpoint`, `user_ca_endpoint`, `known_hosts_endpoint`, `krl_endpoint`, `host_sign_endpoint`, `cert_ttl`, `max_auth_age`, `host_certs`, `host_patterns`, `acr_values`). `<tenant>` is the tenant's id or name: use the id. |
| Caching of the GETs | All four carry an `ETag`, and a request whose `If-None-Match` names it gets `304` with no body. The revocation list, `ca.pub` and `known_hosts` are `Cache-Control: no-cache` (the list's ETag changes only when what it revokes does); the discovery document is `public, max-age=60`. |
| User CA keys | `GET …/ssh/<tenant>/ca.pub` (`text/plain`; one `ssh-ed25519 AAAA… quisora:<org>/<tenant>:user:<key id>` per published key) |
| Host CA lines | `GET …/ssh/<tenant>/known_hosts` (`@cert-authority <patterns> ssh-ed25519 AAAA… quisora:<org>/<tenant>:host:<key id>`; empty unless host certificates are on) |
| Revocation list | `GET …/ssh/<tenant>/krl` (`application/octet-stream`, an OpenSSH KRL; version is the unix time it was made; `503` when it cannot be made) |
| Sign a user certificate | `POST …/ssh/<tenant>/sign` with `Authorization: Bearer <access token of the SSH application>` (the CLI uses bearer tokens; a DPoP-bound token is accepted too) and `{"public_key": "…", "principals": […], "ttl": seconds}`; answers `certificate`, `serial`, `key_id`, `principals`, `valid_after`, `valid_before`. Errors `401 invalid_token`, `403 access_denied`, `400 invalid_request`, `429 slow_down` |
| Management API | `GET`, `PATCH /api/orgs/{org}/tenants/{id}/ssh`; `POST …/ssh/rotate`; `DELETE …/ssh/keys/{key}`; `GET …/ssh/certificates`; `POST …/ssh/certificates/{cert}/revoke`; `POST …/ssh/host-certificates` (scope `ssh:host`) |
| Account page | `GET /o/<org id>/api-internal/account/ssh`, `POST …/account/ssh/sign` (`{"tenant_id", "public_key"}`), `POST …/account/ssh/certificates/{id}/revoke` (session and CSRF token) |
| Scopes | `ssh` (settings, keys, certificates), `ssh:host` (sign host certificates only) |
| Settings JSON | `enabled`, `cert_ttl`, `max_auth_age`, `principal_username`, `principal_groups`, `principal_roles`, `permit_pty`, `permit_user_rc`, `permit_port_forwarding`, `permit_agent_forwarding`, `permit_x11_forwarding`, `source_addresses`, `allow_privileged`, `rotation_days`, `host_certs`, `host_ttl_days`, `host_patterns` (and `client_id`, read only) |
| Principals | `<username>`, `group:<group name>`, `role:<role>`; the name part 1 to 64 of `A-Za-z0-9._@-` |
| CLI | `quisora ssh login <url> [--device] [--no-browser] [--no-agent] [--key <path>] [--principal …] [--ttl …]`, `status`, `logout [<url>]`, `host-sign <url> <host public key file> [--principal …] [--ttl <days>] [--auth-method auto\|post\|basic]`, `fetch <url> [--ca-file …] [--krl-file …] [--known-hosts-file …]` |
| `fetch` defaults | `--ca-file /etc/ssh/quisora_user_ca.pub`, `--krl-file /etc/ssh/quisora.krl`, `--known-hosts-file` not written; an empty value leaves a file alone |
| Key id | user `<username>@<org name>/<user id>`, host `host:<first name>@<org name>`; serials are random 64-bit numbers |
| Validity | from 5 minutes before signing; to the lifetime, never past the account's end date |
| Revocation timing | list kept 30 s per node, not cached by clients; servers fetch every minute |
| CA key rotation | user key: published at once, signs in 7 days, old one published 25 h more; host key: signs at once. A removed key is revoked by the list for 24 h 10 min (user) or 365 days 10 min (host). |
| Limits | 100 unexpired user certificates per user and tenant (revoked ones count); 20 signs a minute per person, 60 per address; 60 account-page revocations a minute per person; 16 000 fetch units a minute per address and tenant |
| Stored | `ssh_ca_keys` (CA keys, private halves sealed with the master key; a removed key stays as a tombstone) and `ssh_certificates` (until an hour after they expire): [DATABASE.md](../DATABASE.md) |
| Design | [docs/design/ssh-ca.md](../design/ssh-ca.md) |
