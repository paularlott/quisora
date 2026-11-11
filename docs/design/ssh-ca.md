# SSH certificate authority

Status: built. This is the design record the pieces were built against, corrected where the code turned out
differently (the code wins); the user-facing guide is [docs/ssh/README.md](../ssh/README.md).

Quisora signs short-lived OpenSSH user certificates for people who signed in with a second factor, and longer-lived
host certificates for servers. Servers trust one CA key per tenant (`TrustedUserCAKeys`) instead of a list of user
keys; who may log in as which account is decided by the certificate's principals (the user's username,
`group:<name>` for each of their groups, `role:<role>` for each application role), so access is managed in Quisora.

Not released yet: no migrations, no compatibility shims.

## Pieces

| Piece | Where |
| --- | --- |
| Certificate and KRL encoding, key parsing (pure, no store) | `internal/sshca` |
| Stored kinds `sshkey`, `sshcert`; tenant settings | `internal/model` |
| Business rules: enabling, signing, principals, revocation, rotation, KRL | `internal/service/ssh*.go` |
| Public endpoints under `/o/{org}/ssh/{tenant}/…` (discovery, CA keys, KRL, sign) | `internal/oidc/ssh.go` |
| Management API `/api/orgs/{org}/tenants/{id}/ssh…` | `internal/admin/ssh.go`, `web/openapi/openapi.yaml` |
| Console: the tenant's SSH page (`/admin/orgs/{org}/tenants/{tenant}/ssh`), the SSH column of the tenants list and the summary card of the tenant page; the user page's SSH certificates card | `web/templates/pages/admin-tenant-ssh.html`, `partials/admin.html` (`tenant-ssh`), `pages/admin-user.html`, `web/src/js/pages/ssh.js`, `admin.js` |
| Account page: SSH certificates section | `internal/login/account*.go`, `web/templates/pages/account.html`, `web/src/js/pages/account.js` |
| CLI: `quisora ssh login|logout|status|host-sign|fetch` | `cmd/ssh.go`, `internal/sshcli` |
| Housekeeping: missing keys and application of tenants with SSH on, scheduled CA rotation | `internal/app/modules.go` → `Service.EnsureSSHKeys` |
| KRL cache dropped on every node for a revocation, a change of a CA key or of a tenant | `internal/app/modules.go` (`sshKRLChanged`) → `Service.InvalidateSSHKRLOf`, `InvalidateSSHKRLIn` |

## Model

### Tenant settings

`model.Tenant` gets `SSH *TenantSSH` (`msgpack:"ssh,omitempty" json:"ssh,omitempty"`). Nil means never enabled.

```go
type TenantSSH struct {
    Enabled  bool   // off: signing is refused (404) and every certificate is revoked (the KRL lists them all); the
                    // discovery document, ca.pub, known_hosts and the KRL are still served; keys are kept
    ClientID string // the tenant's SSH application, made by Quisora when SSH is first enabled (see below)

    // User certificates
    CertTTL         int      // seconds; default 28800 (8 h), 300..86400
    MaxAuthAge      int      // seconds a sign-in may be old when it asks for a certificate; default 3600, 60..86400
    PrincipalUsername bool   // the user's username (default true)
    PrincipalGroups   bool   // "group:" + the name of each of the user's groups (default true)
    PrincipalRoles    bool   // "role:" + each application role the tenant's access list gives the user (default false)
    PermitPTY, PermitUserRC bool                                    // default true
    PermitPortForwarding, PermitAgentForwarding, PermitX11Forwarding bool // default false
    SourceAddresses []string // CIDRs or addresses: OpenSSH critical option source-address; empty = anywhere
    AllowPrivileged bool     // managers and administrators may get user certificates (default false)
    RotationDays    int      // user CA scheduled rotation, days; 0 = by hand only; default 0

    // Host certificates
    HostCerts    bool     // host certificates may be signed (default false)
    HostTTLDays  int      // default 90, 1..365
    HostPatterns []string // patterns host principals must match ("*.example.com", "db1.internal"); required when HostCerts
}
```

`model.DefaultTenantSSH()` returns the defaults. Validation lives in the service (`Invalid("ssh.cert_ttl", …)`): among
it, `SourceAddresses` and `HostPatterns` hold at most 32 entries, which is checked before any loop over them (a 100 000
entry list is refused at once, not de-duplicated first), and while `Enabled` at least one of the three principal
sources is on (`ssh.principal_username`).
JSON names are snake_case of the Go names (`cert_ttl`, `max_auth_age`, `principal_username`, `permit_pty`,
`source_addresses`, `allow_privileged`, `rotation_days`, `host_certs`, `host_ttl_days`, `host_patterns`, `enabled`,
`client_id`).

### `KindSSHKey` ("sshkey", SQL table `ssh_ca_keys`; `Service.SSHCAKeys`)

A tenant's CA key. Scope and partition: the org id. Field `tenant_id` (Index). `MayExpire`.

```go
type SSHKey struct {
    Meta
    OrgID, TenantID string
    Purpose    string    // "user" or "host"
    Alg        string    // "ssh-ed25519" (the only one made)
    PublicKey  string    // authorized_keys form, no comment
    PrivateKey string    // sealed (binding SSHKeyBinding(id) = "sshkey/<id>/private"), OpenSSH PEM or raw ed25519 seed
    NotBefore  time.Time // published from Created; signs from NotBefore
    RetireAt   time.Time // stops signing (zero: until a successor starts); still published until Expires
    Expires    time.Time // removed from the store (zero: kept until removed by hand; host keys)
    Removed    time.Time // removed by hand: a tombstone (below)
}
```

`RemoveSSHKey` keeps the record as a tombstone: `PrivateKey` dropped, `Removed` set, `Expires` = removal + the longest
certificate the key can have signed + `sshKRLGrace` (user keys: 24 h + 10 min; host keys: 365 days + 10 min). A
tombstone is not published, never signs, and the KRL revokes the key itself (an explicit key section) while it lasts.
The tenant record has an indexed `ssh_enabled` field (SSH on), which housekeeping lists.

Registered everywhere a kind must be (meta.go, schema.go `Schemas`/`Kinds`/`NewEntity`/`expiries`,
`sqlstore/table.go`, `cluster/store.go` `gatedScope` org-scoped case, `docs/DATABASE.md`, partition test, sweep
owners: the tenant; both kinds are also streamed to the console's live updates, `internal/events`). Sealed field: `resealSteps`, backup `sealedKeys`, `sealedfields_test.go`.

### `KindSSHCert` ("sshcert", SQL table `ssh_certificates`; `Service.SSHCerts`)

Every certificate issued, until it expires: what the KRL and the console's list are made from. Scope and partition:
the org id. Fields `tenant_id` (Index; user certificates only), `host_tenant_id` (Index; host certificates only, so the
KRL reads a tenant's user certificates without its host certificates), `user_id` (Index), `revoked` (bool, Index),
`created` (Sort). `AlwaysExpires` (Expires = ValidBefore + 1 h).

```go
type SSHCert struct {
    Meta
    OrgID, TenantID string
    UserID     string    // "" for a host certificate
    Host       bool
    Serial     uint64    // random, non-zero; unique per CA key in practice (64 random bits)
    KeyID      string    // the certificate's key id, as sshd logs it
    CAKeyID    string    // the SSHKey that signed it
    Principals []string
    Fingerprint string   // SHA256:… of the certified public key
    ValidAfter, ValidBefore time.Time
    Extensions      []string // user certificates: the extensions granted, sorted
    SourceAddresses []string // user certificates: the source-address critical option (none: anywhere)
    SessionEpoch uint64  // the session epoch of what the request stood on: the access token's grant (sign endpoint) or
                         // the session (account page), never the user's current one
    Stamp      model.SignOutStamp // likewise the grant's or session's sign-out counters: an emergency sign-out after it
                                  // makes the certificate count as revoked
    Via        string    // "cli" (sign endpoint), "account" (account page), "api" (host, management API)
    IssuedBy   string    // actor name, for host certificates (service account)
    Revoked    bool
    RevokedAt  time.Time
    RevokedBy  string
    RevokedReason string // why, when Quisora found it revoked (RevokedBy "system"): access_removed, principals_changed or
                         // role_not_allowed; "" for one revoked by hand
}
```

Sweep owner: the tenant, for both kinds (not the user: a deleted user's certificate must stay on the KRL until it
expires, which removing its record would undo). The record has no JSON for `SessionEpoch` and `Stamp`.

## Signing user certificates

`Service.SignUserSSH(ctx, req SSHUserRequest) (*SSHIssued, error)`:

```go
type SSHUserRequest struct {
    Actor      *Actor
    User       *model.User
    TenantID   string
    ClientID   string    // the token's client (sign endpoint); "" from the account page
    PublicKey  string    // authorized_keys line
    Principals []string  // optional subset of the allowed principals
    TTL        time.Duration // optional, ≤ CertTTL
    AMR        []string
    AuthTime   time.Time
    Via        string    // "cli" | "account"
    Session    *SSHSession // account page: how the session signed in (amr, provider); the tenant's sign-in methods
                           // must allow it (nil at the sign endpoint, whose token was issued under that rule)
    SessionEpoch uint64             // of the access token's grant (sign endpoint) or the session (account page)
    Stamp        model.SignOutStamp // likewise; recorded on the certificate
    SignIn       string             // the grant (sign endpoint) or the session (account page); recorded too
}
type SSHIssued struct {
    Certificate string // authorized_keys form of the certificate (…-cert-v01@openssh.com AAAA…)
    Cert        *model.SSHCert
}
```

Refusals (each audited `ssh.cert.refused` with a `reason`, `tenant` and `via`, at most once a minute per user, tenant and
reason; returned as `*SSHRefusal` (`ErrForbidden`: 403 `access_denied` at the sign endpoint) or `Invalid` (400
`invalid_request` there)). The reasons, in the order they are checked: `not_enabled`, `no_user_key` (1), `wrong_client`
(2), `mfa_required` (3), `auth_too_old` (4), `method_not_allowed` (4a), `user_unusable`, `session_ended` (5a),
`app_unavailable` and `no_access` (5), `privileged` (6), `bad_key` (7), `no_principals`, `too_many` (8),
`bad_principal`, `bad_ttl`:

1. SSH not enabled on the tenant, or no active user CA key.
2. `ClientID` given and not the tenant's `SSH.ClientID`.
3. Not `model.MFA(AMR)`: a second factor is always required.
4. `AuthTime` older than `MaxAuthAge`.
   4a. When `Session` is set (the account page): the tenant's sign-in methods (`EffectiveSignIn`, the same rule the
   authorization endpoint applies to a sign-in to the tenant's applications: `SignInMethods.AllowsSession` on the
   session's amr and provider) must allow the way it signed in. `SSHTenantsFor(ctx, u, session)` applies it too, so the
   account page lists only the tenants the session may use.
5. The user is not usable (`UserUsable`), or has no access to the tenant (same rule as signing in to its applications:
   `MembersOnly` and the access list, access end dates); `app_unavailable` when the SSH application is disabled or gone.
   5a. `session_ended`: the request's `SessionEpoch` is not the user's, or its `Stamp` is not current (the grant's or
   session's sign-in has ended since).
6. The user is a manager or above and `AllowPrivileged` is off.
7. The public key does not parse, is a certificate, is RSA under 2048 bits or DSA. Accepted: ed25519, ecdsa
   P-256/384/521, RSA ≥ 2048, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com.
8. The allowed set is empty (`no_principals`), the user already has 100 user certificates for the tenant that have not
   expired, revoked ones included (each is on the KRL until it expires: `too_many`, a message saying when the first
   expires), or a requested principal is not in
   the allowed set (`bad_principal`). A `ttl` under 60 seconds or over `CertTTL` is `bad_ttl`.
9. Rate limit (endpoint and account page): 20 certificates per user per minute, 60 per address per minute, one budget
   for both (`web.Server.SSHSignAllowed`). Revoking on the account page: 60 a minute per user (`SSHRevokeAllowed`, 429).

Certificate: type user, key id `<username>@<org name>/<user id>`, random serial, principals as allowed (or the
requested subset; sorted, deduplicated), ValidAfter now − 5 min, ValidBefore now + TTL capped at the user's
`ValidUntil` if set, extensions from the Permit settings, critical option `source-address` from SourceAddresses.
Signed by the tenant's current user CA key (the newest key with NotBefore ≤ now < RetireAt). The record is stored,
then audited `ssh.cert.issue` (detail: serial, principals, fingerprint, valid_before, via, amr). Then the `SignIn`
record (the session when `ClientID` is "", else the grant) is read again from the store: gone, the certificate is
revoked (`sign_in_ended`) and the request refused (`session_ended`); unreadable, it is revoked as well and the request
fails (nothing decided, nothing handed out).

Principals: `PrincipalUsername` → `u.Username`; `PrincipalGroups` → `group:<display name>` for each of the user's
groups; `PrincipalRoles` → `role:<role>` for each application role from the user's tenant access (empty on a tenant
open to everyone). The name part must match `^[A-Za-z0-9._@-]{1,64}$` (others are skipped, not refused); the prefix is
added after. A username never holds `:`, so a user (whom a manager may create or rename) cannot be named after a
group's or a role's principal. `Service.SSHPrincipals(ctx, t, u) ([]string, error)`.

## Host certificates

`Service.SignHostSSH(ctx, a *Actor, tenantID string, in SSHHostRequest) (*SSHIssued, error)`, `in{PublicKey,
Principals []string, TTL}`. Requires an administrator of the organization or a service account with scope `ssh:host`
(`ScopeSSHHost`); the endpoint allows 120 requests a minute per actor (a service account's client id, or the user id:
429). Refused unless `Enabled && HostCerts`. Principals are lower-cased and must be host names or addresses (no wildcards), 1..32 (more are refused before any is looked at), and each must match one of
`HostPatterns` (`path.Match` style on the lower-cased name; `*` crosses dots: `*.example.com` matches
`a.b.example.com`). TTL between 1 hour and HostTTLDays (default: HostTTLDays). Key id `host:<first principal>@<org name>`.
Audited `ssh.host.issue`; a refusal is audited `ssh.host.refused` (reasons `host_certs_off`, `no_host_key`, `bad_key`,
`bad_principals`, `pattern`, `bad_ttl`), throttled like `ssh.cert.refused`.

## Revocation and the KRL

The KRL lists every certificate of the tenant that has not expired and **would not be issued now**:

- revoked by hand (`Revoked`);
- user certificates whose user is deleted or not usable (disabled, locked out, end date passed, organization signed
  out), whose `SessionEpoch` no longer holds (sign out everywhere, credential reset, lockout), issued before the
  organization's or server's emergency sign-out stamp, whose user lost access to the tenant, whose tenant's SSH
  application is disabled or gone (`app_unavailable`), or whose principals are no longer a subset of what
  `SSHPrincipals` gives now (removed from a group);
- user certificates that grant more than the settings now would (`settings_changed`): a lifetime over `CertTTL`, an
  extension no longer permitted, or source addresses other than those the tenant now restricts certificates to;
- certificates signed by a CA key that has been removed (`ca_key_removed`): the KRL revokes the key itself while its
  tombstone lasts, so a server with a stale `ca.pub` distrusts it too;
- every certificate of the tenant, user and host, while SSH is turned off (`ssh_off`): the KRL revokes every CA key of
  the tenant outright (not sticky: turning SSH on again takes it back).

A certificate stays on the list until `ValidBefore + 10 minutes` (`sshKRLGrace`), so a server with a slow clock still
sees it revoked; the records live an hour past `ValidBefore`.

Revocation is sticky for a lost access. When the list is built and a certificate is found revoked for `access_removed`,
`principals_changed` or `role_not_allowed`, `sshPersist` writes it down once (`Revoked`, `RevokedAt`, `RevokedBy`
"system", `RevokedReason`; audited `ssh.cert.revoke` as the system with a `reason`; best effort and bounded: at most 50
a build, none after the first unavailable store write or one of unknown outcome, the list revoking them all the same;
written after the list is kept and its lock released, one build's writing at a time), so restoring the access,
group or role does not revive old certificates. The user's reasons are evaluated before `ssh_off`, so they are written
down while SSH is off too. The other reasons are not written: they follow the user's or the tenant's state (a disabled
account enabled again, a disabled SSH application enabled again, and in particular `ssh_off`: turning SSH on again
makes the certificates that were not revoked otherwise valid again).

So no hook is needed: the KRL is computed when asked for (cached 30 s per tenant on the node) and every way Quisora
ends a user's access reaches SSH within that time plus the servers' fetch interval. `Service.SSHRevoked(ctx,
tenantID) ([]SSHRevokedCert, error)` returns them with a reason, the first that applies: `revoked`, `ca_key_removed`,
`user_deleted`, `user_disabled`, `sessions_ended`, `sign_in_ended`, `signed_out`, `role_not_allowed`, `app_unavailable`,
`access_removed`, `principals_changed`, `ssh_off`, `settings_changed` (host certificates only ever get `revoked`,
`ca_key_removed` and `ssh_off`; a certificate written down by `sshPersist` shows its stored reason).
`Service.SSHKRLTagged(ctx, tenantID) ([]byte, etag string, error)` (and `SSHKRL` without the tag) encodes them: a
certificates section (type 1) for each CA key that `ca.pub` or `known_hosts` publishes (user keys; host keys while
`HostCerts`), serial lists sorted; and one explicit key section (type 2, `KRL_SECTION_EXPLICIT_KEY`) revoking the
tombstoned keys and, while SSH is off, every CA key of the tenant. A retired key that expires within the 30 s the list
may be kept gets no certificates section (`ca.pub` stops publishing it meanwhile; its certificates have all ended). Of
the host certificates only those revoked by hand are read. KRL version = unix seconds of generation; the tag is a hash of everything after the version and date
(`sshca.KRLTag`), so a list made again that revokes the same has the same ETag. An empty KRL is valid and always served
while SSH is enabled; it is `ErrNotFound` (404) only for a tenant that never had SSH (no SSH application yet). The
node's cache of a tenant's list is dropped on every node by the change hook (`sshKRLChanged`): for a change of the
tenant, of a CA key, or of a certificate that is revoked or deleted (one just signed, not revoked, is on no list), the
tenant's list (`InvalidateSSHKRLOf`); for a change that carries no index fields (a change notice of a node sharing the
database) the lists of its organization (`InvalidateSSHKRLIn`, by the record's scope). Changes of users, groups and
access reach it within the 30 s. Invalidation counts a generation: a list is kept only if no invalidation came during
its build, and the invalidations made while a build's sticky revocations are written down (their own writes fire the
hook) are held back and count once the writing ends, so the requests meanwhile take the list just made. One request
at a time makes the list of a tenant on a node (a per-tenant lock around the build); the others wait and take what it
made, so a burst of fetches is one build. A build that fails is logged at error level (the list is a 503).

`Service.RevokeSSHCert(ctx, a, orgID, certID)` (administrator, or a service account with `ssh`; or the owner from the
account page) sets Revoked, audited `ssh.cert.revoke`; revoking one already revoked changes nothing.
`Service.ListSSHCertsCounted(ctx, a, tenantID, SSHCertFilter{UserID, Status, Host, Limit})` returns views with a
computed `Status`: `active`, `expired` (kept an hour after the end), `revoked` (with `Reason`), and the number of
matches (`ListSSHCerts` without it).

## CA keys and rotation

- Enabling SSH the first time creates one user CA key (NotBefore = now) and, when HostCerts, one host CA key, and the
  SSH application (below). Audited `ssh.ca.create` per key.
- `RotationDays` is 0 (by hand only) or 8..3650 (a successor is published 7 days before it signs, so less has no room).
  `RotationDays > 0`: housekeeping (`EnsureSSHKeys`, leader only, idempotent) makes a successor when the newest user
  key's NotBefore is older than `RotationDays − 7 days`: the successor is published at once and signs from
  NotBefore = now + 7 days (servers that fetch `ca.pub` daily have it first); the predecessor's RetireAt = successor
  NotBefore, Expires = RetireAt + 24 h + 1 h.
- `Service.RotateSSHKey(ctx, a, tenantID, purpose string, immediate bool)`: a successor now. `immediate=false`: as
  scheduled (signs in 7 days for user keys; host keys: signs at once, predecessor keeps publishing with no Expires).
  `immediate=true`: signs at once, predecessor retires now (user: Expires = now + 25 h; for a host key it changes
  nothing, `false` already does this). While a user successor has not started, `immediate=false` is refused (422,
  field `immediate`) and `immediate=true` deletes that successor (it never signed) and replaces it. Audited
  `ssh.ca.rotate` (detail: `immediate`, `scheduled`, `retires`). The management API asks for a recent re-authentication
  first (see below).
- `Service.RemoveSSHKey(ctx, a, tenantID, keyID)`: only a key that has started and no longer signs (as
  `oidc.RemoveKey`). Audited `ssh.ca.remove`. It leaves a tombstone (see `SSHKey`), which the KRL revokes. Removing a
  compromised key: rotate immediate, then remove.
- Housekeeping (`EnsureSSHKeys`, leader, every minute) walks the tenants with SSH on (`ssh_enabled`) and makes what is
  missing as the system: the SSH application (written to the tenant, audited `ssh.settings.update`), the CA keys, the
  application's `device_privileged_users`; it deletes the tenant's SSH applications (`Client.SSHApp`) other than the
  current one that are over an hour old (left by an enabling whose tenant write had an unknown outcome, or whose
  rollback failed); then the scheduled rotation. An enabling that failed after the tenant write
  is so finished within a minute.
- `Service.SSHKeys(ctx, tenantID, purpose)` returns the published keys (Expires zero or in the future), oldest first.

## The SSH application

On first enable the service creates a client in the tenant (via the normal client service, as the system):
name `SSH`, public (`token_endpoint_auth_method: none`), grant types `authorization_code` and
`urn:ietf:params:oauth:grant-type:device_code` (no refresh token), redirect URI `http://127.0.0.1/callback` (loopback:
any port), scopes `openid profile`, first party, yet always confirmed on the consent screen, in the browser flow as in
the device flow (its code goes to any loopback port, where another local user may listen),
`device_privileged_users` = `AllowPrivileged` (kept in step when the setting changes). Its id is stored in
`TenantSSH.ClientID`, and the client is marked `Client.SSHApp` (not in JSON); its `client.create` event has
`ssh_tenant`. If it was deleted, enabling again (or housekeeping, while SSH is on) makes a new one, with a new client
id: its `client.create` event (by the system) names the one it `replaces` with a `reason`, and it is logged at warn.
Access entries limited to chosen applications name them by client id, so they do not cover the new one (their people
lose access, which is sticky): the guide says to turn SSH off rather than delete the application. When the tenant
write that records a new application fails for certain, the application is deleted again as the system (audited
`client.delete`); a write of unknown outcome keeps it.

A tenant with SSH on cannot be deleted (409 `ErrSSHOn`: "SSH certificates are on for the tenant …: turn SSH off first,
so that its servers fetch a revocation list that revokes every certificate"), nor an organization with such a tenant
(cascade or not). With SSH off, the tenant's SSH applications (`Client.SSHApp`: the current one and any left over) do
not count as clients in use: they are deleted with the tenant, as the system (audited `client.delete`). The tenant is
deleted as it was read (`DeleteIf` on its version), so SSH turned on in between makes the deletion fail (409, stale).
The organization's check has no such guard: its record is in the global partition and its tenants in its own, which no
one write spans, and the check must come before the deletion guard is committed (a committed deletion is finished by
housekeeping); an enabling in the moment between the two is not caught.

## Public endpoints (`internal/oidc/ssh.go`)

All under `/o/{org}/ssh/{tenant}` where `{tenant}` is the tenant's id or name (a name stops working when the tenant is
renamed, so the guide and the console use the id); 404 when the tenant is unknown or never
had SSH. With SSH off the sign endpoint is 404 but the discovery document (`"enabled": false`), `ca.pub`, `known_hosts`
and `krl` are still served (`SSHTenantPublished`), so that turning SSH off reaches the servers through the KRL.

| Method, path | Answer |
| --- | --- |
| `GET /o/{org}/ssh/{tenant}` | discovery JSON (below) |
| `GET /o/{org}/ssh/{tenant}/ca.pub` | `text/plain`: one `ssh-ed25519 AAAA… quisora:<org name>/<tenant name>:user:<key id>` line per published user CA key |
| `GET /o/{org}/ssh/{tenant}/known_hosts` | `text/plain`: `@cert-authority <patterns joined by ,> ssh-ed25519 AAAA… quisora:<org>/<tenant>:host:<key id>` per published host CA key (empty unless HostCerts) |
| `GET /o/{org}/ssh/{tenant}/krl` | `application/octet-stream`: the KRL |
| `POST /o/{org}/ssh/{tenant}/sign` | user certificate for a bearer (or DPoP) access token |

GETs carry an `ETag` (a request whose `If-None-Match` names it gets 304 with no body). Discovery: `Cache-Control:
public, max-age=60`; `ca.pub`, `known_hosts` and `krl`: `Cache-Control: no-cache`, so a cache cannot serve an old
`ca.pub` beside a new list after a rotation. The ETag is a hash of the body, and for `krl` `sshca.KRLTag` (what it
revokes). Rate limit per address and tenant (`web.RateKeyIP` + the tenant's id, read before the request is counted, so
id and name are one budget; the paths naming no tenant share one more per address): 16 000 units a minute, a 304 (or
refused) request costing 1 and a document sent 4 (429 `slow_down`). The KRL is cached 30 s a node.

Discovery:

```json
{
  "issuer": "https://id.example.com/o/<org id>",
  "org": "acme", "tenant": "prod", "tenant_id": "…",
  "enabled": true,
  "client_id": "…",
  "authorization_endpoint": "…", "token_endpoint": "…", "device_authorization_endpoint": "…",
  "sign_endpoint": "https://id.example.com/o/<org id>/ssh/<tenant id>/sign",
  "user_ca_endpoint": "…/ca.pub", "known_hosts_endpoint": "…/known_hosts", "krl_endpoint": "…/krl",
  "host_sign_endpoint": "https://id.example.com/api/orgs/<org id>/tenants/<tenant id>/ssh/host-certificates",
  "cert_ttl": 28800, "max_auth_age": 3600, "host_certs": true, "host_patterns": ["*.example.com"],
  "acr_values": "urn:quisora:acr:mfa"
}
```

Sign: `Authorization: Bearer <access token>` (or DPoP), JSON body `{"public_key": "...", "principals": [...]?,
"ttl": seconds?}`. The token must be a user token of this organization for the tenant's SSH client
(`client_id` claim), issued from a grant (`gid`): the certificate records that grant's session epoch and sign-out
stamp. Answer 200:

```json
{"certificate": "ssh-ed25519-cert-v01@openssh.com AAAA…", "serial": "1234567890", "key_id": "paul@acme/u_…",
 "principals": ["group:ops", "paul"], "valid_after": "RFC 3339", "valid_before": "RFC 3339"}
```

Errors: 401 `invalid_token` (WWW-Authenticate as userinfo; DPoP challenge for a DPoP token), 403
`{"error":"access_denied","error_description":…}`, 400 `{"error":"invalid_request","error_description":…}` (also a
validation error of the service: `<field>: <message>`), 413 (body over 16 KiB), 429 `{"error":"slow_down"}` (the rate
limits count refused requests too), 503. The body must be `application/json`; unknown fields are refused. A client's own
token (client credentials) is nobody's sign-in and is 401.

## Management API (`internal/admin/ssh.go`)

New service-account scopes: `ssh` (`ScopeSSH`: settings, keys, certificates) and `ssh:host` (`ScopeSSHHost`: sign
host certificates; `ssh` alone cannot). Personal API tokens need `admin` as for every route. Role: administrator of the
org (managers are refused). `{id}` is the tenant's id or name. Validation errors are `422` with the field named
(`ssh.cert_ttl`, …). `rotate` and `keys/{key}` DELETE need a recent re-authentication (`stepUp`): a console session that
has not re-authenticated in the last 5 minutes gets 403 field `reauth`; a service account is exempt; a personal API
token is always refused (it has no session). Settings changes need none.

| Method, path | Scope | |
| --- | --- | --- |
| `GET /api/orgs/{org}/tenants/{id}/ssh` | ssh | settings + keys (id, purpose, alg, public key, fingerprint, not_before, retire_at, expires, state `next`/`active`/`retired`) + endpoints (`discovery`, `ca_pub`, `known_hosts`, `krl`, `host_sign`) |
| `PATCH /api/orgs/{org}/tenants/{id}/ssh` | ssh | change settings (omitted keys keep their values; answers as GET); while SSH is on it makes what is missing: the keys and the application |
| `POST /api/orgs/{org}/tenants/{id}/ssh/rotate` | ssh | `{"purpose":"user"|"host","immediate":bool}` → 201, the new key (with its fingerprint) |
| `DELETE /api/orgs/{org}/tenants/{id}/ssh/keys/{key}` | ssh | remove a retired key |
| `GET /api/orgs/{org}/tenants/{id}/ssh/certificates` | ssh | `?q=&offset=&limit=&user=<id>&status=active|revoked|expired|all&host=true|false` → `{items, total}`, newest first, paged as the users are (25 by default, at most 100); `total` counts every match. `q` searches by prefix, ignoring case: the key id, fingerprint and serial (store search fields of `sshcert`), a principal whole (the `principals` words field) and the username or name of the user (a search of the users, whose certificates are then listed). The status is evaluated in the service, for the unexpired certificates a search or filter leaves (`ListSSHCertsCounted`) |
| `GET /api/orgs/{org}/users/{id}/ssh-certificates` | ssh | the user's certificates that have not expired, across the tenants, newest first, each with `tenant` (display name) and `tenant_name`; every one, no paging. Administrators of the organization and service accounts with `ssh` (`SSHCertsOfUser`); 403 for managers |
| `POST /api/orgs/{org}/tenants/{id}/ssh/certificates/{cert}/revoke` | ssh | `{cert}` is the record id, not the serial |
| `POST /api/orgs/{org}/tenants/{id}/ssh/host-certificates` | ssh:host | `{"public_key","principals":[…],"ttl_days"?}` → as sign |

Audit: `ssh.settings.update` (with field changes), `ssh.ca.create`, `ssh.ca.rotate`, `ssh.ca.remove`,
`ssh.cert.issue`, `ssh.cert.refused`, `ssh.cert.revoke`, `ssh.host.issue`, `ssh.host.refused`.

## Account page

Section "SSH certificates", shown when at least one tenant the user may use has SSH enabled. Lists those tenants
(name, principals the user would get, the `quisora ssh login <discovery URL>` command to copy), a form to paste a
public key and get a certificate (download as `<key>-cert.pub`), and the user's live certificates with Revoke.
Getting a certificate needs the session to have a second factor (`model.MFA(sess.AMR)`) and a re-authentication within
the last 5 minutes (`needReauth`, as for an API token). MaxAuthAge is checked against the later of the session's
AuthTime and that re-authentication (`authTime`), but only when the re-authentication used a second factor of the
account's own (an authenticator code or a passkey): the re-authentication mark is `<generation>@<unix>@<1|0>`, the last
part saying whether it did. An account with no second factor of its own (its MFA came from a `TrustMFA` provider)
re-authenticates with the password alone, which satisfies `needReauth` but does not make an old sign-in look new, so
for the certificate the session's own AuthTime counts. The request carries `Session` (amr and provider), so the tenant's
sign-in methods apply, and `SSHTenantsFor` lists only the tenants whose methods allow the session. The requests count
against the sign endpoint's rate limits (one budget; 429 "Too many certificate requests"). Via `account`; no
`ClientID`; `SessionEpoch` and `Stamp` are the session's. A refusal is 403 with the message. The account page has no live
updates: a revocation by an administrator shows when the page is loaded again or its tab comes back. The admin
console's stream names the user of an `sshcert` change (the hub reads the record's `user_id`), so the admin user page
follows it.

Account JSON API (session + CSRF): `GET /o/{org}/api-internal/account/ssh` (`tenants` with principals, the discovery
URL and `cert_ttl`; the user's unexpired user `certificates`; `mfa`),
`POST /o/{org}/api-internal/account/ssh/sign` `{tenant_id, public_key}`, `POST
/o/{org}/api-internal/account/ssh/certificates/{id}/revoke`.

## CLI (`quisora ssh …`)

No config file, master key or store: a plain HTTPS client. `--insecure` skips TLS verification (development);
`--ca-cert` trusts a PEM.

- `quisora ssh login <discovery URL>`: reads discovery; browser flow (loopback on 127.0.0.1, random port, PKCE S256,
  state, nonce, `acr_values=urn:quisora:acr:mfa`, `max_age=<max_auth_age>`), or `--device` (device flow: prints the
  code and URL). Opens the browser (`open`/`xdg-open`/`rundll32`), `--no-browser` prints the URL. Key: `--key <path>`
  uses that key (its `.pub`), writes `<path>-cert.pub`; otherwise a fresh ed25519 key in memory, added with the
  certificate to `ssh-agent` (`SSH_AUTH_SOCK`) with lifetime = certificate validity, comment
  `quisora:<org>/<tenant>`. In agent mode `login` also writes `~/.ssh/quisora/<org>-<tenant>.pub` and `-cert.pub`, with
  no private key (it removes a private key an earlier file-mode login left there), so that `IdentityFile <path>.pub`,
  `CertificateFile <path>-cert.pub` and `IdentitiesOnly yes` name the key in the agent; `status` lists these as
  `file (no key)`. It writes `~/.ssh/quisora/<org>-<tenant>` (0600), `.pub` and `-cert.pub` instead, and says how to use
  them, with `--no-agent`, with no agent (`warning: no ssh-agent: …: writing the key to a file instead`), when the
  agent refuses the key (locked, or an agent such as 1Password's or Secretive's that takes no imported keys:
  `warning: ssh-agent did not take the key (…): writing the key to a file instead`; the certificate is not thrown away),
  and on Windows, where the agent is a named pipe the CLI does not speak (the 0600 mode means nothing there; the user
  profile's access control protects the file). `--principal` (repeatable, in the prefixed form: `group:ops`), `--ttl`
  (at least 60 seconds, as the server; refused before anything is asked). Prints principals and expiry. The device
  flow sends `acr_values` and `max_age` to the device authorization endpoint, which stores them with the device code;
  when the user opens `/device` the sign-in meets them as an authorization request's do (a password-only session is
  stepped up, an older one signs in again), so `--device` gets a certificate from such a session as the browser flow
  does. Polling the token endpoint goes on until the code expires: `authorization_pending` waits, `slow_down` adds 5
  seconds, and a network error or a 5xx answer (not an answer about the code) is retried, further apart each time up to a
  minute, with one warning. When discovery says `"enabled": false` the command stops with "SSH certificates are turned
  off for the tenant" and asks the server for nothing else. A sign answer whose certificate does not parse is
  `the server's certificate is not valid` (not a TLS error).
- `quisora ssh status`: Quisora certificates in the agent (and files under `~/.ssh/quisora`) with principals and
  time left.
- `quisora ssh logout [<discovery URL>]`: removes them from the agent (and files).
- `quisora ssh host-sign <discovery URL> <host public key file>`: `--principal` (repeatable, default: the host's FQDN),
  `--ttl <days>` (`90`, `90d`, or hours that make whole days; 1 to 365; the tenant refuses more than its
  `host_ttl_days`; default: the tenant's), token from `--token`/`QUISORA_TOKEN` or
  `--client-id`/`--client-secret` (`QUISORA_CLIENT_ID`, `QUISORA_CLIENT_SECRET`) → client credentials with scope
  `ssh:host`, authenticated as `--auth-method` says: `auto` (the default) tries `client_secret_post`, which a service
  account is registered for unless made otherwise, and once more with `client_secret_basic` when the answer is
  `invalid_client`; `post` or `basic` tries that one only. Writes `<file without .pub>-cert.pub` and prints the
  `HostCertificate` line (the guide then has sshd reloaded: a renewed certificate is served only after a reload).
- `quisora ssh fetch <discovery URL>`: for cron or a systemd timer on servers and clients: writes `--ca-file`
  (default `/etc/ssh/quisora_user_ca.pub`) and `--krl-file` (default `/etc/ssh/quisora.krl`) atomically (temp file +
  rename), keeping the previous files when the server cannot be reached or the answer is not valid;
  `--known-hosts-file` optional; an empty value (`--ca-file=`) leaves that file alone (a client wants only the list and
  the known hosts). Everything is fetched and checked before anything is written. The user CA keys and the host CA lines
  are fetched whenever the list is, even when not written, because the list is installed only if its certificate sections
  name CA keys the tenant publishes (`ca.pub`, and `known_hosts`'s host keys), it parses strictly
  (`sshca.ParseKRL`), `ssh-keygen -Q -l -f` reads it when `ssh-keygen` is installed (sshd refuses every public-key login
  it cannot read its list for), and it is not older than the installed one. An older one is kept, with a note, exit 0,
  and the other files are still updated. Files whose bytes are unchanged are not written; the list's version and date
  change each time it is made, so it is rewritten whenever the bytes differ (its modification time shows the last
  successful fetch, which the guide's monitoring uses), and `updated` is printed for it only when what it revokes
  changed. It does not send `If-None-Match` (each run is four full answers, 16 rate-limit units). Exit 0 when current,
  1 on failure (files kept). It works while SSH is off (discovery still answers), warning that the list revokes every
  certificate; that is how turning SSH off reaches the servers.

## Ubuntu server setup (for the guide)

```
TrustedUserCAKeys /etc/ssh/quisora_user_ca.pub
RevokedKeys /etc/ssh/quisora.krl
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

The lines go in `/etc/ssh/sshd_config.d/50-quisora.conf` (RHEL 8's `sshd_config` has no such include: they go in the
main file, above any `Match`; the service is `sshd` there, `ssh` on Debian and Ubuntu). `/etc/ssh/principals/ubuntu`
holds `group:ops` (members of group ops may log in as ubuntu). `AuthorizedPrincipalsFile` is never left out and
privileged accounts are never mapped by username: a username is what a manager names a user. A systemd timer runs
`quisora ssh fetch` every minute, with `RandomizedDelaySec=` (a run is 16 of the address's 16 000 units a minute).
Host: `HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub`, sshd reloaded after every `host-sign`. sshd's
`RevokedKeys` covers user logins only; a client honours host revocation only with `RevokedHostKeys <krl>` in
`ssh_config`, which it gets from `fetch --ca-file= --krl-file … --known-hosts-file …` (the host CA lines in a file of
their own, named in `GlobalKnownHostsFile`; the list file must exist or ssh refuses every connection). The guide also
covers a break-glass login (certificates already issued outlast an outage, new ones cannot be signed), the backup
and restore steps (rotate and remove the CA keys), and monitoring (the fetch unit, the list file's age).

## Known limits

A certificate records the session or grant it was issued under (`SSHCert.SignIn`), and taking that sign-in back
(EndSessions: a session ended from another or by an administrator, or with the passkey it signed in with; a grant
revoked) revokes it for good. The sign-in is deleted first and its certificates listed and revoked after; the signer
stores the certificate first and then reads the sign-in again from the store (not a cache), and revokes the certificate
and refuses if it is gone. On a shared database (SQL) or a single node, whichever comes second sees the other, so a
certificate signed while its sign-in is ended (on a node still trusting a cached session or grant) does not survive it.
In a gossip cluster each node reads its own copy of the store, so the two can miss each other while the deletion and
the certificate are replicating: the window narrows to the replication lag, from the seconds of the caches, but does
not close. A grant is deleted whether or not its
certificates could be revoked (the failure is reported, a 503 to a client's revocation); whose certificates they are
comes from the caller (the grant record or the access token's claims), so the client's retry with the access token
revokes them though the grant is gone (a refresh token cannot be retried that way: the grant it is checked against is
gone, so a retry answers 200 and the certificates last until they expire); the user's own
sign-out (SignOutSession) does not, as it does not end offline grants, and "sign out other sessions" carries the kept
session's certificates to the new epoch (`sign_in_ended`, written when the session or grant is ended: an expiry is not an ending, so it cannot be
worked out from what is left). Open connections are ended by `fetch --end-revoked`, which reads sshd's certificate
logins from journald (root's lines only, `_UID=0`, so neither a session nor another local user can forge one) and
signals the connection's privileged process, only while it is still the one that logged it (root's sshd, whatever
its parent, so connections that outlived an sshd restart or came through socket activation are included; started before
the line on the clock since boot, so a wall-clock step cannot hide one; held by a pidfd from the check to the signal). Where that process leads a logind session (its cgroup is a
`session-<id>.scope` and logind names it the leader), the whole session is ended instead (`loginctl terminate-session`),
taking what it left running (tmux, nohup) with it; a connection made without PAM sits in the scope of whoever started
sshd, which it does not lead, so that is never ended. It also ends every connection logged in longer ago than the tenant's
`cert_ttl` (from the discovery document, on journald's monotonic clock, which stops in a suspend and so never ends one
early): its certificate has expired, and one that expired before its access was removed is never on the list, so no
connection outlives `cert_ttl`. The SSH application uses bearer tokens, not
DPoP. CA key rotation and first enabling are guarded by a lock per node, so two nodes acting in the same instant can each
make a key (both are published; the newer signs; the extra is removed by hand). An emailed one-time code counts as a
second factor (`model.MFA`). Restoring an older backup can republish a removed CA key (its tombstone is gone), undo manual
and written-down revocations, and has no record of certificates issued after it. Open sessions stay open.

## Tests

- `internal/sshca`: certificates parse with x/crypto and with `ssh-keygen -L`; KRLs are checked with `ssh-keygen -Q`
  (skipped when ssh-keygen is absent).
- Service: every refusal, principals, TTL caps, revocation reasons (each way access ends), rotation, KRL contents,
  audit events, unknown-outcome table rows.
- HTTP: sign endpoint with real tokens from the harness (MFA and not, wrong client, old auth_time, privileged),
  discovery, ca.pub, krl, rate limits (sign and the public documents), SSH off still publishing, the device flow with
  `acr_values` and `max_age`.
- Management API: routes in OpenAPI, scope sweep, admin vs manager.
- Console and account page: Playwright + axe.
- CLI: against an httptest Quisora; browser step driven by the test.
- End to end (`QUISORA_SSH_E2E=1`, needs Docker): a real Ubuntu sshd trusting the tenant CA; login works, revoked and
  expired certificates and wrong principals fail, host certificate verified by the client.
