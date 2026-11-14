# SOC 2 with Quisora and VictoriaLogs

This maps the SOC 2 Trust Services Criteria an identity provider is examined against to what Quisora does, what you
must run around it, and where the evidence comes from. It assumes audit events go to VictoriaLogs
([RUNNING.md](RUNNING.md#audit-log)): the database audit trail is not meant for an audit (it is kept for days, and in a
gossip cluster each node keeps only the events it recorded itself, so a lost node's events are lost with it).

A Type 2 report examines whether the controls **operated throughout the audit period** (usually 6–12 months). No code
supplies that: it needs your records of reviews, changes, incidents and tests made during the period. The sections
below say which records, and the queries that produce most of them.

## What Quisora provides, what you provide

| Area | Quisora | You |
| --- | --- | --- |
| Audit trail (CC7.2, CC7.3) | Every security-relevant action recorded with who, what, when, where from and outcome ([what is recorded](RUNNING.md#what-is-recorded)); written to disk on each node before it is sent; numbered per node so a missing event shows | Run VictoriaLogs as below; keep it for the period; review it |
| Logical access (CC6.1–CC6.3) | Roles; MFA always on for managers and above; per-organization MFA policy; per-application access lists; end dates; session limits; emergency sign-out; automation credentials as [service accounts](SERVICE-ACCOUNTS.md) with least-privilege scopes, audited as `service:<name>`; server access by short-lived [SSH certificates](ssh/README.md) from a second-factor sign-in, which end with the person's access | Decide who gets which role and which scopes; review access, service accounts and their scopes regularly; for SSH, the principals files on the servers (`AuthorizedPrincipalsFile`, privileged accounts by `group:` principal), the timer that fetches the revocation list and its [monitoring](ssh/README.md#monitoring), `RevokedHostKeys` on clients, and a break-glass login that does not depend on Quisora |
| Authentication (CC6.1) | Passkeys, TOTP, recovery codes, offline checks against common and guessable passwords (NIST SP 800-63B), lockouts, rate limits | Set the organization policies |
| Change management (CC8.1) | Every configuration change in the console or API audited field by field; cluster reloads, key rotations and a forced start (`cluster.force_start`) audited; an operator's command against a running node (a break-glass invitation, an emergency `sign-out`, `force-start`) recorded as `command:<name>`, not as the system | Approve changes before they are made; keep the approval |
| Encryption (CC6.1, CC6.7) | Secrets sealed with the master key; TLS for every connection it makes; key rotation without downtime | Keep the master key in a secret store; rotate it on schedule |
| Availability (A1.2) | Clustering (every write committed on a majority of the nodes, partitions that move to another node when one is lost), backups verified before restore | Run backups; test a restore each period |
| Monitoring (CC7.2) | Prometheus metrics for readiness, audit delivery, queues, failures | Alert on them; keep the alert history |
| Time (CC7.2) | Refuses to start with a clock before 2025; in a cluster, checks every node's clock against the others' and refuses to serve when it is off | Run NTP on every node (a single node has only its own clock: monitor its NTP sync) |

## The audit log

### Settings

- `audit.victorialogs_url` set: without it every start logs a warning that the database trail is not an audit trail.
- `audit.logins = true` (the default): successful sign-ins are the evidence of access reviews and monitoring. Failed
  ones, lock-outs and refusals are always recorded (a failure or refusal repeated from the same address within a
  minute in the next one's `detail.suppressed` count, and what one address causes past its allowance of events in
  `detail.address_suppressed`; every address that causes one is named until the organization's 200 events a minute
  naming addresses (of each kind, on each node) are spent, and every existing account tried is named once a minute
  per sign-in step whatever the addresses do: [what is recorded](RUNNING.md#what-is-recorded)).
- `audit.tokens = true` if you must show every refresh and client credentials token issued (off by default: new
  grants, revocations and reuse are always recorded).

### What it records, and when

An event is recorded when the action has been made, as its last step: a node that crashes between the two (a power
cut in that window of one request) leaves a change without its event, and without a gap in the numbering below, since
the event never got a number. Every request the API refuses for the actor (a token without the scope, a missing CSRF
header, a console session without a second factor, an action the actor's role does not permit) is recorded as
`api.request.refused`, at most once a minute per actor and reason.

### Completeness

Every event a node accepts is written to its spool on disk before the request goes on (or, while the spool's disk
does not answer within 2 seconds, written in full to the structured log and spooled once the disk answers, while the
spool's queue has room: an event that finds it full is in the structured log only), and leaves
the spool only once VictoriaLogs has taken it ([Spool](RUNNING.md#spool)). An event VictoriaLogs will never receive (a spool full after a
long outage, a disk that fails, a full queue) is written in full to the structured log as `audit.undelivered`; so is
one logged because the disk did not answer in time, which VictoriaLogs receives as well once it does.

Every event carries `node`, `boot` (random, new at each start of the process) and `seq` (1, 2, 3… within that boot,
in the order the node accepted the events). Delivery is at least once (a batch can arrive twice), so an event's `seq`
may appear more than once; count each once. For each node and boot, every number from 1 up to the highest that
VictoriaLogs holds should be there:

```
app:quisora | stats by (node, boot) count_uniq(seq) as held, min(seq) as first, max(seq) as last
            | math (last - held) as missing
            | filter missing:>0 or first:>1
```

Run it over a window that covers whole boots (a boot that started before the window shows its start as missing:
widen the window). A row is a boot with events missing between its first and its last held: each missing one is in
the structured log as `audit.undelivered` (with the same `boot` and `seq`), or was removed from VictoriaLogs.

What the query cannot see on its own:

- **Events after the last one held.** A node logs `audit writer stopped` with its `boot` and `last_seq` when it stops
  cleanly: compare that number with the boot's `last`. After a crash there is no such line; the events accepted
  before it are in the node's spool and are sent after its next start, so check again once the node is back.
- **A boot none of whose events arrived.** Every start logs `audit events from this start are numbered` with its
  `boot`: every boot in the structured log should have a row in VictoriaLogs (`app:quisora | uniq by (node, boot)`).

So the check needs the structured log alongside VictoriaLogs, kept as long. Keep the queries and their results for
the period (monthly is common).

When VictoriaLogs refuses events, the spool decides by the answer:

- **For what the events are** (400, 413, 422: it will never take them): they are written in full to the structured
  log as `audit.undelivered`, with VictoriaLogs' reason, and leave the spool, so they do not hold back the events
  after them. A refused batch is split until the refused events are found, so the other events sent with them, of
  every organization, still reach VictoriaLogs. The splitting is bounded (up to 33 refused events scattered through a
  full batch are found; past that, or in a batch refused wholesale, events that share a part with a refused one are
  logged as `audit.undelivered` with it: [Spool](RUNNING.md#spool)).
- **For who is asking** (401, 403: wrong credentials, or vmauth misconfigured): nothing is dropped. Every event waits
  in the spool until the credentials are fixed, and the log says which. Alert on `quisora_audit_spool_bytes` growing:
  past `audit.victorialogs_spool_max_mb` the oldest events leave the spool as `audit.undelivered`.

The shipped structured log is the other half: alert on `audit.undelivered` and keep those lines as long as the audit
log itself.

### Protection

Quisora writes and reads VictoriaLogs; nothing else should be able to write to it, and nobody should be able to
delete from it during the retention period. VictoriaLogs has no users of its own, so put **vmauth** (VictoriaMetrics'
authenticating proxy) in front of it and let nothing else reach it (bind VictoriaLogs to a private address or a
container network that only vmauth shares):

```yaml
# vmauth.yml
users:
  - username: quisora          # the nodes: insert and the audit pages' reads, nothing else
    password: "%{QUISORA_VL_PASSWORD}"
    url_map:
      - src_paths: ["/insert/jsonline", "/select/logsql/query"]
        url_prefix: "http://victorialogs:9428"
  - username: auditor          # read-only, for reviews and the auditor
    password: "%{AUDITOR_VL_PASSWORD}"
    url_map:
      - src_paths: ["/select/.*"]
        url_prefix: "http://victorialogs:9428"
```

```bash
vmauth -auth.config=vmauth.yml -httpListenAddr=:8427
victoria-logs -retentionPeriod=400d -httpListenAddr=127.0.0.1:9428   # or a private network
```

```toml
[audit]
victorialogs_url = "op://Infra/Quisora VictoriaLogs/url"   # https://quisora:<password>@vmauth.internal:8427
```

- Use TLS between Quisora and vmauth (`https://`; put the URL, which holds the password, in a
  [secret store](secret-stores.md)).
- No vmauth user gets any other path, so no credential Quisora or a reviewer holds can delete or rewrite events.
- Restrict the host and volume VictoriaLogs runs on to the people who operate it, and keep that list as evidence.
- Back up VictoriaLogs' data directory (a filesystem snapshot) to storage that cannot be changed for the retention
  period (object storage with object lock, say).
- The events carry no signature or hash chain: their integrity rests on the access controls above. Until VictoriaLogs
  has taken them they are in each node's spool (`<data_dir>/auditspool`), where whoever has access to the node's data
  directory could change them: list node host access as a control too.

### Retention

Set `-retentionPeriod` to cover the audit period plus the time until the report is issued: 400 days covers a 12-month
period with a margin. The structured log (with `audit.undelivered`) needs the same retention in your log pipeline.

### Who reads it

Administrators see their own organization's events in the console; super admins see every organization's. Auditors
read through the `auditor` vmauth user with LogsQL.

## Evidence, and how to get it

| Control | Evidence | How |
| --- | --- | --- |
| Access reviews (CC6.2, CC6.3) | Each organization's administrators, managers and their last sign-in, reviewed and signed off each quarter | `GET /api/orgs/<org>/users?role=admin` (and `manager`, `super_admin`), saved with the reviewer's sign-off; changes made as a result show as `user.update` events |
| Joiners and leavers (CC6.2) | Accounts created, invited, disabled, locked out, ended and deleted, matched to HR records | `action:user.create OR action:user.provision OR action:user.invite OR action:user.update OR action:user.password OR action:user.locked_out OR action:user.expire OR action:user.delete` |
| Privileged changes (CC6.3) | Role changes (an update that also sets a password is recorded as `user.password`) | `detail.changed.role:*` |
| Authentication policy (CC6.1) | MFA required where the policy says | `action:org.update AND detail.changed.settings.require_mfa:*`; the organization settings pages |
| Change management (CC8.1) | Configuration changes, each matched to an approved change request | `action:org.update OR action:tenant.* OR action:client.* OR action:provider.* OR action:cluster.reload OR action:cluster.force_start OR action:keys.*`; your change tickets |
| Operator commands (CC6.1, CC8.1) | Each command an operator ran against a running node: which one, from which address, authenticated how (a request signed with the master key; for a forced start, access to the node's data directory), matched to an approved change or break-glass ticket (`invite --break-glass --super-admin` also records the account's promotion as `user.update` by `command:invite`) | `actor:command:* OR action:user.invite.break_glass OR action:server.signout OR action:org.signout OR action:cluster.force_start` (`detail.command`, `detail.authenticated`, `ip`); commands run against a stopped node's store show as `cli:<os user>@<host>` |
| Security events (CC7.2, CC7.3) | Alerts raised and how each was handled | Alerts on `login.lockout`, `login.limited`, `oauth.refresh.reuse`, `oauth.code.replay`, `passkey.clone`, `apitoken.refused`, `api.request.refused` ([alerts](RUNNING.md#metrics)); your incident tickets |
| Incident response (CC7.4) | Emergency sign-outs and what followed | `action:org.signout OR action:server.signout OR action:signout.sweep`; [emergency-sign-out.md](emergency-sign-out.md) |
| Audit log completeness (CC7.2) | The sequence check above, each month, with the boots and last numbers from the structured log; no `audit.undelivered` lines, or each one explained | The queries above; your log pipeline |
| Backups and recovery (A1.2, A1.3) | Backups made on schedule; a restore tested each period | `action:backup.download`, `action:backup.restore`; the record of the restore test |
| Key management (CC6.1) | Master key and signing key rotations | `action:keys.rotate OR action:keys.create`; `quisora_master_key_rotation` |
| SSH access (CC6.1–CC6.3) | Which tenants issue SSH certificates, who got one and for which principals, revocations, and CA key rotations and removals | `action:ssh.*` (`ssh.cert.issue`, `ssh.cert.refused`, `ssh.cert.revoke`, `ssh.ca.rotate`, `ssh.ca.remove`, `ssh.settings.update`); sshd's log on the servers; the fetch unit's status and the age of each server's revocation list file; [SSH certificates](ssh/README.md#what-is-recorded) |
| Time (CC7.2) | Clocks synchronised | NTP monitoring; `clock_offset_ms` in `/readyz` stays within milliseconds, `clock_skewed` and `skew_refused` stay at 0; a node more than 5 s off refuses to serve and logs it |
| Monitoring (CC7.2) | Alerts configured and their history | Your alerting system |

## Not covered by Quisora

Physical security, HR processes, vendor management, risk assessment, the security of the hosts and networks it runs
on, and the policies themselves (access control, change management, incident response, backup) are yours. Quisora's
own development (code review, tests, dependency scanning: `govulncheck`, `npm audit`) is evidence only when you build
and run a reviewed release from source.
