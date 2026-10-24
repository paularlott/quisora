# SOC 2 with Quisora and VictoriaLogs

This maps the SOC 2 Trust Services Criteria an identity provider is examined against to what Quisora does, what you
must run around it, and where the evidence comes from. It assumes audit events go to VictoriaLogs
([RUNNING.md](RUNNING.md#audit-log)): the database audit trail is not meant for an audit.

A Type 2 report examines whether the controls **operated throughout the audit period** (usually 6–12 months). No code
supplies that: it needs your records of reviews, changes, incidents and tests made during the period. The sections
below say which records, and the queries that produce most of them.

## What Quisora provides, what you provide

| Area | Quisora | You |
| --- | --- | --- |
| Audit trail (CC7.2, CC7.3) | Every security-relevant action recorded with who, what, when, where from and outcome ([what is recorded](RUNNING.md#what-is-recorded)); written to disk on each node before it is sent; numbered per node so a missing event shows | Run VictoriaLogs as below; keep it for the period; review it |
| Logical access (CC6.1–CC6.3) | Roles; MFA always on for managers and above; per-organization MFA policy; per-application access lists; end dates; session limits; emergency sign-out | Decide who gets which role; review access regularly |
| Authentication (CC6.1) | Passkeys, TOTP, recovery codes, offline checks against common and guessable passwords (NIST SP 800-63B), lockouts, rate limits | Set the organization policies |
| Change management (CC8.1) | Every configuration change in the console or API audited field by field; cluster reloads and key rotations audited | Approve changes before they are made; keep the approval |
| Encryption (CC6.1, CC6.7) | Secrets sealed with the master key; TLS for every connection it makes; key rotation without downtime | Keep the master key in a secret store; rotate it on schedule |
| Availability (A1.2) | Clustering, quorum writes, backups verified before restore | Run backups; test a restore each period |
| Monitoring (CC7.2) | Prometheus metrics for readiness, audit delivery, queues, failures | Alert on them; keep the alert history |
| Time (CC7.2) | Refuses to start with a clock before 2025; checks every node's clock against the others' and refuses to serve when it is off | Run NTP on every node |

## The audit log

### Completeness

Every event a node accepts is written to its spool on disk before the request goes on, and leaves the spool only once
VictoriaLogs has taken it ([Spool](RUNNING.md#spool)). An event VictoriaLogs will never receive (a spool full after a
long outage, a disk that fails) is written in full to the structured log as `audit.undelivered`.

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

### Retention

Set `-retentionPeriod` to cover the audit period plus the time until the report is issued: 400 days covers a 12-month
period with a margin. The structured log (with `audit.undelivered`) needs the same retention in your log pipeline.

### Who reads it

Administrators see their own organization's events in the console; super admins see every organization's. Auditors
read through the `auditor` vmauth user with LogsQL.

## Evidence, and how to get it

| Control | Evidence | How |
| --- | --- | --- |
| Access reviews (CC6.2, CC6.3) | Each organization's administrators, managers and their last sign-in, reviewed and signed off each quarter | `GET /api/orgs/<org>/users?role=admin` (and `manager`, `superadmin`), saved with the reviewer's sign-off; changes made as a result show as `user.update` events |
| Joiners and leavers (CC6.2) | Accounts created, disabled, ended and deleted, matched to HR records | `action:user.create OR action:user.provision OR action:user.update OR action:user.expire OR action:user.delete` |
| Privileged changes (CC6.3) | Role changes | `action:user.update AND detail.changed.role:*` |
| Authentication policy (CC6.1) | MFA required where the policy says | `action:org.update AND detail.changed.settings.require_mfa:*`; the organization settings pages |
| Change management (CC8.1) | Configuration changes, each matched to an approved change request | `action:org.update OR action:tenant.* OR action:client.* OR action:provider.* OR action:cluster.reload OR action:keys.*`; your change tickets |
| Security events (CC7.2, CC7.3) | Alerts raised and how each was handled | Alerts on `login.lockout`, `login.limited`, `oauth.refresh.reuse`, `oauth.code.replay`, `passkey.clone`, `apitoken.refused` ([alerts](RUNNING.md#metrics)); your incident tickets |
| Incident response (CC7.4) | Emergency sign-outs and what followed | `action:org.signout OR action:server.signout OR action:signout.sweep`; [emergency-sign-out.md](emergency-sign-out.md) |
| Audit log completeness (CC7.2) | The sequence check above, each month, with the boots and last numbers from the structured log; no `audit.undelivered` lines, or each one explained | The queries above; your log pipeline |
| Backups and recovery (A1.2, A1.3) | Backups made on schedule; a restore tested each period | `action:backup.download`, `action:backup.restore`; the record of the restore test |
| Key management (CC6.1) | Master key and signing key rotations | `action:keys.rotate OR action:keys.create`; `quisora_master_key_rotation` |
| Time (CC7.2) | Clocks synchronised | NTP monitoring; `clock_offset_ms` in `/readyz` stays within milliseconds, `clock_skewed` and `skew_refused` stay at 0; a node more than 5 s off refuses to serve and logs it |
| Monitoring (CC7.2) | Alerts configured and their history | Your alerting system |

## Not covered by Quisora

Physical security, HR processes, vendor management, risk assessment, the security of the hosts and networks it runs
on, and the policies themselves (access control, change management, incident response, backup) are yours. Quisora's
own development (code review, tests, dependency scanning: `govulncheck`, `npm audit`) is evidence only when you build
and run a reviewed release from source.
