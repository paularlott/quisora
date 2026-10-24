# Secrets in Vault or 1Password

Any secret setting can name its value in HashiCorp Vault (or OpenBao) or 1Password instead of holding it. The
configuration file then holds no secrets at all, only references to them, and the keys can be rotated in the store.

The secret settings are: `server.master_key` and `server.previous_master_keys`, `cluster.key` and
`cluster.previous_keys`, the database DSNs and passwords, the SMTP password, `storage.badgerdb.encryption_key`,
`server.restore_password`, and a VictoriaLogs URL with credentials in it.

## References

| Reference                               | Store                                                                                   |
| --------------------------------------- | --------------------------------------------------------------------------------------- |
| `op://<vault>/<item>/<field>`           | 1Password: the field of an item, by name (or id).                                       |
| `op://<vault>/<item>/<section>/<field>` | 1Password: a field in a section of the item.                                            |
| `vault://<path>#<field>`                | Vault: the API path after `/v1/`, KV version 1 or 2; field `value` when none is named.  |

Every other value is the value itself, so references and plain values mix freely.

```toml
[server]
master_key = "vault://secret/data/quisora#master_key"            # a KV version 2 mount called "secret"
previous_master_keys = ["vault://secret/data/quisora#previous_master_key"]

[storage.postgres]
dsn = "op://Infra/Quisora PostgreSQL/dsn"

[secrets.vault]
address = "https://vault.internal:8200"
token_file = "/etc/quisora/vault-token"   # or token = "…"; or AppRole: role_id, secret_id or secret_id_file
# namespace = "admin/quisora"             # Vault Enterprise
# ca_file = "/etc/quisora/internal-ca.pem"

[secrets.onepassword]
connect_url = "https://op-connect.internal:8080"   # 1Password Connect
connect_token_file = "/etc/quisora/op-connect-token"
# service_account_token = "ops_…"         # a service account instead of Connect: needs the 1Password build (below)
```

Use `https` (with `ca_file` for a private CA). Plain `http` works, for a store on the same host or a sidecar, but the
keys then cross the network unencrypted, and `serve` logs a warning naming the setting at every start.

In a KV version 2 mount the API path has `data/` after the mount name: the secret the Vault CLI calls
`secret/quisora` is `vault://secret/data/quisora#master_key`.

## When they are read

Every command that runs against the server (`serve`, `bootstrap`, `invite`, `sign-out`, `restore`…) reads the
references it needs when it starts, and `serve` refuses to start if a store cannot be read. The values are kept in
memory only: nothing is written to disk.

## Reloading

A configuration reload reads the master keys and the cluster keys from their stores again and switches to them:

- **SIGHUP** on one node; or
- **Read secret stores now** on the console's **System overview** (super admins, after confirming it is them). Every
  node runs it, checking first and changing nothing unless all can. Nodes sharing a database are reached through
  `cluster.notify`; without it, reload each node with SIGHUP.

A store that cannot be read fails the reload and leaves the keys in use as they were. The other settings (DSNs, the
SMTP password, the BadgerDB encryption key) are read at start-up only, like their plain values.

## Rotating the master key in the store

The [usual two steps](RUNNING.md#rotating-the-master-key), each an edit in the store and a reload:

1. Put the new key in the previous key's field (keeping the old one as the master key); reload.
2. Swap them: the new key as the master key, the old one as the previous key; reload.
3. Once the rotation status says `complete`, empty the previous key's field; reload.

An empty field means "no key", so a previous key's field can stay in the configuration between rotations. Removing
the old key before every secret is re-sealed is refused, as with keys in the configuration file. The cluster key
rotates the same way ([rotating the cluster key](RUNNING.md#rotating-the-cluster-key)).

## The stores' own credentials

They go in the configuration file, in a file it names (`*_file`: the file's first line), or in the environment
(`QUISORA_VAULT_TOKEN`, `QUISORA_ONEPASSWORD_CONNECT_TOKEN`…).

- Keep those files, and a configuration file that holds a secret, readable by the user Quisora runs as only
  (`chmod 600`): every command warns about one that others can read.
- Prefer Vault AppRole, with a short token lifetime, to a long-lived token.
- Give the Vault token, the 1Password service account or the Connect token read access to Quisora's items only.

## 1Password service accounts

1Password service accounts use 1Password's SDK, which talks to 1Password's servers over the internet. Builds include
it only with the `onepassword` build tag: `task build-1password`, the `quisora-1password-…` release binaries, or
`docker build --build-arg GO_TAGS=onepassword` (about 15 MB larger). Any other build reads 1Password through a Connect
server you run, and refuses a service account token with a message saying so. Vault and Connect can both run on your
own network.
