# Service accounts

A service account is a non-human principal of one organization, for automation: provisioning tools, deployment
pipelines, importers. It gets short-lived access tokens from its organization's token endpoint with the
[client credentials grant](oauth/client-credentials.md) and calls the management API (`/api/…`) and
[SCIM](API-TOKENS.md#scim-scim) with them as bearer tokens. Unlike a [personal API token](API-TOKENS.md) it belongs to
no person, so it keeps working when someone leaves, and it holds only the scopes it was granted, nothing a role
implies.

A service account acts as an administrator of its own organization within its scopes, and never as a super admin. It
has no tenant and is not an application: it does not appear in the list of clients. The server's own
administration (keys, backups, cluster, the audit log, the organization's settings) is closed to it.

## Making one

The **Service accounts** page of an organization in the console, or the management API (the operations are in the OpenAPI
document, under the Service accounts tag). Organization administrators and super admins manage service accounts, and so
does a service account that holds the `service_accounts` scope; managers cannot.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$QUISORA/api/orgs/acme/service-accounts" \
  -d '{"name": "hr-sync", "scopes": ["users", "groups"]}'
```

The response carries the account's `id` (its `client_id`), the `token_endpoint` to ask for tokens at and, shown once, its
`secret`. Quisora keeps only a hash of it.

How it authenticates at the token endpoint (`token_endpoint_auth_method`):

- `client_secret_post` (the default) or `client_secret_basic`: with the secret Quisora issued.
- `private_key_jwt`: with keys it holds, given as `jwks` or `jwks_uri`. No secret is ever issued, and asking to rotate
  one answers `422`. See [client authentication](oauth/client-authentication.md).

`fapi2_security_profile` applies the [FAPI 2.0](oauth/fapi2.md) profile (it needs `private_key_jwt`; its tokens are
bound to a [DPoP](oauth/dpop.md) key, which SCIM accepts and the management API does not).

```bash
# get a token (the token_endpoint from the response) and call the API
TOKEN=$(curl -s -u "$CLIENT_ID:$SECRET" "$TOKEN_ENDPOINT" -d grant_type=client_credentials | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/users?limit=10"
```

Ask for `scope=…` to get a token with fewer scopes than the account has; without it the token has all of them. The
token lasts 10 minutes by default and cannot be revoked: disabling or deleting the account, or taking a scope from it,
stops the tokens already issued at once, because the account is read at every request.

## Scopes

Every management route names the scope a service account needs to call it; the OpenAPI document lists it in each
operation's `serviceAccount` security requirement.

| Scope | Lets it | Organizations |
| --- | --- | --- |
| `users` | Manage users and managers: details, email addresses, sessions, linked providers, tokens, invitations | any |
| `manage_admins` | With `users`, manage the organization's administrators too (never super admins) | any |
| `groups` | Manage groups and their members | any |
| `providers` | Manage sign-in providers | any |
| `tenants` | Create, change and delete tenants | any |
| `clients` | Manage applications (OAuth clients) and the self-registered ones | any |
| `access` | Manage tenants' access lists | any |
| `ssh` | Manage tenants' SSH certificate authorities: settings, CA keys and issued certificates ([SSH certificates](ssh/README.md)) | any |
| `ssh:host` | Only sign SSH host certificates, for the machines that need one (`quisora ssh host-sign`: [host certificates](ssh/README.md#host-certificates)) | any |
| `import` | With `users`, create users with a password hash, an authenticator secret or provider links from another system ([API-TOKENS.md](API-TOKENS.md#importing-users-with-their-passwords-authenticator-apps-and-provider-links-import)) | any |
| `scim` | Use the SCIM API, `/scim/v2/<org>/…` | any |
| `service_accounts` | Manage the organization's service accounts, granting none more than it holds | any |
| `orgs:create` | Create organizations | the primary organization only |
| `orgs:delete` | Delete the organizations it created | the primary organization only |

Any service account may also read its own organization, its tenants and its applications, whatever its scopes. The
organization's settings, the audit log, emergency sign-out and the server's keys, backups and status are closed to
service accounts.

SCIM provisioning is a service account with the `scim` scope: Entra ID, Okta and similar tools use its `client_id` and
secret. The SCIM rules for what a provisioning client may touch
are unchanged: it never reaches a super admin, and it manages administrators only with the `manage_admins` scope.

## Who may grant what

- Creating, changing, rotating and deleting service accounts is for organization administrators, super admins and
  accounts with `service_accounts`.
- A service account grants only scopes it holds itself, so a chain of accounts never widens.
- Only super admins grant `import`, `orgs:create` and `orgs:delete`; the last two exist only on the primary
  organization.
- Whoever changes, rotates or deletes an account must be able to grant every scope it holds, so an administrator cannot
  reach an account that holds `import`.
- The one exception is the first service account made with a new organization (below): whoever creates the
  organization (a super admin, or an account with `orgs:create`) may give it any of the organization's scopes,
  `import` and `service_accounts` included.
- A service account is not asked to re-authenticate for the sensitive changes a person must confirm; what it may do was
  decided when it was granted its scopes. Granting `manage_admins` or `orgs:delete` is therefore a decision to take seriously.

## Deploying organizations

A provisioning pipeline that creates an organization for each customer, sets it up and removes it again needs one
account on the primary organization, made by a super admin:

1. A super admin makes a service account on the primary organization with `orgs:create` (and `orgs:delete` if the
   pipeline also removes organizations).
2. The pipeline gets a token from the primary organization's token endpoint and creates the organization, with its
   first service account in the same request. The response carries that account's secret, shown once:

   ```bash
   curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$QUISORA/api/orgs" -d '{
     "name": "customer-42",
     "display_name": "Customer 42",
     "service_account": {
       "name": "setup",
       "scopes": ["users", "manage_admins", "groups", "providers", "tenants", "clients", "access", "ssh", "ssh:host", "import", "service_accounts"]
     }
   }'
   ```

   If the account cannot be created, the organization is not left behind, so a retry starts clean.
3. The pipeline gets a token from the new organization's token endpoint (`service_account.token_endpoint` in the
   response, which names the organization by its id) with that account, and sets the organization up: users (with
   `import`, their password hashes and authenticator secrets), tenants, applications, providers, and the organization's
   long-lived service accounts (granting no more than `setup` holds).
4. It deletes the `setup` account when it is done, or keeps it for later changes.
5. To remove the organization, it calls `DELETE /api/orgs/customer-42?cascade=1` with the primary organization's
   account. An account with `orgs:delete` deletes only organizations it created itself; it cannot delete the primary
   organization or one a person made.

## Rotating credentials

**A secret**: `POST /api/orgs/{org}/service-accounts/{id}/secret` (or **Rotate secret** in the console) makes a new one and
the old one stops working at once: there is no overlap, so update the consumer straight after. Tokens issued with the old
secret keep working until they expire (10 minutes by default). Where an overlap matters, use `private_key_jwt`.

**Keys** (`private_key_jwt`): with `jwks`, `PATCH` the account with a key set holding the old and the new key, switch the
consumer to the new key, then `PATCH` again with the new key alone. With `jwks_uri`, publish both keys at that address
the same way. The account is never without a working key.

## Auditing

Every change a service account makes is recorded in the [audit log](RUNNING.md#audit-log) with the actor
`service:<name>`. Changes to the accounts themselves are events too (`service_account.create`,
`service_account.update`, `service_account.secret.rotate`, `service_account.delete`, with the scopes granted). Calls
refused for a missing scope are recorded as `api.request.refused`. Name accounts for what uses them, so the log reads
`service:hr-sync` rather than something to look up, and review the list of accounts and their scopes with your other
access reviews ([SOC2.md](SOC2.md)).
