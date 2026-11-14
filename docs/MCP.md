# MCP servers and self-registered apps

AI clients (Claude, ChatGPT, IDE assistants and others) connect to MCP servers on behalf of a user. Under the MCP
authorization spec the MCP server is an OAuth resource server, Quisora is its authorization server, and the AI
client registers itself with Quisora instead of being set up by an administrator. Each organization is its own
authorization server, with its own issuer, `https://id.example.com/o/<organization id>`, and its own endpoints under
it: the MCP server names the organization of its users, and everything below is that organization's. Quisora supports
both ways a client registers itself:

- **Client ID Metadata Documents**: the client's `client_id` is an https URL (at most 190 characters) serving a small JSON document that
  describes it (name, redirect URIs). Quisora reads it the first time the client is used and again after a day.
- **Dynamic client registration** (RFC 7591): the client posts its metadata to the organization's
  `/o/<organization id>/oauth/register` and gets a `client_id` (`dyn-…`).

Both are advertised in the organization's discovery document (`registration_endpoint`,
`client_id_metadata_document_supported`), which MCP clients find where RFC 8414 puts it:
`/.well-known/oauth-authorization-server/o/<organization id>` (also `/.well-known/openid-configuration/o/<organization id>`
and, under the organization, `/o/<organization id>/.well-known/…`). The documents are served at the organization's id
form only, since the issuer in a document must be the address it was fetched from: asked for by the organization's name,
they answer with a permanent redirect to the id form.

Quisora also runs an MCP server of its own, for managing an organization's users and groups from an AI client:
[Quisora's own MCP server](#quisoras-own-mcp-server) below.

## Setting it up

1. **Pick the tenant** the MCP server's users sign in through, and in its **Sign-in rules** turn on **Allow
   self-registered apps** and add the MCP server's address under **Resources** (for example
   `https://mcp.example.com/mcp`, exactly as the MCP server names itself in its protected resource metadata). A
   resource is an https URL without a query (plain http only on `127.0.0.1` or `[::1]`) and belongs to one tenant
   of the organization (another organization may own the same address: its tokens carry its own issuer); letter case, a default port or a trailing slash do not make a different one. The same settings through the API:

   ```bash
   curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"resources":["https://mcp.example.com/mcp"],"settings":{...the tenant'"'"'s settings...,"self_registration":true}}' \
     "$QUISORA/api/orgs/<org>/tenants/<tenant name or id>"
   ```

   `<org>` is the organization's name (`primary` on a freshly bootstrapped server); the tenant's name (its "address
   name") and its ID are both at the top of its page in the console.

2. **On the MCP server**:
   - Publish `/.well-known/oauth-protected-resource` (RFC 9728) with `"resource": "https://mcp.example.com/mcp"` and
     `"authorization_servers": ["https://id.example.com/o/<organization id>"]` (the organization's issuer).
   - Answer a request without a valid token with `401` and
     `WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`.
   - Check each access token. Either verify the JWT yourself (signature against the organization's `/o/<organization id>/oauth/jwks`, `iss` is the organization's issuer,
     `aud` contains your resource URL, `exp`), or introspect it at `/o/<organization id>/oauth/introspect` as a
     confidential client of the same organization with **May introspect every token of the organization** turned on.

That is all: the AI client finds Quisora from the protected resource metadata, registers itself, and signs the user
in with PKCE, naming the MCP server as `resource`.

## What applies to self-registered apps

- **The tenant's rules.** A self-registered app belongs to the organization it registered at or was first
  authorized in. The same app (one metadata-document URL, say) used with two organizations is two applications, one
  record in each, with the same `client_id`; each is limited to its organization's tenants and resources, and a token
  of one is nothing to the other. Within the organization every sign-in is tied to one tenant: the authorization
  request must name a resource, and the tenant that owns it decides everything else, as for any of its applications:
  who may sign in (members-only access), which sign-in methods, whether a second factor is needed. A request without a resource, or
  for a resource whose tenant does not allow self-registered apps, is refused (`invalid_target`). Turning the switch
  off, or removing the resource, also stops the apps' refresh tokens and makes their access tokens inactive at
  introspection at once; an MCP server that verifies JWTs itself accepts one until it expires (`tokens.access_ttl`,
  10 minutes by default).
- **Public clients only**, always with PKCE, for user sign-in: no client secret, no client credentials grant, no
  introspection.
- **Scopes**: `openid`, `profile`, `email` and `offline_access` at most.
- **Redirect URIs** (RFC 8252): https; http on `localhost`, `127.0.0.1` or `[::1]`, where any port is accepted at
  sign-in (a desktop app listens on whichever port is free); or a private-use scheme named after a domain the app
  owns, such as `com.example.app:/callback` (a scheme without a dot, like `myapp:`, is refused). Never a fragment or
  credentials in the URI. Each at most 512 characters and all of them together at most 2,048 (the same in a metadata
  document): every registration is audited with them, and anyone may register. This is a deliberate limit, and it
  applies each time a stored app's metadata document is read again too: an app whose document goes over it (or was
  stored before the caps applied) is no longer refreshed, which the log records as `oidc: client metadata document
  refused: its redirect URIs are over the length caps` with the app's `client_id` and both caps, and it becomes
  unknown once its stored copy is a week old (see **Document changes**).
- **Consent is always asked**, with a warning that the app is not verified by the organization and where it sends
  the result (a host, or the app scheme for a desktop app): its name is only what it calls itself.
- **Registration is open only where it can be used**: an organization with no tenant that allows self-registered apps
  for a resource it owns answers `/oauth/register` with `403 access_denied`.
- **Abuse limits**: 10 registration requests per address and minute, 100 registrations made per address and
  organization a day, 60 registrations made per organization and minute from every address together, the last 20 of
  them only for addresses that have made none at the organization that day, so a few addresses registering again and
  again cannot keep everyone else's apps from registering (refused requests count toward none but the first, so bad
  requests from a few addresses cannot block others, and leave nothing behind that lasts a day) (`429 slow_down` past
  any of them). An IPv6 address counts as its /64, and its /48 is counted as well: 40 requests a minute and 400
  registrations a day per /48, and an address is new to the organization only if its /48 is too, so the /64s of one
  allocation cannot pass for many new addresses. At most 10,000 registrations
  per organization nobody has used yet (apps people use never count; at the cap, a new registration removes one of
  the unused ones picked at random among those registered over an hour ago, so a flood cannot stop others
  registering, nor remove an app that has just registered before its first sign-in; that removal ends any access
  users hold to the app, as **Revoke** does), and a registration never used to sign anyone in is removed after a day.
  An app counts as used from its first authorization, which is recorded before its code is issued: when that cannot
  be recorded, the user is asked to try again. An app nobody has signed in with yet is given no
  CORS origin (its https redirect URIs count once it has been used), so a browser app's first request through
  pushed authorization (`/oauth/par`, which it calls from script) is refused by the browser until its first
  authorization: such an app starts its first sign-in with a plain authorization request (a redirect, which needs no
  CORS), and may use PAR from then on. A metadata
  document is read only for a resource whose tenant accepts self-registered apps, at most 20 new documents per address
  and minute (80 per IPv6 /48) and once a minute per URL and organization, with the same SSRF guard as JWKS (no private or loopback
  addresses unless listed in `server.allowed_networks` or `server.allow_private_networks` is set), at most 5 KB; the
  app is stored only once a user lets it sign in. Until then what the document said (its name, redirect URIs and
  scope, not the document as it was written) is kept in the sign-in that read it (which counts toward the address's
  `limits.flows_per_ip` and `limits.held_kb`), and what was read in the last minute is shared, so requests at
  the same time for one URL make one read, and one organization's requests cannot keep another's app from being read.
  In a cluster a request that finds the minute's read taken by another node waits for what that node shares (up to 9
  seconds: the read's 8-second timeout and a second to share it), and is answered at once when that read found no
  valid document (a note an earlier minute's read left is removed when the next minute's read begins). That shared
  copy is a cache with a memory cap of its own (see [RUNNING.md](RUNNING.md)), apart from sign-in state: documents
  read for requests that never start a sign-in cannot fill the memory sign-ins need, and at the cap the newest reads
  take the room of the oldest, so a full cache refuses no sign-in. Should the minute's read be over and its copy gone
  from the cache (reads from hundreds of addresses at once, each within its 20 a minute, turning the whole cap over),
  the next sign-in that minute does not wait for it: it reads the document again, at most 5 times a minute per URL and
  organization (past them it is told the app is unknown, at once). The cap is a node's own
  memory's: with a shared database the cache is kept in the database, under the same cap for the rows each node
  writes. Every sign-in to an app not stored yet counts toward its address's 20 a minute, whether the document was
  read for it or found shared.
- **Document changes**: a stored app's document is read again once a day, in the background: requests naming the app
  are answered from the stored copy at once while it is read (once at a time per node, at most once a minute per
  organization), so a slow or stalled document server holds no request. A stored app is as old as the read that
  stored it, made when its first sign-in began, not when the user consented. The stored copy is used for up to a week
  while its URL cannot be read (a network error, a timeout, any other answer than the ones below, or a document
  refused, such as one over the redirect URI caps); past that the document is read for the request, as for an app not
  stored (within the address's 20 a minute), and the app is unknown until it is read. A document whose own URL answers
  `404 Not Found` or `410 Gone` has been withdrawn by its author, once it has answered so for ten minutes without a
  break: every read from the first such answer on found it gone, none more than ten minutes after the one before. A
  document gone once and then found again was a hiccup, such as a CDN edge or a deploy, and nothing ends; nor do two
  such answers further apart than ten minutes with no read in between, which start the ten minutes again. So an app
  read less often than every ten minutes (a lightly used one, read as people sign in to it) is not ended this way:
  its stored copy is not refreshed meanwhile, and it is unknown once that is a week old, as above. The app ends then, as **Revoke** ends one (every
  user's access to it, then the app), recorded as `client.self_registered.revoke` by the system with the answer as its
  `reason`. Only Quisora's own read of that exact URL decides it (no redirect is followed), so nobody but whoever serves
  the URL can end an app this way; a later sign-in naming the URL reads it again and asks the user, as for a new app.
  If the new copy changes the redirect URIs, codes issued before the change are no longer
  redeemed (the user signs in again and is asked again, as always), and a sign-in under way whose redirect URI the
  new copy no longer names ends without a code. The same holds for an administrator's application whose redirect
  URIs are changed during a sign-in.

## Seeing and removing them

The organization lists its **Self-registered apps**, with the host each sends sign-ins to, how many users it holds
access for and when it was last used. **Revoke** ends every user's access to it and removes it from the organization
(a metadata-document app can return by asking each user again; a registered one has to register again). The API:

```bash
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/<org>/self-registered"
curl -X DELETE -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/<org>/self-registered/<client id>"
```

A user sees each app under **Connected apps** on their account page and can remove it there too.

## Quisora's own MCP server

Quisora is also an MCP server itself: an AI client (Claude, say) signed in by one of an organization's managers or
administrators can look up and manage the organization's users and groups for them. Each organization's server is at

```
https://id.example.com/o/<organization id>/mcp
```

and it is off until a super admin switches it on for the organization. It is an MCP server like any other as far as
sign-in goes, so everything above applies to it, and nothing else decides who may use it.

### Turning it on

1. **Switch it on for the organization.** A super admin edits the organization on the **Organizations** page and
   turns on **MCP server** under **AI assistants** (`settings.mcp_server` in the API). Until then its address and
   metadata answer 404. The organization's overview then lists the address under **Addresses**, to copy.
2. **Choose who may sign AI clients in.** Pick (or make) the tenant whose sign-in rules should apply, and in its
   **Sign-in rules** turn on **Allow self-registered apps** and add the address under **Resources**. Until a tenant
   does, the overview says no AI client can sign in yet.

Then give the address to the AI client (in Claude, add it as a custom connector). The client finds Quisora from the
server's protected resource metadata
(`/.well-known/oauth-protected-resource/o/<organization id>/mcp`), registers itself, and the person signs in and
approves it on the consent page, which warns that the client will manage the organization as them. Whoever signs a
client in hands it their management rights for as long as its refresh token lasts (the tenant's token lifetimes
apply), so, as with the admin console, it needs a sign-in with a passkey or an authenticator code, whatever the
tenant requires.

An application an administrator set up (rather than one that registered itself) may also use the server, when its
**Resources** list the address: a deliberate choice, for an AI client you want to pre-register. Access tokens are
sent as `Bearer` tokens; DPoP-bound tokens are not accepted here. The server answers POST requests only (its tools
send no notifications, so it offers no event stream), and a JSON-RPC batch (which protocol version 2025-03-26 allows)
may hold at most 10 requests.

Switching the organization's **MCP server** off, removing the address from the tenant or turning off its
self-registered apps stops the server at once, for clients already signed in too; so does removing the address from an
administrator's application.

To keep MCP off for every organization, start the server with `--disable-mcp` (`server.disable_mcp = true`,
`QUISORA_DISABLE_MCP=true`): every organization's address and metadata answer 404, the console no longer offers the
switch or shows the address, and the API refuses to switch it on. It is off by default, so organizations may switch
their server on. Each client a person approved is listed with the organization's **Self-registered apps**, where
**Revoke** ends its access, and under **Connected apps** on the person's account page.

### Who may use it, and what it can do

- **Managers and up only.** Anyone the tenant lets sign in may approve the client, but the server refuses a token
  whose user is not a manager, administrator or super admin, or whose sign-in did not use a second factor.
- **As the person who signed in.** Every tool is one management API request, made as that person: their role decides
  what they may see and change, exactly as in the console (a manager changes plain users only; only administrators
  read the audit log). The organization is the one the address names.
- **No more than a personal API token.** A change that needs a recent re-authentication in the console (disabling an
  administrator, sending an invitation to another manager or administrator, removing someone's password, authenticator or
  passkey)
  is refused, as it is for an API token. The client cannot make API tokens either.
- **In the audit log.** Every change is recorded under the person's name, with the client (its `client_id`) in the
  event's detail as `app`.
- **No sign-in links.** An invitation is emailed to the user; the link itself is never given to the AI client.

| Tool | What it does | Hints |
| --- | --- | --- |
| `search_users` | Finds enabled users (disabled ones too when asked) by the start of a username, email address or name (or a whole tag), and by role | read-only |
| `get_user` | A user's details: profile, status, groups, sign-in methods | read-only |
| `list_user_sessions` | A user's signed-in browser sessions | read-only |
| `list_groups` | The groups, with their number of members | read-only |
| `list_group_members` | A group's members | read-only |
| `query_audit_log` | The audit log, filtered by name, action, outcome and time (on the organization's audit budget, shared with the console: [RUNNING.md](RUNNING.md#audit-log)) | read-only |
| `create_user` | Creates a user with the default role, optionally emailing an invitation | not destructive |
| `enable_user` | Enables a disabled user | not destructive, idempotent |
| `add_group_member` | Adds a user to a group | not destructive, idempotent |
| `disable_user` | Disables a user, with a reason | destructive, idempotent |
| `remove_group_member` | Removes a user from a group | destructive, idempotent |
| `send_invitation` | Emails a user a new invitation (a new user's set-up, or a lost sign-in reset) | destructive |
| `sign_out_user` | Ends all of a user's sessions | destructive, idempotent |

The hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) tell the client which calls to
confirm with the person first; they are hints only, and the server enforces the rules above whatever the client does.
Changing roles, deleting anything, locking accounts, and the organization's applications, tenants, providers and
settings are left to the console and the management API on purpose.

What the tools return (names, descriptions, audit details) was typed by people, some of whom the person signed in
may not trust: the server tells the client to treat it as data, never as instructions, and no tool can raise
anyone's role.
