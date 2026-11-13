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
  credentials in the URI.
- **Consent is always asked**, with a warning that the app is not verified by the organization and where it sends
  the result (a host, or the app scheme for a desktop app): its name is only what it calls itself.
- **Registration is open only where it can be used**: an organization with no tenant that allows self-registered apps
  for a resource it owns answers `/oauth/register` with `403 access_denied`.
- **Abuse limits**: 10 registration requests per address and minute, 100 per address and organization a day, 60
  registrations made per organization and minute from every address together (refused requests do not count toward
  it, so bad requests from a few addresses cannot block others) (`429 slow_down` past any of them), at most 10,000 registrations
  per organization nobody has used yet (apps people use never count; at the cap, a new registration removes one of
  the unused ones picked at random, so a flood cannot stop others registering), and a registration never used to sign
  anyone in is removed after a day. An app nobody has signed in with yet is given no
  CORS origin (its https redirect URIs count once it has been used), so a browser app's first request through
  pushed authorization (`/oauth/par`, which it calls from script) is refused by the browser until its first
  authorization: such an app starts its first sign-in with a plain authorization request (a redirect, which needs no
  CORS), and may use PAR from then on. A metadata
  document is read only for a resource whose tenant accepts self-registered apps, at most 20 new documents per address
  and minute and once a minute per URL, with the same SSRF guard as JWKS (no private or loopback addresses unless
  listed in `server.allowed_networks` or `server.allow_private_networks` is set), at most 5 KB; the app is stored only once a user lets it sign in.

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
| `query_audit_log` | The audit log, filtered by name, action, outcome and time | read-only |
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
