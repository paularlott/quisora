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
- **Abuse limits**: 10 registrations per address and minute, at most 10,000 registrations per organization nobody has used yet
  (apps people use never count), and a registration never used to sign anyone in is removed after a day. A metadata
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
