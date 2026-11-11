# Authorization details: fine-grained access in tokens

Scopes say what kind of thing an access token may do (`orders:read`). Some APIs need more than that: which topics a
user may subscribe to on a pub/sub hub, which accounts a payment may come from. RFC 9396 (Rich Authorization
Requests) puts this in the token as `authorization_details`, a JSON array of objects, each with a `type` that the API
defines, and whatever fields that type has. A pub/sub hub, for example, might define a type
`https://example.com/topics` whose objects list `actions` and `topics`.

In Quisora, **administrators decide the details**, as they decide application roles: they are written into a
tenant's access entries (for the people and groups the entry is for) and onto clients (for the client's own
client_credentials tokens). Applications cannot ask for more than that; they can ask for less.

## Setting up

1. **Register the types on the application.** On the client, under **Authorization details types**, list the types
   it uses, exactly as its APIs name them: a URN (`urn:example:admin`) or a URL (`https://example.com/topics`), at
   most 16, each up to 256 characters without spaces. Its access tokens carry only details of these
   types, and its requests may name only these. An application with no types gets no details at all.
2. **Give the details through access.** In the tenant's **Access** list (a tenant whose **Who can sign in** is set to
   the people on the list), edit a user's or group's entry and fill in **Authorization details**: a JSON array, at
   most 16 objects and 8 KB. They go into the access tokens of the applications the entry covers.
   The console's editor completes the common fields, the application's types (after `"type": `) and the placeholders
   (after `{{`), and marks mistakes as you type: JSON errors and what the server would refuse, and, as warnings,
   details of a type the application does not list, which its tokens would leave out.
3. **For a service that acts as itself** (a publisher, say), fill in **Authorization details of its own tokens** on
   its client (shown when **Client credentials** is ticked). They go into its client_credentials tokens.

The same through the management API:

```bash
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"authorization_details_types":["https://example.com/topics"]}' \
  "$QUISORA/api/orgs/acme/clients/<client id>"

curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"authorization_details":[{"type":"https://example.com/topics",
        "actions":["subscribe"],"topics":[{"match":"https://chat.example.com/users/{{sub}}"}]}]}' \
  "$QUISORA/api/orgs/acme/tenants/<tenant id>/access/<access id>"
```

Send `[]` to remove them.

### Placeholders

Strings in the details may hold `{{sub}}`, `{{org}}` and `{{tenant}}`, filled in when a token is issued: the user's id
(for a client's own tokens, its client ID), and the ids of the organization and the tenant. One entry for a whole group
can then give each member a topic of their own. Any other `{{…}}` is refused when the details are saved. Object keys
are left as they are, and so are single-brace URI template expressions such as `{id}`.

### Which API a detail is for

A detail with the common field `locations` (an array of API addresses) goes only into tokens whose audience includes
one of them: ask for the token with `resource=<that address>` (RFC 8707). A detail without `locations` goes into every
token of the application.

### Several entries

A user's own entry and those of their groups add up: the token carries each different detail once, the user's own
first. Details are taken from live entries that cover the application, as roles are; a tenant open to everyone in the
organization has no access entries in use, so its applications get no details from access.

## In the tokens

The access token carries the details as the `authorization_details` claim, filtered to the token's application and
audience. The token response repeats them (RFC 9396 §7), and introspection reports them as the token holds them. ID
tokens and userinfo never carry them.

```json
{
  "sub": "034q53I8Z6tNZqoaxLu6DR",
  "aud": ["c_chat", "https://hub.example.com/"],
  "authorization_details": [
    {"type": "https://example.com/topics", "actions": ["subscribe"],
     "topics": [{"match": "https://chat.example.com/users/034q53I8Z6tNZqoaxLu6DR"}]}
  ]
}
```

## Asking for less

Any request may send `authorization_details` to narrow the token to some types: the authorization request (or a
pushed one), the device authorization request, and token requests (code exchange, refresh, token exchange, client
credentials). Quisora reads the `type` of each object; the token then carries only the granted details of those types.
The types named at authorization are kept with the refresh grant: later token requests may narrow them further, never
widen them. A [token exchange](token-exchange.md) is bound by the subject token in the same way: the new token carries
only types the subject token carries (all of them when the exchange names none). When a request asks and nothing is
granted, the token response says `"authorization_details": []`.

A request is refused with `invalid_authorization_details` when the parameter is not a JSON array of objects each with
a `type`, when a common field has the wrong shape, when it names a type the client is not registered for, or when a
token request names a type its authorization did not (for a token exchange, one the subject token does not carry).

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=refresh_token -d "refresh_token=$REFRESH" \
  --data-urlencode 'authorization_details=[{"type":"https://example.com/topics"}]' \
  "$ISSUER/oauth/token" | jq .authorization_details
```

Discovery does not list `authorization_details_types_supported`: the types are each application's, not the server's.
