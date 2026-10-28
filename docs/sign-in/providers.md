# Upstream sign-in providers

An organization can let its users sign in with an account they already have elsewhere: the company's own single
sign-on, Google, Microsoft Entra ID, GitHub, GitLab, Auth0, or any OpenID Connect provider. Each appears on the
sign-in page as **Continue with …**. Quisora stays the identity provider of your applications: the upstream sign-in
signs the user in to Quisora, and Quisora signs them in to the application, with its own rules (tenants, access lists,
second factors) on top.

## Adding a provider

Organization → **Providers** → **New provider**. Providers belong to one organization; its tenants choose
which of them their applications offer.

| Type | What it needs |
| --- | --- |
| **OpenID Connect** | The **Issuer URL** (https); Quisora reads its discovery document. |
| **Google** | Nothing more: the issuer is `https://accounts.google.com`. |
| **Microsoft (Entra ID)** | **Directory (tenant)**: your tenant's ID, or `organizations` with a list of **Allowed tenants** (IDs). Personal Microsoft accounts are not supported. Add the optional claim `xms_edov` to the app registration's ID token, or Quisora cannot tell whether an address is verified. |
| **GitHub** | Nothing more (an OAuth app on github.com). |
| **GitLab** | **GitLab address**: empty for gitlab.com, or your self-managed server. |
| **Auth0** | **Auth0 domain**, such as `acme.eu.auth0.com` (or your custom domain). |

Every type needs a **Client ID** and **Client secret** from the provider. The dialog shows the provider's **Callback
URL** from the start: register it at the provider as the redirect URI (the dialog says where for each type), then
paste the client ID and secret back. It is `https://id.example.com/o/<org id>/login/callback/<provider id>`: the provider's organization's address
space, and each provider has its own, so a response meant for one provider cannot be passed off as another's.

The other settings:

| Setting | |
| --- | --- |
| **Button label** | What the sign-in page shows after "Continue with". Defaults to the type's name. |
| **Scopes** | `openid profile email` by default (GitHub: `read:user user:email`). Add `offline_access` for [leaver detection](#leavers). |
| **Allowed email domains** | Only people with a verified address at one of these domains can use it. Empty: anyone. |
| **Link existing users by verified email** | On by default, except for an [organization provider](#users-of-another-organization-guest-accounts), where it is off. See [who signs in](#who-signs-in-as-whom). |
| **Create accounts automatically** | Off by default. |
| **Sign-in through this provider counts as a second factor** | Off by default; super admins only. See [second factors](#second-factors). |
| **Provider is enabled** | Off: its button goes, and nobody can sign in through it. |

The client secret is stored sealed with the master key and never shown again; leave it blank when editing to keep it.
Pointing a provider at another issuer, Microsoft tenant or type needs the new provider's secret, and unlinks everyone
who had signed in through it (their links were with the old provider).

Through the management API (an API token with the `admin` scope):

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"type":"oidc","name":"Company SSO","issuer":"https://login.example.com",
       "client_id":"quisora","client_secret":"…","scopes":["openid","profile","email","offline_access"],
       "allowed_domains":["example.com"],"link_by_email":true,"auto_provision":false,"enabled":true}' \
  "$QUISORA/api/orgs/acme/providers"
```

The answer includes `callback_url`. To register the callback URL before the provider has issued the client ID and
secret, choose the provider's ID yourself: send `"id"` (a lower-case UUID) when creating it, as the console does.
`GET`, `PATCH` and `DELETE /api/orgs/acme/providers/{id}` read, change and remove one.

## Which applications offer it

Each tenant's **Sign-in rules** choose its providers: **All of the organization's providers** (the default, which
includes ones added later) or a chosen list. Only enabled providers count, whatever is ticked. A sign-in through a
provider the application's tenant does not offer is refused, even with a session from elsewhere.

## Who signs in as whom

The first time someone signs in through a provider, Quisora decides which account they are:

1. **Already linked**: the provider's user id was linked to an account before. The email address no longer matters:
   it can change at the provider without breaking the link.
2. **Link by email** (when on): the provider says the address is verified, and it is the verified address (primary or
   linked) of exactly one user in the organization. The two are linked from then on (`identity.link.email`). Managers
   and administrators are never linked this way (`identity.link.refused`): they sign in the usual way and connect the
   provider themselves on their account page. A user who is promoted to manager or administrator (or super admin)
   loses every link they did not make themselves there: those made by email, by an account the provider created at
   first sign-in (including a guest of an [organization provider](#users-of-another-organization-guest-accounts)),
   or by an administrator. The provider's side controls such a link, and the account may have no second factor yet,
   so whoever held the provider's account could enrol their own. Each removal is audited as `identity.unlink`. The
   user connects the provider again on their account page, signed in, if they want it.
3. **Create accounts automatically** (when on): a new user with the provider's verified address and name, the `user`
   role (`user.provision`). Refused if a user already has that address.
4. Otherwise the sign-in is refused: *the account is not linked*.

**Allowed email domains** apply at every step, also to accounts already linked.

Users can connect and disconnect providers themselves: **Your account → Sign-in providers** (after confirming it is
them). Disconnecting is refused when it is their only way to sign in. Administrators see a user's linked providers on
their page and can disconnect them (`GET`/`DELETE /api/orgs/acme/users/<id>/providers`).

## Second factors

A sign-in through a provider is a first factor, like a password: Quisora never trusts what the provider says about its
own second factors. Where a second factor is required, or for managers and administrators, Quisora asks for the
user's own (authenticator app, passkey, or a code by email) after the provider, as after a password. The session's
`amr` is `["fed", …]`.

**Sign-in through this provider counts as a second factor** changes that for plain users: Quisora asks them for no
second factor after this provider, even where one is required, and the session's `amr` is `["fed","mfa"]`. Turn it on
only when the provider itself makes everyone use a second factor (your company SSO enforcing MFA). Managers and
administrators always give their own. Only super admins can change it.

## Leavers

When someone leaves, their account at the provider is disabled, but a Quisora session they started through it would
otherwise carry on. With `offline_access` in the provider's scopes, Quisora keeps the refresh token the provider gives
at sign-in (sealed) and replays it every `session.upstream_check_minutes` (60 by default; 0 turns it off) while the user
has a session that came through that provider. If the provider refuses it (`invalid_grant`), Quisora ends all of that
user's sessions and refresh grants, and applications are told (`identity.refresh.refused`). The account is not
disabled: lock it out or end-date it in Quisora for that. GitHub gives no refresh tokens, so this does not apply to it.

## Network

Quisora calls the provider's discovery, token and key endpoints from the server, over https only, without following
redirects. Addresses on private networks (and loopback) are refused unless allowed: list the provider's network in
`server.allowed_networks` (`allowed_networks = ["172.16.0.0/12"]`, or the provider's address alone), or, in a home
lab, set `server.allow_private_networks` to allow every private address. A provider whose certificate comes from an internal CA needs that CA in
`server.extra_ca_file`.

## Audit

| Event | When |
| --- | --- |
| `provider.create`, `provider.update`, `provider.delete` | Providers changed (a new secret shows as `client_secret: replaced`, never the value) |
| `identity.link.email` | An account was linked by its verified email |
| `identity.link.refused` | A manager or administrator was not linked by email |
| `user.provision` | An account was created automatically |
| `identity.unlink` | Links removed because the provider changed, or because the user was promoted to a privileged role (`reason`) |
| `identity.refresh.refused` | A leaver: the provider refused the refresh token, sessions ended |
| `account.provider.connect`, `account.provider.connect_refused`, `account.provider.disconnect` | A user connected or disconnected a provider |
| `user.provider.disconnect` | An administrator disconnected one |
| `login.failure` with reason `upstream …` | A provider sign-in was refused (`not_linked`, `unverified`, `domain`, `exists`, `disabled`…) |

## Users of another organization (guest accounts)

Organizations are separate: a user belongs to one, and signs in to its pages and applications there. To let the people
of one organization (typically the primary one, the server's own) use another organization's applications, set up an
**Organization** provider in the second one, as Microsoft Entra calls it a guest (B2B) account: the person keeps signing
in where they belong, and the other organization adds them, as a guest, to the people it lets in. The sign-in page of
the second organization shows **Continue with &lt;the first organization's name&gt;**.

Only a **super admin** can create, change or delete one: it makes an application in the other organization.

### Setting it up

In the organization that receives the guests (organization B): **Providers** → **New provider** → type **Another
organization**, and choose the organization whose users sign in (S) from the list. Nothing else is needed:

- The provider's issuer is S's own (`https://id.example.com/o/<S id>`). Its requests to S (discovery, token, keys) are
  answered by the server itself, in memory: they work whatever the server can reach on its own public address, and never
  leave the process.
- Quisora makes the client the provider signs in with, in S: a confidential application named
  `Sign-in to <B's name>` in S's default tenant, whose only redirect URI is the provider's callback address, with the
  scopes `openid profile email`. It is first-party, so the people signing in are not asked for consent, and its secret is
  sealed into the provider; nobody sees it. It is listed with S's applications, and made and removed with the provider:
  edit the provider, not the application. S's own rules for that tenant (who may sign in, second factors) apply to the
  sign-in at S, as for any application of S.
- **Button label** defaults to S's display name. Scopes, client ID and secret are not entered.
- **Link existing users by verified email** is **off** (unlike other providers), **Create accounts automatically** is
  off, and **counts as a second factor** is off. Allowed email domains work as for any provider. Linking by email is off
  because S's managers, administrators and SCIM clients can set a user's email address and mark it verified: with it on,
  any of them could create a user in S with the address of one of B's users and sign in to B as them. Turning it on is a
  super admin's decision to trust S's staff with the addresses they assert (see below).

Changing the organization moves the client (a new one in the new organization, the old one removed) and unlinks everyone
who had signed in through the provider. Deleting the provider deletes its client. These are two writes in two
organizations, never one transaction, so they are ordered to leave at most an unused client: the client is made before
the provider is written, and removed after the provider is deleted or no longer uses it. When a removal fails (the
store was unavailable), Quisora logs a warning and the housekeeping orphan sweep removes the client within the day; a
client made for a provider whose creation then failed, or never completed, is removed the same way.

### Adding a guest

There are two ways to let a person of S in to B. Choose one when you set the provider up; they can be combined.

**Create accounts automatically** (recommended): every user of S who signs in becomes a guest, a plain `user` in B with
their S name and verified address, made on their first sign-in. Combine it with **Allowed email domains** and the
tenants' access lists (**Who can sign in**) to keep that bounded. An address that one of B's users already has is
refused (`exists`): nobody takes over an existing account this way. As everywhere, managers and administrators of B are
not linked by email: they connect the provider on their own account page. A guest who is promoted to manager or
administrator of B loses the link the provider created, for the same reason, and connects the provider again on their
account page if they want it.

**Add each person by hand**: an administrator of B adds them (**Users** → **New user**, or invite them) with the **same
email address** the person has in S, verified (an invitation they accept verifies it, or an administrator marks it
verified), and a super admin switches **Link existing users by verified email** on for the provider. The person then
chooses **Continue with …** on B's sign-in page, signs in at S if they are not yet (with S's password, passkey or
second factor) and returns to B. Quisora links the two accounts by that verified address, as for any provider
([who signs in as whom](#who-signs-in-as-whom)): the link is S's user id, so changing the address later does not break
it. Someone S knows but B has not added is refused (`not_linked`). Linking by email is off by default for an
organization provider because it trusts S to say whose address is whose: S's managers, administrators and SCIM clients
can mark any address verified, so each of them could then sign in to B as any of B's users (below administrator).
Switch it on only for an organization whose staff you trust that far; with it off, an existing user of B is never
matched to a guest by address.

### Second factors and leavers

A guest signs in to B with a first factor only (`amr` `["fed"]`), as with any provider: B's own rules ask for a second
factor where one is required, and the person gives the second factor they have in B. The provider is *not* trusted to
have asked for one by default. A super admin can turn on **counts as a second factor** when S's rules require one of
everybody who signs in to that application (S's default tenant); then B asks plain users for none after it.

The provider asks for no refresh token, so there is no leaver detection: a person disabled or removed in S keeps the
B session they already have until it ends (its idle and absolute limits). Disable or remove their guest account in B
too (ending its sessions), or use [emergency sign-out](../emergency-sign-out.md).

Through the management API, as a super admin:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"type":"organization","source_org":"primary"}' "$QUISORA/api/orgs/acme/providers"
```

`source_org` is the other organization's name or id. `PATCH` the provider's `source_org` to move it; `client_id`,
`client_secret`, `issuer` and `scopes` are ignored for this type.

Audit: `provider.create`/`update`/`delete` in B, and `client.create`/`client.delete` in S for the client made and removed
with it.
