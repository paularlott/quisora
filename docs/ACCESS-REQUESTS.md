# Access requests

People ask for access to a tenant for a while, someone allowed to approve it does, and the access ends by itself.
Approving gives the person a [timed access entry](TIMED-ACCESS.md) on the tenant, so everything that already happens
when timed access ends happens here too: they are signed out of the tenant's applications, and no token or SSH
certificate outlives it.

Typical uses:

- **Support access to a customer.** The customer's organization signs in your support staff through an
  [organization provider](sign-in/providers.md#users-of-another-organization-guest-accounts), whose own tenant in your
  organization lets in only the people on its access list. Access to that tenant is access to the customer.
- **Your own tools.** An engineer asks for a production tooling tenant for a few hours.

## Setting it up

Administrators set it up for their own organization, on **Groups**:

1. Make (or choose) the group whose members **approve**, for example *CST Approval*.
2. Edit the group whose members may **ask**, for example *CST*. Under **Access requests**, turn on **Members can
   request access**, choose the approver group in **Approved by**, and the lengths they may ask for: 1 hour, 4 hours,
   8 hours, 1 day, 3 days, 1 week, 2 weeks or 1 month (none ticked: all of them).
3. Optionally turn on **Service accounts can approve**, for a bot (below).

From then on, only administrators (and provisioning by an administrator) can change who is in either group: a
manager cannot add themselves, or anyone else, and approve their own way in. An approver group cannot be deleted
while a group names it.

People can ask for any **members-only** tenant of the organization (the ones only the people given access can use).

### What approved access gives

What a person gets on a tenant, beyond being let in, is the tenant's **defaults for new access**: on the tenant's page,
the **Access** card's **Edit defaults** sets roles, tags and authorization details. They are copied into every new
access entry that does not give its own, however it is made (by hand, through the API, or by an approved request), so
changing them later changes no existing access. Approved access always covers all of the tenant's clients.

## Asking

Members of a requester group see **Request access** in their account menu. They choose the tenant (type its name),
**Request approval from** (only when their groups have more than one approver group), how long, and why: a ticket
number and what they need to do. The approvers get an email.

They cannot ask for a tenant they have access to with no end, and only once at a time for each tenant. A request for a
tenant they hold until a time asks to extend it. A request nobody decides within a day lapses.

The same page lists their requests: waiting (they can cancel), active (with the end, and **End now**), and past.

## Approving

Members of an approver group see **Approvals** in their account menu: the requests waiting for them, with who asked,
for which tenant, how long and why. **Approve** or **Deny**, with an optional note that the person sees. Before
deciding, they confirm it is them (their password and second factor, or a passkey), unless they did within the last
5 minutes. Nobody decides their own request, and a guest from another organization never approves.

Approving gives the person access to the tenant from now until the end of the length they asked for:

- no access yet: a new timed entry, for all of the tenant's clients, with the tenant's defaults;
- access until a time: its end moves later (never earlier), and nothing else changes;
- access with no end (given meanwhile by an administrator): nothing changes, and the request says so.

The person gets an email either way. The page also lists the access the approver's groups gave that has not ended,
with **End now**.

## Ending early

The person themselves (**End now** on their Request access page), a member of the approver group, or an administrator
can end the access a request gave. It is removed at once, and the person is signed out of the tenant's applications.
Someone else ending it emails the person.

An administrator who removes the access on the tenant's **Access** card instead (or through the API) takes it away just
as surely, but the request is not told: it keeps showing **Active** on the Request access, Approvals and console pages
until its end time passes. Use **End now** on the request to end access a request gave, so the request, the emails and
the audit log all agree. If the access was removed already, **End now** on the request still marks it ended.

## Emails

Three emails, which each organization can change under **Emails** like the others: **Access request** (to the
approvers), **Access request decided** and **Access ended** (to the person who asked).

## Through the API

| Call | Who |
| --- | --- |
| `GET/POST /api/orgs/{org}/access-requests`, `GET …/options`, `POST …/{id}/cancel`, `POST …/{id}/end` | the person, with a personal API token holding `access_requests` (or `admin`) |
| `GET …/pending`, `POST …/{id}/approve`, `POST …/{id}/deny`, `POST …/{id}/end` | a service account with `access_requests:approve`, for the groups that allow service accounts |
| `GET …/all?state=` | administrators, or a service account with `access` |

A personal API token never approves: it cannot show a recent second factor. The [Scriptling](../scriptling/README.md)
library wraps these calls, and `examples/approve_requests.py` is an approval bot that approves the requests whose
reason starts with a ticket prefix.

## Records and audit

Requests are kept for 90 days after they close; the audit log keeps the history:
`access_request.create`, `.approve`, `.deny`, `.cancel`, `.lapse`, `.end`, and the `tenant.access.add`,
`tenant.access.update` and `tenant.access.remove` an approval or an early end makes (with the request's id and reason).
The console's **Access requests** page lists every request of the organization.
