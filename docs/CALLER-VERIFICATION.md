# Caller verification

A support agent confirms that the person on a call is the account holder they say they are. The agent starts a
verification and reads its six-digit code to the caller; the caller enters it in their own account, sees who is asking
and why, and confirms it is them with a passkey or their second factor. The agent's screen then says so.

No passwords or security questions are asked over the phone, and nothing is sent to the caller: they go to their own
account themselves, on the address they already know, so nobody can send them a look-alike page. Entering the code also
shows the caller who they are really talking to: the agent's name and email, and the organization.

## Setting it up

A super administrator sets it up, in each organization's settings (**Organizations** → edit → **Caller
verification**):

- **Agents can verify callers**, with the **Agent groups** whose members verify callers (the support team). Their
  members see **Verify a caller** at the top of their account menu, and verify the organization's own people. Only
  administrators can change who is in an agent group while the switch is on.
- **Let the primary organization's agents verify this organization's people** (every organization but the primary
  one): the operator's support team, in the primary organization, can then verify this organization's people too. Only
  the primary organization's agents ever verify people of another organization.

People of an organization whose users can be verified (its own agents verify callers, or the primary organization's
may) see **Verify a call** in their account menu.

## Verifying a caller

On **Verify a caller**, the agent:

1. chooses the **Organization**, for an agent of the primary organization while another organization lets it verify its
   people (their own to start with); otherwise there is nothing to choose, and the form starts with the person;
2. finds the **Person** by name, family name, username or email (how each starts), and adds **Why** if they like: the
   caller sees it, for example the ticket being discussed;
3. selects **Start verification**, and reads the code to the caller, telling them to open **Verify a call** in their
   account menu (the page shows its address too).

The code works for 5 minutes, for that person only. The page shows the answer as it comes: **Confirmed** (with a
passkey or second factor, or, for an account that has neither, with the password alone, which the page points out),
**Not them**, **Ran out** or **Cancelled**. The agent's verifications of the day are listed below it, the waiting
ones with **Open** and **Cancel**.

The server keeps only a hash of the code; the agent's browser keeps the code until it runs out, so reloading the page
shows the waiting verification again with its code. In another browser it shows how the verification stands, without
the code: cancel it and start again if the caller does not have it.

## Verifying a call

On **Verify a call**, the caller first sees who is verifying them right now (the agent's name, organization and why,
never the code), as soon as the agent starts, and only then a box for the code: if someone on a call asks for a code
and nobody shows there, they did not start a verification. The caller then enters the six digits. They then see who is asking (the agent's name and email), from
which organization, and why, and a warning: confirm only if they are on a call with that person right now. **Yes,
it's me** asks them to confirm it is them first (their passkey or second factor, unless they did within the last 5
minutes); **Not me** tells the agent so.

Wrong codes are limited to 5 in 10 minutes for each account. The page also lists **Who verified you**: everyone who
asked, from where, when, and what came of it, so a person can spot a verification they did not expect.

Both pages follow each other live: each person's browser keeps a stream open (Server-Sent Events, at
`/o/<org>/api-internal/account/events`) that says only that a verification about them changed, never what, and the page
then asks again through the account API. The customer's page shows a verification the moment the agent starts it, and
the agent's page the answer the moment it is given. The pages also look again every 10 to 15 seconds, for a browser or
proxy that does not keep the stream open, and for servers sharing a database without change notices.

## What it proves, and what it does not

A confirmed verification means the person on the call was signed in to that account and confirmed it is them with what
the account signs in with. It says nothing about who the account holder is in the world beyond what the account says.

A code read over the phone can be relayed: someone who has the agent on one line and the account holder on another
could pass the code on. The caller is shown who is asking and warned to confirm only a call they are on; the agent
should still treat a verification as one piece of evidence, not the only one, for anything that cannot be undone.

## Records and audit

Verifications are kept for 30 days; the audit log keeps the history, in both organizations (the agent's and the
customer's): `call_verify.start`, `.confirm` (with `detail.second_factor`), `.deny` and `.cancel`. Agents start at most
60 verifications an hour.
