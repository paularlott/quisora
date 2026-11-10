# Email templates

Quisora sends five emails: an **invitation**, a **password reset**, an **address verification**, a notice that a
**recovery code was used**, and a **sign-in code** (a second factor by email). Each is rendered from templates: a
**layout**, which holds the header and footer of every email, and each email's **subject**, **HTML body** and
**plain-text body**. Every email goes out with both an HTML and a plain-text part.

Templates are set per organization, in the console (**Emails**, for the organization's administrators and super
admins) or with the management API. Saving them needs a recent re-authentication in the console (**Confirm it is
you**): they carry every link and code the organization sends, so a personal API token cannot change them. The
primary organization's, which every other organization inherits, only a super admin changes; its administrators read
and preview them. A part an organization leaves unset is inherited, one part at a time:

1. the organization's own,
2. else the **primary organization's**, which are so every organization's default,
3. else the built-in ones (the emails as Quisora sends them out of the box).

So the primary organization can give every organization one branded layout, and one organization can change just its
invitation's wording, keeping the rest. A part saved equal to the one it would inherit is not kept as its own: it
follows the inherited one when that changes.

The console has a tab for the layout and one for each email. **Preview**, **Send test**, **Save** and **Use the
default** act on the tab shown (the layout tab previews and tests the layout around the invitation):
saving the invitation saves its subject and bodies and nothing else, and **Use the default**, once confirmed, puts the
inherited parts in that tab's editors (save the tab to keep them). A tab with edits not saved yet is marked, and they stay in its
editors while other tabs are saved.

Email is sent only with `mail.smtp_host` set ([RUNNING.md](RUNNING.md#email)). The templates can be edited and previewed
without it; test emails need it.

## Writing templates

Templates are [Go templates](https://pkg.go.dev/text/template). The HTML parts are rendered with
[html/template](https://pkg.go.dev/html/template), so every field is escaped for where it stands (text, attribute, URL);
the subject and the plain-text parts are not escaped.

The layout places the email's body with `{{template "body" .}}`; it must, in both the HTML and the plain-text layout.

```html
<!doctype html><html lang="en"><body style="margin:0;padding:24px;background:#f4f5f7;font-family:Arial,sans-serif">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:32px">
  {{if .LogoURL}}<img src="{{.LogoURL}}" alt="{{.Site}}" height="40">{{end}}
  <p>Hello {{.Name}},</p>
  {{template "body" .}}
  <p style="font-size:12px;color:#666">{{.Org}}</p>
</div></body></html>
```

The fields are written as below, with their capitals (`{{.Name}}`, not `{{.name}}`).

| Field | |
| --- | --- |
| `.Site` | Who the email is from: the organization's display name, else the server's `ui.site_name`. |
| `.Org` | The organization's display name. |
| `.Name` | The recipient's full name. |
| `.Link` | The link the email carries: the invitation, reset or verification link, or the account page (recovery code used). Not in the sign-in code email. |
| `.Expires` | How long the link or code works, such as `1 hour`. |
| `.Code` | The sign-in code (the sign-in code email only). |
| `.Left` | Recovery codes left (the recovery code email only). |
| `.LogoURL` | The absolute address of the organization's logo, else the server's. Many mail clients show no SVG images: use a PNG logo for email. |
| `.PrimaryColor` | The organization's primary colour (`#rrggbb`), else `#3730a3`. |

A template is checked when it is saved, and refused (with the part at fault, and the line where Go reports one) unless:

- it parses, and every email renders with it, over what it inherits;
- it uses no loops (`{{range}}`) and defines no templates of its own (`{{define}}`, `{{block}}`), and only a layout
  places a template (`{{template "body" .}}`);
- it sets no variables (`{{$x := ...}}`, `{{$x = ...}}`; `$`, the email's fields, may be read) and calls no function
  but the tests `and`, `or`, `not`, `eq`, `ne`, `lt`, `le`, `gt` and `ge` (`{{if not .Name}}`, `{{if eq .Left "1"}}`):
  `print`, `printf` and the rest could build text of any size in memory before the output limit is reached;
- the invitation, reset and verification bodies show `{{.Link}}`, and the sign-in code body shows `{{.Code}}`, in HTML
  and in plain text;
- in the HTML, the link shows only as the whole address of a link (`<a href="{{.Link}}">`, with no `ping`) or as
  text, and the code only as text: never in an image's address, a style, another attribute, a `<style>` or `<script>`,
  and nothing in the email depends on their values. A mail client fetches images and styles by itself, so a link or
  code there would go to whoever wrote the template with every email;
- no subject shows the link or the code: subjects show on lock screens and in notifications;
- each part is at most 64 KB, all of an organization's at most 512 KB, and an email renders to at most 512 KB.

A subject is put on one line (line breaks become spaces) and cut at 200 characters. Where the link and the code show is
checked again each time an email is rendered, with the real link and code (the HTML is rendered a second time with
other values in their place, and only text and that `href` may differ), so a branch the save did not take is held to
it too. Should a stored template fail to render all the same, the email is sent from the built-in templates and the
failure logged (`email template failed`), so a password reset or a sign-in code is never held back by a template.

## Preview and test emails

Each tab has a **Preview** button and a **Send test** button, which asks for the address to send the tab's email to.
Previews and test emails are rendered by the server from the templates as they are in the editors, saved or not, with a made-up recipient (Alex Example) and a link to the real page without a valid token. The HTML
preview is drawn in a sandboxed frame with a policy of its own, so the email's inline styles and remote images show and
nothing in it runs. Nor does it lead anywhere: the email's `<meta http-equiv>` (a refresh) and `<base>` are left out of
the preview, and its links show but do nothing when clicked. A test email goes to the address given, with `[Test]` before its subject, through the
organization's share of the mail queue, and is audited (`org.email_templates.test`, with the address). Each
administrator may send at most 5 test emails a minute and 30 an hour (then 429), so the endpoint cannot be used to relay
mail.

## Limits

Invitations and verification links go to whatever address an administrator enters, with the organization's own
templates. So that the user endpoints cannot be used to relay mail, an organization's administration (its
administrators, managers and service accounts, in the console, the management API or an [MCP](MCP.md) client) has the
server email at most **300** of them an hour: invitations (**Email the invitation**, `POST .../users` with
`"invite": {"email": true}`, `POST .../users/{id}/invite` with `"email": true`), and verification links for an address
given to a user or added to them, or sent again. Past that, the request is refused with 429 and nothing is created
or sent; an invitation link can still be issued without email and shared. Only emails sent count: a request refused (an address the
server turns down, email not set up) or an email that could not be sent spends nothing. A change to an administrator's
own addresses does not count, and each organization has a budget of its own. The count is kept in the cluster's shared counters, as
the test emails' are.

## Replication

An organization's templates are one record in its partition (the `email_templates` table), replicated and backed up
like its other records. Every node reads them when it renders an email, so a change takes effect on each node as soon
as it has replicated there; an email rendered meanwhile on a node that has not seen it yet uses the templates before
it. Deleting an organization deletes its templates (the orphan sweep).

## API

| | |
| --- | --- |
| `GET /api/orgs/{org}/email-templates` | The organization's own parts (`own`), every part as it inherits them (`inherited`), the emails, and whether the server sends email |
| `PUT /api/orgs/{org}/email-templates` | Replace the organization's own parts; audited as `org.email_templates` (which parts were set, changed or removed) |
| `POST /api/orgs/{org}/email-templates/preview` | Render one email from a draft: `{"templates": {...}, "email": "reset"}` |
| `POST /api/orgs/{org}/email-templates/test` | Send one email from a draft: `{"templates": {...}, "email": "reset", "to": "you@example.com"}` |

The organization's administrators and super admins, with a console session or a personal API token; not service
accounts. `PUT` needs a recent re-authentication of the console session (403 with field `reauth` otherwise; a personal
API token cannot), and on the primary organization a super admin. A template set is `{"layout_html": "...", "layout_text": "...", "emails": {"reset": {"subject": "...",
"html": "...", "text": "..."}}}`; the emails are `invite`, `reset`, `verify`, `recovery` and `code`.

```bash
# preview a draft (saving it is done in the console, re-authenticated)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$QUISORA/api/orgs/acme/email-templates/preview" \
  -d '{"templates": {"emails": {"invite": {"subject": "Welcome to {{.Org}}"}}}, "email": "invite"}'
```
