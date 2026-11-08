# Email templates

Quisora sends five emails: an **invitation**, a **password reset**, an **address verification**, a notice that a
**recovery code was used**, and a **sign-in code** (a second factor by email). Each is rendered from templates: a
**layout**, which holds the header and footer of every email, and each email's **subject**, **HTML body** and
**plain-text body**. Every email goes out with both an HTML and a plain-text part.

Templates are set per organization, in the console (**Emails**, for the organization's administrators and super
admins) or with the management API. A part an organization leaves unset is inherited, one part at a time:

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
- the invitation, reset and verification bodies show `{{.Link}}`, and the sign-in code body shows `{{.Code}}`, in HTML
  and in plain text;
- no subject shows the link or the code: subjects show on lock screens and in notifications;
- each part is at most 64 KB, all of an organization's at most 512 KB, and an email renders to at most 512 KB.

A subject is put on one line (line breaks become spaces) and cut at 200 characters. Should a stored template fail to
render all the same, the email is sent from the built-in templates and the failure logged (`email template failed`),
so a password reset or a sign-in code is never held back by a template.

## Preview and test emails

Each tab has a **Preview** button and a **Send test** button, which asks for the address to send the tab's email to.
Previews and test emails are rendered by the server from the templates as they are in the editors, saved or not, with a made-up recipient (Alex Example) and a link to the real page without a valid token. The HTML
preview is drawn in a sandboxed frame with a policy of its own, so the email's inline styles and remote images show and
nothing in it runs. A test email goes to the address given, with `[Test]` before its subject, through the
organization's share of the mail queue, and is audited (`org.email_templates.test`, with the address).

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
accounts. A template set is `{"layout_html": "...", "layout_text": "...", "emails": {"reset": {"subject": "...",
"html": "...", "text": "..."}}}`; the emails are `invite`, `reset`, `verify`, `recovery` and `code`.

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$QUISORA/api/orgs/acme/email-templates" \
  -d '{"emails": {"invite": {"subject": "Welcome to {{.Org}}"}}}'
```
