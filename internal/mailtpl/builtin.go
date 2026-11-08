package mailtpl

import "github.com/paularlott/quisora/internal/model"

// The built-in templates: a minimal, table-free, inline-styled layout that renders in every mail client, and the
// emails' text. They are what an organization sends when neither it nor the primary organization set a part.

const builtinLayoutHTML = `<!doctype html><html lang="en"><body style="margin:0;padding:24px;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2430">
<div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;border:1px solid #e3e5ea">
<p style="margin:0 0 16px;font-size:18px;font-weight:600">{{.Site}}</p>
<p style="margin:0 0 16px;line-height:1.5">Hello {{.Name}},</p>
{{template "body" .}}
</div></body></html>`

const builtinLayoutText = `Hello {{.Name}},

{{template "body" .}}`

// linkHTML is the HTML body of an email that carries a link: intro, the link as a button and written out, outro.
func linkHTML(intro, button, outro string) string {
	return `<p style="margin:0 0 24px;line-height:1.5">` + intro + `</p>
<p style="margin:0 0 24px"><a href="{{.Link}}" style="display:inline-block;background:#3730a3;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600">` + button + `</a></p>
<p style="margin:0 0 8px;line-height:1.5;font-size:14px;color:#4b5263">If the button does not work, copy this link into your browser:</p>
<p style="margin:0 0 24px;font-size:14px;word-break:break-all"><a href="{{.Link}}" style="color:#3730a3">{{.Link}}</a></p>
<p style="margin:0;line-height:1.5;font-size:14px;color:#4b5263">` + outro + `</p>`
}

var builtin = model.EmailTemplateSet{
	LayoutHTML: builtinLayoutHTML,
	LayoutText: builtinLayoutText,
	Emails: map[string]model.EmailTemplate{
		Invite: {
			Subject: "You have been invited to {{.Site}}",
			Text: `You have been invited to join {{.Site}}. Finish setting up your account (set a password or create a passkey, depending on what your organization allows):

{{.Link}}

This link can be used once and expires in {{.Expires}}.
If you were not expecting this invitation you can ignore this message.
`,
			HTML: linkHTML(`You have been invited to join <strong>{{.Site}}</strong>. Finish setting up your account: set a password or create a passkey, depending on what your organization allows.`,
				"Set up your account",
				`This link can be used once and expires in {{.Expires}}. If you were not expecting this invitation you can ignore this message.`),
		},
		Reset: {
			Subject: "Reset your {{.Site}} password",
			Text: `Someone asked to reset the password for your {{.Site}} account. To choose a new password, open:

{{.Link}}

This link can be used once and expires in {{.Expires}}.
If you did not ask for this, ignore this message: your password has not changed.
`,
			HTML: linkHTML(`Someone asked to reset the password for your {{.Site}} account. Choose a new password to continue.`,
				"Reset password",
				`This link can be used once and expires in {{.Expires}}. If you did not ask for this, ignore this message: your password has not changed.`),
		},
		Verify: {
			Subject: "Confirm your email address for {{.Site}}",
			Text: `Please confirm that this is your email address for your {{.Site}} account:

{{.Link}}

This link can be used once and expires in {{.Expires}}.
If you did not request this, you can ignore this message.
`,
			HTML: linkHTML(`Please confirm that this is your email address for your {{.Site}} account.`,
				"Confirm email address",
				`This link can be used once and expires in {{.Expires}}. If you did not request this, you can ignore this message.`),
		},
		Recovery: {
			Subject: "A recovery code was used to sign in to {{.Site}}",
			Text: `One of your recovery codes was just used to sign in to your {{.Site}} account. {{.Left}} of them are left.

If it was you, set up your authenticator app or passkey again, and make new recovery codes once few are left:

{{.Link}}

If it was not you, tell your administrator at once: someone has your password and your recovery codes.
`,
			HTML: linkHTML(`One of your recovery codes was just used to sign in to your {{.Site}} account. <strong>{{.Left}}</strong> of them are left. If it was you, set up your authenticator app or passkey again, and make new recovery codes once few are left.`,
				"Open your account",
				`If it was not you, tell your administrator at once: someone has your password and your recovery codes.`),
		},
		Code: {
			Subject: "Your {{.Site}} sign-in code", // not the code: subjects show in lock-screen previews and notifications
			Text: `Your code to finish signing in to {{.Site}}:

    {{.Code}}

It works once and expires in {{.Expires}}. Never give it to anyone: {{.Site}} never asks for it by phone or by email.
If you are not signing in, someone has your password: change it, and tell your administrator.
`,
			HTML: `<p style="margin:0 0 16px;line-height:1.5">Your code to finish signing in to {{.Site}}:</p>
<p style="margin:0 0 24px;font-size:32px;font-weight:700;letter-spacing:6px;font-family:ui-monospace,Menlo,Consolas,monospace">{{.Code}}</p>
<p style="margin:0 0 8px;line-height:1.5;font-size:14px;color:#4b5263">It works once and expires in {{.Expires}}. Never give it to anyone: {{.Site}} never asks for it by phone or by email.</p>
<p style="margin:0;line-height:1.5;font-size:14px;color:#4b5263">If you are not signing in, someone has your password: change it, and tell your administrator.</p>`,
		},
	},
}

// Builtin returns the built-in templates: every part set.
func Builtin() model.EmailTemplateSet {
	out := builtin
	out.Emails = make(map[string]model.EmailTemplate, len(builtin.Emails))
	for k, v := range builtin.Emails {
		out.Emails[k] = v
	}
	return out
}
