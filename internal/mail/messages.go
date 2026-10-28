package mail

import (
	"bytes"
	"context"
	"errors"
	htmltemplate "html/template"
	"strconv"
	texttemplate "text/template"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// SetService enables the emails that carry links (invitation, reset, verification): the links are the service's
// durable, hashed, single-use link tokens, so they work on any node and survive a restart.
func (m *Mailer) SetService(svc *service.Service) { m.Svc = svc }

var errNoService = errors.New("mail: link tokens are not configured")

// SendInviteLink emails an invitation URL that was issued already (service.CreateInvite): "generate a new invite and
// email it" is CreateInvite as the acting admin followed by this.
func (m *Mailer) SendInviteLink(ctx context.Context, u *model.User, org *model.Org, link string, expires time.Time) error {
	if u.Email == "" {
		return errors.New("mail: user has no email address")
	}
	// The address the invitation is bound to, not the one on the caller's copy of the user, which may be older (an
	// address corrected since): a link is only ever mailed to the address it opens the account for.
	to := u.Email
	if m.Svc != nil {
		var err error
		if to, err = m.Svc.LinkAddress(ctx, link); err != nil {
			return err
		}
	}
	if err := m.renderTo(ctx, to, u, org, inviteTpl, link, time.Until(expires)); err != nil {
		return err
	}
	if m.Svc != nil {
		// Accepting an invitation that went to the address on file proves the address.
		if err := m.Svc.MarkLinkSent(ctx, link, to); err != nil {
			m.Log.Warn("mail: invitation not marked as emailed", "error", err)
		}
	}
	return nil
}

// SendReset emails u a password reset link (valid 1 hour).
func (m *Mailer) SendReset(ctx context.Context, u *model.User, org *model.Org) error {
	return m.sendLink(ctx, service.LinkReset, service.ResetTTL, u, org, resetTpl)
}

// SendVerify emails u a link (valid 24 hours) that confirms the address on file.
func (m *Mailer) SendVerify(ctx context.Context, u *model.User, org *model.Org) error {
	return m.sendLink(ctx, service.LinkVerify, service.VerifyTTL, u, org, verifyTpl)
}

type tplData struct {
	Site    string
	Name    string
	Org     string
	Link    string
	Expires string
	Left    string // recovery codes left (recoveryTpl)
	Code    string // a sign-in code (codeTpl)
}

// linkPaths are the pages the mailed links open, in the address space of the organization of the user they are for.
var linkPaths = map[string]string{service.LinkInvite: "/invite", service.LinkReset: "/reset", service.LinkVerify: "/verify-email"}

func (m *Mailer) sendLink(ctx context.Context, purpose string, ttl time.Duration, u *model.User, org *model.Org, t *tpl) error {
	if m.Svc == nil {
		return errNoService
	}
	if u.Email == "" {
		return errors.New("mail: user has no email address")
	}
	tok, l, err := m.Svc.IssueLink(ctx, u, purpose, u.Email, ttl)
	if err != nil {
		return err
	}
	// To the address the link was issued for (the account's as it is now), not the caller's copy of the user's.
	return m.renderTo(ctx, l.Email, u, org, t, m.Svc.LinkURL(u.OrgID, linkPaths[purpose], tok), ttl)
}

// SendVerifyAddress emails a verification link to one address of u (a linked address, or the primary): the link is
// bound to that address, so it verifies nothing else.
func (m *Mailer) SendVerifyAddress(ctx context.Context, u *model.User, org *model.Org, address string) error {
	if m.Svc == nil {
		return errNoService
	}
	tok, err := m.Svc.IssueEmailLink(ctx, u, address)
	if err != nil {
		return err
	}
	return m.renderTo(ctx, address, u, org, verifyTpl, m.Svc.LinkURL(u.OrgID, linkPaths[service.LinkVerify], tok), service.VerifyTTL)
}

// SendRecoveryUsed tells u that one of their recovery codes was used to sign in, and how many are left: someone who
// got hold of the codes is noticed at their first use.
func (m *Mailer) SendRecoveryUsed(ctx context.Context, u *model.User, org *model.Org, left int) error {
	d := tplData{Site: m.Cfg.UI.SiteName, Name: u.FullName(), Org: org.DisplayName, Link: m.Cfg.Server.PublicURL + web.OrgPath(u.OrgID, "/account"), Left: strconv.Itoa(left)}
	msg, err := recoveryTpl.render(d)
	if err != nil {
		return err
	}
	msg.To, msg.OrgID = u.Email, u.OrgID
	return m.Send(ctx, msg)
}

// SendSignInCode emails u the one-time code that finishes a sign-in as its second factor, valid for ttl.
func (m *Mailer) SendSignInCode(ctx context.Context, u *model.User, org *model.Org, code string, ttl time.Duration) error {
	d := tplData{Site: m.Cfg.UI.SiteName, Name: u.FullName(), Org: org.DisplayName, Code: code, Expires: humanTTL(ttl)}
	msg, err := codeTpl.render(d)
	if err != nil {
		return err
	}
	msg.To, msg.OrgID, msg.Expires = u.Email, u.OrgID, time.Now().Add(ttl)
	return m.Send(ctx, msg)
}

func (m *Mailer) renderTo(ctx context.Context, to string, u *model.User, org *model.Org, t *tpl, link string, ttl time.Duration) error {
	d := tplData{Site: m.Cfg.UI.SiteName, Name: u.FullName(), Org: org.DisplayName, Link: link, Expires: humanTTL(ttl)}
	msg, err := t.render(d)
	if err != nil {
		return err
	}
	msg.To, msg.OrgID, msg.Expires = to, u.OrgID, time.Now().Add(ttl)
	return m.Send(ctx, msg)
}

func humanTTL(d time.Duration) string {
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return strconv.Itoa(n) + " " + unit + "s"
	}
	switch {
	case d >= 47*time.Hour:
		return plural(int((d+12*time.Hour)/(24*time.Hour)), "day")
	case d >= 55*time.Minute:
		return plural(int((d+30*time.Minute)/time.Hour), "hour")
	case d >= time.Minute:
		return plural(int((d+30*time.Second)/time.Minute), "minute")
	}
	return "1 minute"
}

type tpl struct {
	subject string
	text    *texttemplate.Template
	html    *htmltemplate.Template
}

func (t *tpl) render(d tplData) (Message, error) {
	var sub, txt, htm bytes.Buffer
	if err := texttemplate.Must(texttemplate.New("s").Parse(t.subject)).Execute(&sub, d); err != nil {
		return Message{}, err
	}
	if err := t.text.Execute(&txt, d); err != nil {
		return Message{}, err
	}
	if err := t.html.Execute(&htm, d); err != nil {
		return Message{}, err
	}
	return Message{Subject: sub.String(), Text: txt.String(), HTML: htm.String()}, nil
}

func mk(subject, text, intro, button, outro string) *tpl {
	return &tpl{
		subject: subject,
		text:    texttemplate.Must(texttemplate.New("t").Parse(text)),
		html:    htmltemplate.Must(htmltemplate.New("h").Parse(htmlShell(intro, button, outro))),
	}
}

// htmlShell is a minimal, table-free, inline-styled layout that renders in every mail client.
func htmlShell(intro, button, outro string) string {
	return `<!doctype html><html lang="en"><body style="margin:0;padding:24px;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2430">
<div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;border:1px solid #e3e5ea">
<p style="margin:0 0 16px;font-size:18px;font-weight:600">{{.Site}}</p>
<p style="margin:0 0 16px;line-height:1.5">Hello {{.Name}},</p>
<p style="margin:0 0 24px;line-height:1.5">` + intro + `</p>
<p style="margin:0 0 24px"><a href="{{.Link}}" style="display:inline-block;background:#3730a3;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600">` + button + `</a></p>
<p style="margin:0 0 8px;line-height:1.5;font-size:14px;color:#4b5263">If the button does not work, copy this link into your browser:</p>
<p style="margin:0 0 24px;font-size:14px;word-break:break-all"><a href="{{.Link}}" style="color:#3730a3">{{.Link}}</a></p>
<p style="margin:0;line-height:1.5;font-size:14px;color:#4b5263">` + outro + `</p>
</div></body></html>`
}

// codeTpl is the sign-in code: no link (a code is typed where the sign-in asked for it), the code itself large.
var codeTpl = &tpl{
	subject: "Your {{.Site}} sign-in code", // not the code: subjects show in lock-screen previews and notifications
	text: texttemplate.Must(texttemplate.New("t").Parse(`Hello {{.Name}},

Your code to finish signing in to {{.Site}}:

    {{.Code}}

It works once and expires in {{.Expires}}. Never give it to anyone: {{.Site}} never asks for it by phone or by email.
If you are not signing in, someone has your password: change it, and tell your administrator.
`)),
	html: htmltemplate.Must(htmltemplate.New("h").Parse(`<!doctype html><html lang="en"><body style="margin:0;padding:24px;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2430">
<div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;border:1px solid #e3e5ea">
<p style="margin:0 0 16px;font-size:18px;font-weight:600">{{.Site}}</p>
<p style="margin:0 0 16px;line-height:1.5">Hello {{.Name}},</p>
<p style="margin:0 0 16px;line-height:1.5">Your code to finish signing in to {{.Site}}:</p>
<p style="margin:0 0 24px;font-size:32px;font-weight:700;letter-spacing:6px;font-family:ui-monospace,Menlo,Consolas,monospace">{{.Code}}</p>
<p style="margin:0 0 8px;line-height:1.5;font-size:14px;color:#4b5263">It works once and expires in {{.Expires}}. Never give it to anyone: {{.Site}} never asks for it by phone or by email.</p>
<p style="margin:0;line-height:1.5;font-size:14px;color:#4b5263">If you are not signing in, someone has your password: change it, and tell your administrator.</p>
</div></body></html>`)),
}

var (
	inviteTpl = mk("You have been invited to {{.Site}}",
		`Hello {{.Name}},

You have been invited to join {{.Org}} on {{.Site}}. Finish setting up your account (set a password or create a passkey, depending on what your organization allows):

{{.Link}}

This link can be used once and expires in {{.Expires}}.
If you were not expecting this invitation you can ignore this message.
`,
		`You have been invited to join <strong>{{.Org}}</strong> on {{.Site}}. Finish setting up your account: set a password or create a passkey, depending on what your organization allows.`,
		"Set up your account",
		`This link can be used once and expires in {{.Expires}}. If you were not expecting this invitation you can ignore this message.`)

	resetTpl = mk("Reset your {{.Site}} password",
		`Hello {{.Name}},

Someone asked to reset the password for your {{.Site}} account. To choose a new password, open:

{{.Link}}

This link can be used once and expires in {{.Expires}}.
If you did not ask for this, ignore this message: your password has not changed.
`,
		`Someone asked to reset the password for your {{.Site}} account. Choose a new password to continue.`,
		"Reset password",
		`This link can be used once and expires in {{.Expires}}. If you did not ask for this, ignore this message: your password has not changed.`)

	recoveryTpl = mk("A recovery code was used to sign in to {{.Site}}",
		`Hello {{.Name}},

One of your recovery codes was just used to sign in to your {{.Site}} account. {{.Left}} of them are left.

If it was you, set up your authenticator app or passkey again, and make new recovery codes once few are left:

{{.Link}}

If it was not you, tell your administrator at once: someone has your password and your recovery codes.
`,
		`One of your recovery codes was just used to sign in to your {{.Site}} account. <strong>{{.Left}}</strong> of them are left. If it was you, set up your authenticator app or passkey again, and make new recovery codes once few are left.`,
		"Open your account",
		`If it was not you, tell your administrator at once: someone has your password and your recovery codes.`)

	verifyTpl = mk("Confirm your email address for {{.Site}}",
		`Hello {{.Name}},

Please confirm that this is your email address for your {{.Site}} account:

{{.Link}}

This link can be used once and expires in {{.Expires}}.
If you did not request this, you can ignore this message.
`,
		`Please confirm that this is your email address for your {{.Site}} account.`,
		"Confirm email address",
		`This link can be used once and expires in {{.Expires}}. If you did not request this, you can ignore this message.`)
)
