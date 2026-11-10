package admin

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/mail"

	"github.com/paularlott/quisora/internal/mailtpl"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// emailTemplatesView is GET /api/orgs/{org}/email-templates: the organization's own templates and what it inherits
// (service.EmailTemplateView), the emails there are, and whether this server sends email (a test email needs it).
type emailTemplatesView struct {
	*service.EmailTemplateView
	Emails      []mailtpl.Email `json:"emails"`
	MailEnabled bool            `json:"mail_enabled"`
}

func (m *Module) emailTemplatesView(v *service.EmailTemplateView) emailTemplatesView {
	_, noop := m.Mailer.(noopMailer)
	return emailTemplatesView{EmailTemplateView: v, Emails: mailtpl.Emails, MailEnabled: !noop}
}

// getEmailTemplates returns the organization's email templates (its admins; never a service account).
func (m *Module) getEmailTemplates(w http.ResponseWriter, r *http.Request) {
	o, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	v, err := m.s.Svc.EmailTemplates(r.Context(), a, o.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.emailTemplatesView(v))
}

// putEmailTemplates replaces the organization's own email templates (service.UpdateEmailTemplates), after a recent
// re-authentication (stepUp): the templates carry every invitation, reset link and sign-in code the organization
// sends, so a stolen session or API token must not be enough to change where those go.
func (m *Module) putEmailTemplates(w http.ResponseWriter, r *http.Request) {
	o, a, found := m.orgFor(w, r)
	if !found || !m.stepUp(w, r) {
		return
	}
	var in model.EmailTemplateSet
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	v, err := m.s.Svc.UpdateEmailTemplates(r.Context(), a, o.ID, in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, m.emailTemplatesView(v))
}

// emailDraft is the body of the preview and the test email: the templates as they are being edited (not saved), the
// email to render, and for a test email the address to send it to.
type emailDraft struct {
	Templates model.EmailTemplateSet `json:"templates"`
	Email     string                 `json:"email"`
	To        string                 `json:"to"`
}

// renderDraft decodes a draft and renders its email with made-up values (mailtpl.Sample) as the organization would
// send it; on failure it has written the error.
func (m *Module) renderDraft(w http.ResponseWriter, r *http.Request) (*model.Org, *service.Actor, *emailDraft, mailtpl.Message, bool) {
	o, a, found := m.orgFor(w, r)
	if !found {
		return nil, nil, nil, mailtpl.Message{}, false
	}
	var in emailDraft
	if !web.DecodeJSON(w, r, &in) {
		return nil, nil, nil, mailtpl.Message{}, false
	}
	set, err := m.s.Svc.PreviewEmailTemplates(r.Context(), a, o.ID, in.Templates) // who may, first
	if err != nil {
		web.WriteError(w, err)
		return nil, nil, nil, mailtpl.Message{}, false
	}
	path, known := previewPaths[in.Email]
	if !known {
		web.WriteError(w, service.Invalid("email", "choose one of the emails: invite, reset, verify, recovery or code"))
		return nil, nil, nil, mailtpl.Message{}, false
	}
	d := web.MailBrand(m.s.Cfg, o)
	if path != "" {
		d.Link = m.s.Cfg.Server.PublicURL + web.OrgPath(o.ID, path)
	}
	msg, err := mailtpl.Render(set, in.Email, mailtpl.Sample(in.Email, d))
	if err != nil { // checked by PreviewEmailTemplates with other values: not expected
		var te *mailtpl.Error
		if errors.As(err, &te) {
			err = service.Invalid(te.Field, te.Msg)
		}
		web.WriteError(w, err)
		return nil, nil, nil, mailtpl.Message{}, false
	}
	return o, a, &in, msg, true
}

// previewPaths are the pages the links of the previews open: the real pages, without a token (so they only say the
// link is not valid), or the account page; "" for the sign-in code, which has no link.
var previewPaths = map[string]string{mailtpl.Invite: "/invite?token=preview", mailtpl.Reset: "/reset?token=preview",
	mailtpl.Verify: "/verify-email?token=preview", mailtpl.Recovery: "/account", mailtpl.Code: ""}

// previewEmailTemplate renders one email from the templates as they are being edited, with made-up values: its subject,
// HTML and text (POST /api/orgs/{org}/email-templates/preview). Nothing is saved or sent.
func (m *Module) previewEmailTemplate(w http.ResponseWriter, r *http.Request) {
	_, _, _, msg, ok := m.renderDraft(w, r)
	if !ok {
		return
	}
	web.WriteJSON(w, http.StatusOK, msg)
}

// testEmailTemplate emails one email, rendered as the preview is, to an address the administrator gives, with
// "[Test]" before its subject (POST /api/orgs/{org}/email-templates/test). It is queued as the organization's mail, so
// it counts against the organization's share of the queue, and audited with the address.
func (m *Module) testEmailTemplate(w http.ResponseWriter, r *http.Request) {
	o, a, in, msg, found := m.renderDraft(w, r)
	if !found {
		return
	}
	addr, err := mail.ParseAddress(in.To)
	if err != nil || addr.Name != "" {
		web.WriteError(w, service.Invalid("to", "enter an email address, such as you@example.com"))
		return
	}
	// Per administrator (service accounts may not), counted once the address is valid (what is refused counts too).
	within, err := m.s.TestEmailAllowed(r.Context(), a.UserID)
	switch {
	case err != nil:
		web.WriteError(w, fmt.Errorf("%w: %v", service.ErrUnavailable, err))
		return
	case !within:
		w.Header().Set("Retry-After", "60")
		web.WriteJSON(w, http.StatusTooManyRequests, web.ErrorBody{Error: "Too many test emails were sent. Wait a minute and try again."})
		return
	}
	msg.Subject = "[Test] " + msg.Subject
	detail := map[string]string{"email": in.Email, "to": addr.Address}
	err = m.s.Svc.Audited(r.Context(), a, o.ID, "org.email_templates.test", o.Name, detail, func() error {
		return m.Mailer.SendTest(r.Context(), o.ID, addr.Address, msg)
	})
	switch {
	case errors.Is(err, ErrMailerDisabled):
		web.WriteJSON(w, http.StatusServiceUnavailable, web.ErrorBody{Error: "Email is not set up on this server."})
	case err != nil:
		web.WriteError(w, err)
	default:
		ok(w)
	}
}

// The email preview is drawn in a frame of its own (GET /admin/email-preview), sandboxed by the console (an opaque
// origin: nothing in it reaches the console or its session) and under a policy of its own, which lets the email's
// inline styles and remote images show (the console's forbids both) and runs no script but the frame's own. The console
// posts the rendered HTML to it; the frame parses it (scripts in it never run) and puts it in place of its own page,
// then posts its height back.
//
// The frame must not leave the email either: a page it navigated to would run in the console's dialog with the
// frame's allow-scripts, free to pose as the console. The policy cannot forbid navigation, so the frame's script does:
// the email's <meta http-equiv> (a refresh moves the frame as soon as it is in place) and <base> are dropped before it
// is put in place, and a click on a link is cancelled (the links show, and go nowhere). The sandbox has no
// allow-popups, allow-top-navigation or allow-forms, so nothing opens a window, moves the console or posts a form.
const emailPreviewScript = `addEventListener("click",function(e){var t=e.target;if(t&&t.closest&&t.closest("a,area"))e.preventDefault()},true);` +
	`addEventListener("message",function(e){if(e.source!==parent||!e.data||typeof e.data.html!=="string")return;` +
	`var d=new DOMParser().parseFromString(e.data.html,"text/html");` +
	`d.querySelectorAll("meta[http-equiv],base").forEach(function(n){n.remove()});` +
	`document.replaceChild(document.importNode(d.documentElement,true),document.documentElement);` +
	`parent.postMessage({previewHeight:document.documentElement.scrollHeight},"*")});` +
	`parent.postMessage({previewReady:true},"*")`

var (
	emailPreviewPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Email preview</title></head><body><script>` +
		emailPreviewScript + `</script></body></html>`
	emailPreviewCSP = func() string {
		h := sha256.Sum256([]byte(emailPreviewScript))
		return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(h[:]) + "'; style-src 'unsafe-inline'; " +
			"img-src https: data:; font-src https: data:; frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
	}()
)

func emailPreviewFrame(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", emailPreviewCSP)
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(emailPreviewPage))
}
