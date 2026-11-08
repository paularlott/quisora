package admin_test

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// An organization's admins read, change, preview and test its email templates; managers, other organizations' admins
// and service accounts do not.
func TestEmailTemplatesAPI(t *testing.T) {
	w := newWorld(t)
	const ET = A + "/email-templates"
	ad := w.as("admin")

	r := ad.get(ET)
	want(t, r, 200)
	inherited := r.JSON["inherited"].(map[string]any)
	if r.JSON["primary"] != false || r.JSON["mail_enabled"] != false || len(r.JSON["emails"].([]any)) != 5 ||
		!strings.Contains(inherited["layout_html"].(string), `{{template "body" .}}`) {
		t.Fatalf("get: %s", r.Raw)
	}

	body := map[string]any{"emails": map[string]any{"reset": map[string]any{"subject": "{{.Org}}: new password"}}}
	r = ad.put(ET, body)
	want(t, r, 200)
	if r.JSON["own"].(map[string]any)["emails"].(map[string]any)["reset"].(map[string]any)["subject"] != "{{.Org}}: new password" {
		t.Fatalf("put: %s", r.Raw)
	}
	if len(auditActions(t, w, "org.email_templates")) != 1 {
		t.Error("not audited")
	}
	wantField(t, ad.put(ET, map[string]any{"emails": map[string]any{"invite": map[string]any{"html": "<p>no link</p>"}}}), 422, "emails.invite.html")
	wantField(t, ad.put(ET, map[string]any{"layout_text": "{{.Nope}}"}), 422, "layout_text")
	want(t, ad.put(ET, map[string]any{"extra": 1}), 400)

	// a preview renders the draft, not what is saved, with the organization's brand and a sample recipient
	draft := map[string]any{"emails": map[string]any{"reset": map[string]any{"subject": "Draft for {{.Name}}"}}}
	r = ad.post(ET+"/preview", map[string]any{"templates": draft, "email": "reset"})
	want(t, r, 200)
	if r.str("subject") != "Draft for Alex Example" || !strings.Contains(r.str("html"), "/reset?token=preview") || !strings.Contains(r.str("text"), "Hello Alex Example") {
		t.Fatalf("preview: %s", r.Raw)
	}
	r = ad.post(ET+"/preview", map[string]any{"email": "code"})
	if want(t, r, 200); !strings.Contains(r.str("text"), "123456") || !strings.Contains(r.str("subject"), "Acme") {
		t.Fatalf("preview code: %s", r.Raw)
	}
	wantField(t, ad.post(ET+"/preview", map[string]any{"email": "nope"}), 422, "email")
	wantField(t, ad.post(ET+"/preview", map[string]any{"email": "reset", "templates": map[string]any{"layout_html": "x"}}), 422, "layout_html")

	// a test email: refused without SMTP; sent, marked as a test and audited with it
	want(t, ad.post(ET+"/test", map[string]any{"email": "reset", "to": "pat@example.com"}), 503)
	m := &fakeMailer{}
	w.mod.Mailer = m
	if r = ad.get(ET); r.JSON["mail_enabled"] != true {
		t.Fatalf("mail enabled: %s", r.Raw)
	}
	wantField(t, ad.post(ET+"/test", map[string]any{"email": "reset", "to": "not an address"}), 422, "to")
	want(t, ad.post(ET+"/test", map[string]any{"email": "reset", "to": "pat@example.com", "templates": draft}), 200)
	if len(m.sent) != 1 || m.sent[0] != "test pat@example.com [Test] Draft for Alex Example" {
		t.Fatalf("sent: %v", m.sent)
	}
	if ev := auditActions(t, w, "org.email_templates.test"); len(ev) != 1 || ev[0].Detail["to"] != "pat@example.com" {
		t.Fatalf("test audit: %+v", ev)
	}
	// a few test emails a minute per administrator: then 429, and nothing more is sent
	for i := 2; i < web.TestEmailsPerMinute; i++ { // two counted: the one refused while email was off, and the one sent
		want(t, ad.post(ET+"/test", map[string]any{"email": "reset", "to": "pat@example.com"}), 200)
	}
	if res := ad.post(ET+"/test", map[string]any{"email": "reset", "to": "pat@example.com"}); res.Status != 429 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("over the limit: %d", res.Status)
	}
	if len(m.sent) != web.TestEmailsPerMinute-1 {
		t.Fatalf("sent %d test emails", len(m.sent))
	}

	for name, c := range map[string]*caller{"manager": w.as("manager"), "other org": w.as("other"),
		"service account": w.asServiceAccount(w.acme, service.ScopeUsers, service.ScopeClients)} {
		for _, rr := range []resp{c.get(ET), c.put(ET, body), c.post(ET+"/preview", map[string]any{"email": "reset"}),
			c.post(ET+"/test", map[string]any{"email": "reset", "to": "pat@example.com"})} {
			if rr.Status != 403 && rr.Status != 404 {
				t.Errorf("%s: %d %s", name, rr.Status, rr.Raw)
			}
		}
	}
	if len(m.sent) != web.TestEmailsPerMinute-1 {
		t.Fatalf("sent by others: %v", m.sent)
	}
}
