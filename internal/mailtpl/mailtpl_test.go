package mailtpl

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

func sample(name string) Data {
	return Sample(name, Data{Site: "Acme", Org: "Acme", LogoURL: "https://id.example.com/logo", PrimaryColor: DefaultColor})
}

// The built-in templates pass their own checks and render every email.
func TestBuiltin(t *testing.T) {
	if err := Check(model.EmailTemplateSet{}, Builtin()); err != nil {
		t.Fatal(err)
	}
	for _, n := range Names() {
		msg, err := Render(Builtin(), n, sample(n))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if !strings.Contains(msg.Subject, "Acme") || !strings.HasPrefix(msg.Text, "Hello Alex Example,\n\n") ||
			!strings.Contains(msg.HTML, "Hello Alex Example,") || !strings.HasSuffix(msg.HTML, "</div></body></html>") {
			t.Fatalf("%s: %+v", n, msg)
		}
	}
	msg, _ := Render(Builtin(), Code, sample(Code))
	if strings.Contains(msg.Subject, "123456") || !strings.Contains(msg.Text, "    123456\n") {
		t.Fatalf("code: %+v", msg)
	}
}

// An organization's part wins over the inherited one; a part it leaves empty is inherited.
func TestMergeAndNormalize(t *testing.T) {
	primary := model.EmailTemplateSet{LayoutHTML: `<main>{{template "body" .}}</main>`}
	own := model.EmailTemplateSet{Emails: map[string]model.EmailTemplate{Reset: {Subject: "Reset for {{.Org}}"}}}
	set := Merge(&own, &primary, ptr(Builtin()))
	if set.LayoutHTML != primary.LayoutHTML || set.LayoutText != builtinLayoutText || set.Emails[Reset].Subject != "Reset for {{.Org}}" ||
		set.Emails[Reset].HTML != builtin.Emails[Reset].HTML || len(set.Emails) != len(Emails) {
		t.Fatalf("merge: %+v", set)
	}

	inherited := Merge(&primary, ptr(Builtin()))
	got, err := Normalize(model.EmailTemplateSet{
		LayoutHTML: inherited.LayoutHTML, // the same as inherited: not kept
		LayoutText: "Hi\r\n{{template \"body\" .}}",
		Emails: map[string]model.EmailTemplate{
			Reset:  {Subject: "  \n", HTML: inherited.Emails[Reset].HTML},
			Invite: {Subject: "Join {{.Site}}"},
		},
	}, inherited)
	if err != nil {
		t.Fatal(err)
	}
	if got.LayoutHTML != "" || got.LayoutText != "Hi\n{{template \"body\" .}}" || len(got.Emails) != 1 || got.Emails[Invite].Subject != "Join {{.Site}}" {
		t.Fatalf("normalize: %+v", got)
	}
	if _, err := Normalize(model.EmailTemplateSet{Emails: map[string]model.EmailTemplate{"nope": {Subject: "x"}}}, inherited); field(err) != "emails.nope" {
		t.Fatalf("unknown email: %v", err)
	}
	if !IsEmpty(model.EmailTemplateSet{}) || IsEmpty(got) {
		t.Fatal("IsEmpty")
	}
}

func ptr[T any](v T) *T { return &v }

func field(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Field
	}
	return ""
}

// Check refuses templates that could not be sent, would not do their job, or would cost the server.
func TestCheck(t *testing.T) {
	inherited := Builtin()
	email := func(name string, e model.EmailTemplate) model.EmailTemplateSet {
		return model.EmailTemplateSet{Emails: map[string]model.EmailTemplate{name: e}}
	}
	for _, c := range []struct {
		name  string
		own   model.EmailTemplateSet
		field string
		msg   string
	}{
		{"ok", email(Reset, model.EmailTemplate{Subject: "{{.Org}}: reset", HTML: `<p><a href="{{.Link}}">Reset</a> {{if .LogoURL}}<img src="{{.LogoURL}}">{{end}}</p>`}), "", ""},
		{"parse", email(Reset, model.EmailTemplate{HTML: "<p>\n{{.Link</p>"}), "emails.reset.html", "line 2:"},
		{"unknown field", email(Reset, model.EmailTemplate{Text: "{{.Link}}\n{{.Password}}"}), "emails.reset.text", "line 2:"},
		{"loop", email(Reset, model.EmailTemplate{Text: "{{.Link}}{{range 1000000000}}{{end}}"}), "emails.reset.text", "loops"},
		{"define", email(Reset, model.EmailTemplate{Text: `{{.Link}}{{define "x"}}y{{end}}`}), "emails.reset.text", "define"},
		{"template", email(Reset, model.EmailTemplate{Text: `{{.Link}}{{template "body" .}}`}), "emails.reset.text", "not available"},
		{"no body", model.EmailTemplateSet{LayoutHTML: "<p>{{.Site}}</p>"}, "layout_html", `{{template "body" .}}`},
		{"layout loses link", model.EmailTemplateSet{LayoutText: `{{if false}}{{template "body" .}}{{end}}`}, "layout_text", "must show the link"},
		{"no link", email(Invite, model.EmailTemplate{HTML: "<p>Welcome</p>"}), "emails.invite.html", "must show the link"},
		{"no code", email(Code, model.EmailTemplate{Text: "Your code is coming"}), "emails.code.text", "must show the code"},
		{"code in subject", email(Code, model.EmailTemplate{Subject: "Code {{.Code}}"}), "emails.code.subject", "must not show"},
		{"link in subject", email(Reset, model.EmailTemplate{Subject: "{{.Link}}"}), "emails.reset.subject", "must not show"},
		{"too much output", email(Reset, model.EmailTemplate{Text: "{{.Link}}" + strings.Repeat(`{{printf "%900000s" ""}}`, 2)}), "emails.reset.text", "writes more than"},
		{"too long", email(Reset, model.EmailTemplate{Text: "{{.Link}}" + strings.Repeat("x", MaxPartBytes)}), "emails.reset.text", "longer than"},
	} {
		err := Check(c.own, inherited)
		if c.field == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if field(err) != c.field || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: got %v, want %s: ...%s...", c.name, err, c.field, c.msg)
		}
	}
}

// HTML templates escape what they are given: a display name cannot add markup to an email.
func TestEscaping(t *testing.T) {
	d := sample(Reset)
	d.Name = `<script>x</script>`
	msg, err := Render(Builtin(), Reset, d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg.HTML, "<script>") || !strings.Contains(msg.HTML, "&lt;script&gt;") || !strings.Contains(msg.Text, "<script>") {
		t.Fatalf("%s", msg.HTML)
	}
	// a subject is one line, whatever its template writes
	set := Builtin()
	set.Emails[Reset] = model.EmailTemplate{Subject: "a\r\nBcc: x@example.com", HTML: set.Emails[Reset].HTML, Text: set.Emails[Reset].Text}
	if msg, _ = Render(set, Reset, d); msg.Subject != "a Bcc: x@example.com" {
		t.Fatalf("subject %q", msg.Subject)
	}
}
