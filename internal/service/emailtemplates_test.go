package service_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/mailtpl"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// An organization sends its own templates, part by part over the primary organization's, over the built-in ones.
func TestEmailTemplatesInherit(t *testing.T) {
	c := newCast(t)
	b := mailtpl.Builtin()
	if got := c.svc.SendingEmailTemplates(c.ctx, c.a.ID); got.LayoutHTML != b.LayoutHTML || got.Emails[mailtpl.Reset] != b.Emails[mailtpl.Reset] {
		t.Fatal("without templates: the built-in ones")
	}

	// the primary organization's layout is every organization's
	layout := `<div class="brand">{{.Site}}{{template "body" .}}</div>`
	v, err := c.svc.UpdateEmailTemplates(c.ctx, actor(c.super), c.primary.ID, model.EmailTemplateSet{LayoutHTML: layout})
	if err != nil || !v.Primary || v.Own.LayoutHTML != layout || v.Inherited.LayoutHTML != b.LayoutHTML {
		t.Fatalf("primary: %+v %v", v, err)
	}
	if got := c.svc.SendingEmailTemplates(c.ctx, c.a.ID); got.LayoutHTML != layout || got.LayoutText != b.LayoutText {
		t.Fatalf("inherited layout: %q", got.LayoutHTML)
	}

	// org-a changes one subject; the rest it inherits (and keeps following)
	reset := b.Emails[mailtpl.Reset]
	reset.Subject = "{{.Org}}: choose a new password"
	v, err = c.svc.UpdateEmailTemplates(c.ctx, actor(c.aAdmin), c.a.ID, model.EmailTemplateSet{
		LayoutHTML: layout, // the same as inherited: not kept
		Emails:     map[string]model.EmailTemplate{mailtpl.Reset: reset},
	})
	if err != nil || v.Primary || v.Own.LayoutHTML != "" || v.Inherited.LayoutHTML != layout ||
		v.Own.Emails[mailtpl.Reset] != (model.EmailTemplate{Subject: reset.Subject}) {
		t.Fatalf("org-a: %+v %v", v, err)
	}
	got := c.svc.SendingEmailTemplates(c.ctx, c.a.ID)
	if got.LayoutHTML != layout || got.Emails[mailtpl.Reset].Subject != reset.Subject || got.Emails[mailtpl.Reset].HTML != reset.HTML {
		t.Fatalf("org-a sends: %+v", got)
	}
	if got := c.svc.SendingEmailTemplates(c.ctx, c.b.ID); got.Emails[mailtpl.Reset].Subject != b.Emails[mailtpl.Reset].Subject {
		t.Fatal("org-b: its own (the inherited) subject")
	}
	if ev := c.audited(c.a.ID, "org.email_templates"); len(ev) != 1 || ev[0].Detail["changed.emails.reset.subject"] != "set" || len(ev[0].Detail) != 1 {
		t.Fatalf("audit: %+v", ev)
	}

	// saving what is stored changes nothing (and audits nothing); clearing every part removes the record
	if _, err := c.svc.UpdateEmailTemplates(c.ctx, actor(c.aAdmin), c.a.ID, v.Own); err != nil || len(c.audited(c.a.ID, "org.email_templates")) != 1 {
		t.Fatalf("unchanged: %v", err)
	}
	if v, err = c.svc.UpdateEmailTemplates(c.ctx, actor(c.aAdmin), c.a.ID, model.EmailTemplateSet{}); err != nil || !mailtpl.IsEmpty(v.Own) {
		t.Fatalf("cleared: %+v %v", v, err)
	}
	if _, err := c.svc.EmailTpls.Get(c.ctx, c.a.ID); err == nil {
		t.Fatal("the record stays")
	}
	// and set again after its removal
	if _, err = c.svc.UpdateEmailTemplates(c.ctx, actor(c.aAdmin), c.a.ID, model.EmailTemplateSet{Emails: map[string]model.EmailTemplate{mailtpl.Reset: reset}}); err != nil {
		t.Fatal(err)
	}
	if v, err = c.svc.EmailTemplates(c.ctx, actor(c.aAdmin), c.a.ID); err != nil || v.Own.Emails[mailtpl.Reset].Subject != reset.Subject {
		t.Fatalf("read: %+v %v", v, err)
	}
}

// An organization's admins and the super admins edit its templates; nobody else, and no service account.
func TestEmailTemplatesWho(t *testing.T) {
	c := newCast(t)
	in := model.EmailTemplateSet{Emails: map[string]model.EmailTemplate{mailtpl.Invite: {Subject: "Welcome to {{.Org}}"}}}
	for name, a := range map[string]*service.Actor{"org admin": actor(c.aAdmin), "super admin": actor(c.super)} {
		if _, err := c.svc.UpdateEmailTemplates(c.ctx, a, c.a.ID, in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := c.svc.PreviewEmailTemplates(c.ctx, a, c.a.ID, in); err != nil {
			t.Errorf("%s preview: %v", name, err)
		}
	}
	// The primary organization's templates are every organization's: only a super admin changes them, not its own
	// administrators (who still read and preview them).
	if _, err := c.svc.UpdateEmailTemplates(c.ctx, actor(c.pAdmin), c.primary.ID, in); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("primary org's admin on its templates: %v", err)
	}
	if _, err := c.svc.PreviewEmailTemplates(c.ctx, actor(c.pAdmin), c.primary.ID, in); err != nil {
		t.Errorf("primary org's admin previews: %v", err)
	}
	if _, err := c.svc.UpdateEmailTemplates(c.ctx, actor(c.super), c.primary.ID, in); err != nil {
		t.Errorf("super admin on the primary's templates: %v", err)
	}
	_, sa := newServiceAccount(t, c, c.a.ID, "users", "manage_admins", "clients")
	for name, a := range map[string]*service.Actor{"manager": actor(c.aManager), "user": actor(c.aUser), "another org's admin": actor(c.bAdmin),
		"primary org's admin": actor(c.pAdmin), "service account": sa} {
		if _, err := c.svc.UpdateEmailTemplates(c.ctx, a, c.a.ID, in); !errors.Is(err, service.ErrForbidden) && !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := c.svc.EmailTemplates(c.ctx, a, c.a.ID); !errors.Is(err, service.ErrForbidden) && !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s reads: %v", name, err)
		}
		if _, err := c.svc.PreviewEmailTemplates(c.ctx, a, c.a.ID, in); !errors.Is(err, service.ErrForbidden) && !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s previews: %v", name, err)
		}
	}
}

// A template that cannot be sent is refused with the part at fault, and nothing is stored.
func TestEmailTemplatesInvalid(t *testing.T) {
	c := newCast(t)
	for field, in := range map[string]model.EmailTemplateSet{
		"emails.invite.html":  {Emails: map[string]model.EmailTemplate{mailtpl.Invite: {HTML: "<p>No link</p>"}}},
		"emails.code.subject": {Emails: map[string]model.EmailTemplate{mailtpl.Code: {Subject: "{{.Code}}"}}},
		"layout_text":         {LayoutText: "Hello"},
		"emails.nope":         {Emails: map[string]model.EmailTemplate{"nope": {Subject: "x"}}},
	} {
		_, err := c.svc.UpdateEmailTemplates(c.ctx, actor(c.aAdmin), c.a.ID, in)
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != field {
			t.Errorf("%s: %v", field, err)
		}
		if _, err := c.svc.PreviewEmailTemplates(c.ctx, actor(c.aAdmin), c.a.ID, in); !errors.As(err, &fe) || fe.Field != field {
			t.Errorf("%s preview: %v", field, err)
		}
	}
	if len(c.audited(c.a.ID, "org.email_templates")) != 0 {
		t.Error("audited")
	}
	set, err := c.svc.PreviewEmailTemplates(c.ctx, actor(c.aAdmin), c.a.ID, model.EmailTemplateSet{LayoutText: "Hi {{.Name}}\n{{template \"body\" .}}"})
	if err != nil || !strings.HasPrefix(set.LayoutText, "Hi ") || set.Emails[mailtpl.Code].HTML == "" {
		t.Fatalf("preview set: %+v %v", set, err)
	}
}
