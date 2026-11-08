package service_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// An organization's own password, lockout, API token and privileged session policy: each within its bounds, or 0
// for the server's; the privileged session lengths no longer than the server's sessions.
func TestOrgPolicyValidation(t *testing.T) {
	c := newCast(t)
	c.svc.Cfg.Session.TTL, c.svc.Cfg.Session.Idle = 86400, 3600
	set := func(f func(*model.OrgSettings)) error {
		o, err := c.svc.GetOrg(c.ctx, nil, c.a.ID)
		if err != nil {
			t.Fatal(err)
		}
		st := o.Settings
		f(&st)
		_, err = c.svc.UpdateOrg(c.ctx, service.System, c.a.ID, service.OrgInput{Settings: &st})
		return err
	}
	for name, f := range map[string]func(*model.OrgSettings){
		"password 7":          func(s *model.OrgSettings) { s.PasswordMinLength = 7 },
		"password 65":         func(s *model.OrgSettings) { s.PasswordMinLength = 65 },
		"lockout 101":         func(s *model.OrgSettings) { s.LockoutAttempts = 101 },
		"lockout -1":          func(s *model.OrgSettings) { s.LockoutAttempts = -1 },
		"locked 1441 min":     func(s *model.OrgSettings) { s.LockoutMinutes = 1441 },
		"token -2 days":       func(s *model.OrgSettings) { s.APITokenMaxDays = -2 },
		"token 3651 days":     func(s *model.OrgSettings) { s.APITokenMaxDays = 3651 },
		"privileged ttl":      func(s *model.OrgSettings) { s.PrivilegedTTL = 86401 },
		"privileged idle":     func(s *model.OrgSettings) { s.PrivilegedIdle = 3601 },
		"privileged negative": func(s *model.OrgSettings) { s.PrivilegedTTL = -1 },
	} {
		if err := set(f); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := set(func(s *model.OrgSettings) {
		s.PasswordMinLength, s.LockoutAttempts, s.LockoutMinutes, s.APITokenMaxDays = 20, 5, 60, 30
		s.PrivilegedTTL, s.PrivilegedIdle = 3600, 600
	}); err != nil {
		t.Fatal(err)
	}
	o, _ := c.svc.GetOrg(c.ctx, nil, c.a.ID)
	if s := o.Settings; s.PasswordMinLength != 20 || s.LockoutAttempts != 5 || s.LockoutMinutes != 60 || s.APITokenMaxDays != 30 ||
		s.PrivilegedTTL != 3600 || s.PrivilegedIdle != 600 {
		t.Fatalf("saved %+v", s)
	}
	// A privileged length saved before the server's sessions were shortened does not block other changes.
	c.svc.Cfg.Session.TTL = 1800
	if err := set(func(s *model.OrgSettings) { s.PasswordMinLength = 16 }); err != nil {
		t.Fatalf("unchanged privileged ttl over a lowered limit: %v", err)
	}
}

// The organization's policy is used where it is set, and the server's elsewhere: the shortest password, the lockout
// and the longest API token.
func TestOrgPolicyApplies(t *testing.T) {
	c := newCast(t)
	c.svc.Cfg.Limits.PasswordMinLength, c.svc.Cfg.Tokens.APITokenMaxDays = 15, 365
	c.svc.Cfg.Limits.LockoutAttempts, c.svc.Cfg.Limits.LockoutMinutes = 10, 15
	o, _ := c.svc.GetOrg(c.ctx, nil, c.a.ID)
	st := o.Settings
	st.PasswordMinLength, st.APITokenMaxDays, st.LockoutAttempts = 20, 30, 3
	if _, err := c.svc.UpdateOrg(c.ctx, service.System, c.a.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	pw := "violet maple ox and" // 19 characters
	if err := c.svc.CheckPassword(c.ctx, c.aUser, pw); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("19 characters accepted in an organization asking for 20: %v", err)
	}
	if err := c.svc.CheckPassword(c.ctx, c.bAdmin, pw); err != nil {
		t.Errorf("19 characters refused in an organization with the server's 15: %v", err)
	}

	tok, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "default", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(tok.Expires); d < 29*24*time.Hour || d > 30*24*time.Hour {
		t.Errorf("default expiry %v for the organization's 30 days", d)
	}
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "long", Scopes: []string{"api"}, Expires: 31}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("31 days over the organization's 30: %v", err)
	}
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.bAdmin), service.APITokenInput{Name: "long", Scopes: []string{"api"}, Expires: 300}); err != nil {
		t.Errorf("300 days under the server's 365: %v", err)
	}

	// No limit: a token made without a lifetime never expires, over the server's 365 days.
	st.APITokenMaxDays = model.APITokensNoLimit
	if _, err := c.svc.UpdateOrg(c.ctx, service.System, c.a.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	if tok, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "forever", Scopes: []string{"api"}}); err != nil || !tok.Expires.IsZero() {
		t.Errorf("no limit: %v %v", err, tok.Expires)
	}
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "long", Scopes: []string{"api"}, Expires: 3000}); err != nil {
		t.Errorf("no limit, 3000 days: %v", err)
	}

	a, _ := c.svc.GetOrg(c.ctx, nil, c.a.ID)
	b, _ := c.svc.GetOrg(c.ctx, nil, c.b.ID)
	if n, w := c.svc.Lockout(a); n != 3 || w != 15*time.Minute {
		t.Errorf("organization's lockout %d %v", n, w)
	}
	if n, w := c.svc.Lockout(b); n != 10 || w != 15*time.Minute {
		t.Errorf("server's lockout %d %v", n, w)
	}
}

// The footer is part of an organization's branding: one line, at most MaxFooterBytes, "" for the inherited one.
func TestOrgFooter(t *testing.T) {
	c := newCast(t)
	a := actor(c.aAdmin)
	o, err := c.svc.UpdateBranding(c.ctx, a, c.a.ID, service.BrandingInput{Footer: ptr(`  © Acme · <a href="https://acme.example/privacy">Privacy</a>  `)})
	if err != nil || o.Branding.Footer != `© Acme · <a href="https://acme.example/privacy">Privacy</a>` {
		t.Fatalf("footer: %v %q", err, o.Branding.Footer)
	}
	for _, f := range []string{"two\nlines", strings.Repeat("x", service.MaxFooterBytes+1)} {
		if _, err := c.svc.UpdateBranding(c.ctx, a, c.a.ID, service.BrandingInput{Footer: &f}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("footer %.20q: %v", f, err)
		}
	}
	if o, err = c.svc.UpdateBranding(c.ctx, a, c.a.ID, service.BrandingInput{Footer: ptr("")}); err != nil || o.Branding.Footer != "" {
		t.Fatalf("footer removed: %v %q", err, o.Branding.Footer)
	}
	if _, err := c.svc.UpdateBranding(c.ctx, actor(c.aManager), c.a.ID, service.BrandingInput{Footer: ptr("mine")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("a manager set the footer: %v", err)
	}
}
