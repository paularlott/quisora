package service_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	"image/png"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// pngURI is a data: URI of a 1x1 PNG.
func pngURI(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
}

const svgURI = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxIDEiLz4=" // <svg .../>

// An organization's admins (and super admins) change its logo and primary colour; its managers, other organizations'
// admins and service accounts do not.
func TestBrandingWho(t *testing.T) {
	c := newCast(t)
	in := service.BrandingInput{PrimaryColor: ptr("#1D4ED8"), LogoLight: ptr(pngURI(t))}
	o, err := c.svc.UpdateBranding(c.ctx, actor(c.aAdmin), c.a.ID, in)
	if err != nil || o.Branding.PrimaryColor != "#1d4ed8" || o.Branding.Logo == "" {
		t.Fatalf("org admin: %+v %v", o, err)
	}
	if l, err := c.svc.OrgLogo(c.ctx, c.a.ID); err != nil || l.LightType != "image/png" || len(l.Light) == 0 || len(l.Dark) != 0 {
		t.Fatalf("logo record: %+v %v", l, err)
	}
	if len(c.audited(c.a.ID, "org.branding")) != 1 {
		t.Error("not audited")
	}
	if _, err := c.svc.UpdateBranding(c.ctx, actor(c.super), c.a.ID, service.BrandingInput{PrimaryColor: ptr("#000000")}); err != nil {
		t.Errorf("super admin: %v", err)
	}
	for name, a := range map[string]*service.Actor{"manager": actor(c.aManager), "another org's admin": actor(c.bAdmin)} {
		if _, err := c.svc.UpdateBranding(c.ctx, a, c.a.ID, in); !errors.Is(err, service.ErrForbidden) && !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, sa := newServiceAccount(t, c, c.a.ID, "users", "manage_admins", "clients")
	if _, err := c.svc.UpdateBranding(c.ctx, sa, c.a.ID, in); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("service account: %v", err)
	}
}

// Logos are PNG, JPEG, WebP or SVG data: URIs whose content is what they say, at most service.MaxLogoBytes; a dark
// logo needs a light one; the colour is #rrggbb dark enough for white text on it (WCAG AA, 4.5:1).
func TestBrandingValidation(t *testing.T) {
	c := newCast(t)
	admin := actor(c.aAdmin)
	big := "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, service.MaxLogoBytes+1))
	for name, tc := range map[string]struct {
		in    service.BrandingInput
		field string
	}{
		"colour not hex":      {service.BrandingInput{PrimaryColor: ptr("blue")}, "primary_color"},
		"colour too light":    {service.BrandingInput{PrimaryColor: ptr("#ffd700")}, "primary_color"},
		"not a data URI":      {service.BrandingInput{LogoLight: ptr("https://example.com/logo.png")}, "logo_light"},
		"type not allowed":    {service.BrandingInput{LogoLight: ptr("data:image/gif;base64,R0lGODlhAQABAAAAACw=")}, "logo_light"},
		"content not as said": {service.BrandingInput{LogoLight: ptr(strings.Replace(svgURI, "svg+xml", "png", 1))}, "logo_light"},
		"svg that is not":     {service.BrandingInput{LogoLight: ptr("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte("<html/>")))}, "logo_light"},
		"too big":             {service.BrandingInput{LogoLight: &big}, "logo_light"},
		"dark alone":          {service.BrandingInput{LogoDark: ptr(svgURI)}, "logo_dark"},
	} {
		if _, err := c.svc.UpdateBranding(c.ctx, admin, c.a.ID, tc.in); fieldOf(err) != tc.field {
			t.Errorf("%s: %v", name, err)
		}
	}
	if o, _ := c.svc.GetOrg(c.ctx, nil, c.a.ID); o.Branding.Logo != "" || o.Branding.PrimaryColor != "" {
		t.Fatalf("a refused change was kept: %+v", o.Branding)
	}

	// Both logos; then the dark one alone removed (the light one stays); then the light one, which goes with it.
	o, err := c.svc.UpdateBranding(c.ctx, admin, c.a.ID, service.BrandingInput{LogoLight: ptr(pngURI(t)), LogoDark: ptr(svgURI)})
	if err != nil {
		t.Fatal(err)
	}
	both := o.Branding.Logo
	if l, _ := c.svc.OrgLogo(c.ctx, c.a.ID); l == nil || l.DarkType != "image/svg+xml" {
		t.Fatalf("dark logo: %+v", l)
	}
	if o, err = c.svc.UpdateBranding(c.ctx, admin, c.a.ID, service.BrandingInput{LogoDark: ptr("")}); err != nil || o.Branding.Logo == "" || o.Branding.Logo == both {
		t.Fatalf("dark removed: %+v %v", o.Branding, err)
	}
	if o, err = c.svc.UpdateBranding(c.ctx, admin, c.a.ID, service.BrandingInput{LogoLight: ptr("")}); err != nil || o.Branding.Logo != "" {
		t.Fatalf("light removed: %+v %v", o.Branding, err)
	}
	if _, err := c.svc.OrgLogo(c.ctx, c.a.ID); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("logo record kept: %v", err)
	}
	// and a new one after that
	if o, err = c.svc.UpdateBranding(c.ctx, admin, c.a.ID, service.BrandingInput{LogoLight: ptr(svgURI)}); err != nil || o.Branding.Logo == "" {
		t.Fatalf("a logo after one was removed: %+v %v", o, err)
	}
	if l, err := c.svc.OrgLogo(c.ctx, c.a.ID); err != nil || l.LightType != "image/svg+xml" {
		t.Fatalf("logo record after one was removed: %+v %v", l, err)
	}
}

// The service account that creates an organization (orgs:create) gives it its branding then; afterwards a person
// changes it.
func TestBrandingOnCreate(t *testing.T) {
	c := newCast(t)
	_, deploy := newServiceAccount(t, c, c.primary.ID, service.ScopeOrgsCreate)
	o, _, _, err := c.svc.CreateOrgWithServiceAccount(c.ctx, deploy, service.OrgInput{Name: ptr("branded"),
		Branding: &service.BrandingInput{LogoLight: ptr(svgURI), PrimaryColor: ptr("#0f766e")}})
	if err != nil || o.Branding.Logo == "" || o.Branding.PrimaryColor != "#0f766e" {
		t.Fatalf("create with branding: %+v %v", o, err)
	}
	if l, err := c.svc.OrgLogo(c.ctx, o.ID); err != nil || l.LightType != "image/svg+xml" {
		t.Fatalf("logo record: %+v %v", l, err)
	}
	if _, _, _, err := c.svc.CreateOrgWithServiceAccount(c.ctx, deploy, service.OrgInput{Name: ptr("badly-branded"),
		Branding: &service.BrandingInput{PrimaryColor: ptr("#ffffff")}}); fieldOf(err) != "branding.primary_color" {
		t.Fatalf("invalid branding on create: %v", err)
	}
	if _, err := c.svc.OrgByName(c.ctx, "badly-branded"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("an organization was created with refused branding: %v", err)
	}
}
