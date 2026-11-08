package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// Super admins add, change and remove custom skins; organization administrators list them (to choose one); nobody
// changes a built-in skin. A skin's name is checked, is its id and never changes.
func TestSkinsWho(t *testing.T) {
	c := newCast(t)
	sup, admin := actor(c.super), actor(c.aAdmin)
	name, css := "acme", ":root[data-skin]{--accent:#123456}"
	in := service.SkinInput{Name: &name, CSS: &css}
	if _, err := c.svc.CreateSkin(c.ctx, admin, in); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("an organization admin added a skin: %v", err)
	}
	v, err := c.svc.CreateSkin(c.ctx, sup, in)
	if err != nil || v.DisplayName != "acme" || v.Builtin {
		t.Fatalf("create: %v %+v", err, v)
	}
	if _, err := c.svc.CreateSkin(c.ctx, sup, in); !errors.Is(err, service.ErrConflict) && !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("a second acme: %v", err)
	}
	for _, bad := range []string{"matte", "default", "Bad Name"} {
		n := bad
		if _, err := c.svc.CreateSkin(c.ctx, sup, service.SkinInput{Name: &n, CSS: &css}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("name %q: %v", bad, err)
		}
	}
	other := `:root[data-skin="matte"]{}`
	n2 := "copy"
	if _, err := c.svc.CreateSkin(c.ctx, sup, service.SkinInput{Name: &n2, CSS: &other}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("a copy of matte's selectors: %v", err)
	}

	l, err := c.svc.ListSkins(c.ctx, admin)
	if err != nil || len(l) < 2 || !l[0].Builtin || l[len(l)-1].Name != "acme" || l[len(l)-1].CSS != "" {
		t.Fatalf("list: %v %+v", err, l)
	}
	if _, err := c.svc.ListSkins(c.ctx, actor(c.aUser)); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("a user listed the skins: %v", err)
	}
	if _, err := c.svc.GetSkin(c.ctx, admin, "acme"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("an organization admin read a stylesheet: %v", err)
	}
	if g, err := c.svc.GetSkin(c.ctx, sup, "matte"); err != nil || g.CSS == "" || !g.Builtin {
		t.Errorf("matte: %v", err)
	}

	display, css3 := "Acme", ":root[data-skin=acme]{--accent:#654321}"
	if v, err = c.svc.UpdateSkin(c.ctx, sup, "acme", service.SkinInput{DisplayName: &display, CSS: &css3}); err != nil || v.DisplayName != "Acme" || v.CSS != css3 {
		t.Fatalf("update: %v %+v", err, v)
	}
	if _, err := c.svc.UpdateSkin(c.ctx, sup, "matte", service.SkinInput{DisplayName: &display}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("matte changed: %v", err)
	}
	if err := c.svc.DeleteSkin(c.ctx, admin, "acme"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("an organization admin removed a skin: %v", err)
	}
	if err := c.svc.DeleteSkin(c.ctx, sup, "matte"); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("matte removed: %v", err)
	}
	if err := c.svc.DeleteSkin(c.ctx, sup, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.GetSkin(c.ctx, sup, "acme"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("removed skin: %v", err)
	}
	// its name may be used again
	if _, err := c.svc.CreateSkin(c.ctx, sup, in); err != nil {
		t.Errorf("acme again: %v", err)
	}
}

// An organization's pages use its own skin, else the primary organization's, else none; "default" is the built-in look
// whatever the primary organization chose; a skin removed counts as none chosen; a skin there is not cannot be chosen.
func TestSkinResolve(t *testing.T) {
	c := newCast(t)
	sup := actor(c.super)
	name, css := "acme", ":root[data-skin]{}"
	if _, err := c.svc.CreateSkin(c.ctx, sup, service.SkinInput{Name: &name, CSS: &css}); err != nil {
		t.Fatal(err)
	}
	choose := func(orgID, v string) error {
		_, err := c.svc.UpdateBranding(c.ctx, sup, orgID, service.BrandingInput{Skin: &v})
		return err
	}
	resolve := func(orgID string) string {
		o, err := c.svc.GetOrg(c.ctx, nil, orgID)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := c.svc.ResolveSkin(c.ctx, o)
		return n
	}
	if n := resolve(c.a.ID); n != "" {
		t.Fatalf("none chosen: %q", n)
	}
	if err := choose(c.primary.ID, "matte"); err != nil {
		t.Fatal(err)
	}
	if n := resolve(c.a.ID); n != "matte" {
		t.Fatalf("the primary organization's: %q", n)
	}
	if err := choose(c.a.ID, "acme"); err != nil {
		t.Fatal(err)
	}
	if n := resolve(c.a.ID); n != "acme" {
		t.Fatalf("its own: %q", n)
	}
	if err := choose(c.b.ID, "default"); err != nil {
		t.Fatal(err)
	}
	if n := resolve(c.b.ID); n != "" {
		t.Fatalf("the built-in look: %q", n)
	}
	if err := choose(c.a.ID, "nope"); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("a skin there is not: %v", err)
	}
	if err := c.svc.DeleteSkin(c.ctx, sup, "acme"); err != nil {
		t.Fatal(err)
	}
	if n := resolve(c.a.ID); n != "matte" {
		t.Fatalf("its skin removed: %q", n)
	}
	// an organization's administrator chooses its skin
	if _, err := c.svc.UpdateBranding(c.ctx, actor(c.aAdmin), c.a.ID, service.BrandingInput{Skin: ptr("default")}); err != nil {
		t.Fatal(err)
	}
}
