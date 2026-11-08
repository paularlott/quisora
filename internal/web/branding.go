package web

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/mailtpl"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// An organization's branding (model.OrgBranding) is served under /o/<org>/branding/: logo-light, logo-dark (when it
// has one) and brand.css (its primary colour). The pages name them with ?v=<version>, so a change
// is a new URL and each can be cached for good.

// OrgLogoURL is the URL of organization o's logo (dark: its dark-theme image), or "" when it has none.
func OrgLogoURL(o *model.Org, dark bool) string {
	if o.Branding.Logo == "" || dark && !o.Branding.LogoDark {
		return ""
	}
	name := "/branding/logo-light"
	if dark {
		name = "/branding/logo-dark"
	}
	return OrgPath(o.ID, name) + "?v=" + o.Branding.Logo
}

// MailBrand is who organization o's emails are from, as their templates are given it (mailtpl.Data): its display name
// (else the server's site name), the absolute URL of its logo (else of the server's) and its primary colour (else the
// built-in one).
func MailBrand(cfg *config.Config, o *model.Org) mailtpl.Data {
	d := mailtpl.Data{Site: cfg.UI.SiteName, LogoURL: cfg.Server.PublicURL + "/branding/logo-light", PrimaryColor: mailtpl.DefaultColor}
	if o == nil {
		return d
	}
	d.Org = o.DisplayName
	if strings.TrimSpace(o.DisplayName) != "" {
		d.Site = o.DisplayName
	}
	if u := OrgLogoURL(o, false); u != "" {
		d.LogoURL = cfg.Server.PublicURL + u
	}
	if o.Branding.PrimaryColor != "" {
		d.PrimaryColor = o.Branding.PrimaryColor
	}
	return d
}

// For is the site as the pages of organization o show it (nil: the server's): with its logo, under its name (Brand;
// the footer stays the server's), when it has a logo; in its primary colour when it has one.
func (st Site) For(o *model.Org) Site {
	if o == nil {
		return st
	}
	if o.Branding.Logo != "" {
		st.LogoLight, st.Brand, st.OrgLogo = OrgLogoURL(o, false), o.DisplayName, true
		st.LogoDark = cmp.Or(OrgLogoURL(o, true), st.LogoLight)
	}
	if c := o.Branding.PrimaryColor; c != "" {
		st.BrandCSS = OrgPath(o.ID, "/branding/brand.css") + "?v=" + strings.TrimPrefix(c, "#")
	}
	if o.Branding.Footer != "" {
		st.Footer = FooterHTML(o.Branding.Footer)
	}
	if o.Settings.PasswordMinLength > 0 {
		st.PasswordMin = o.Settings.PasswordMinLength
	}
	return st
}

// siteFor is the site's branding for the pages of organization o (Site.For), with its skin (withSkin; preview is a
// page's ?skin=) and the primary organization's footer when o has none of its own (else ui.footer).
func (s *Server) siteFor(ctx context.Context, o *model.Org, preview string) Site {
	st := s.withSkin(ctx, s.Site.For(o), o, preview)
	if o != nil && o.Branding.Footer != "" || o != nil && o.Primary {
		return st
	}
	if id, err := s.Svc.PrimaryOrgID(ctx); err == nil {
		if p, err := s.Svc.Org(ctx, id); err == nil && p.Branding.Footer != "" {
			st.Footer = FooterHTML(p.Branding.Footer)
		}
	}
	return st
}

// orgBranding serves the branding of the organization of the path (InOrg).
func (s *Server) orgBranding(w http.ResponseWriter, r *http.Request) {
	o := Org(r)
	var body []byte
	var typ string
	switch name := r.PathValue("name"); {
	case name == "brand.css" && o.Branding.PrimaryColor != "":
		body, typ = []byte(brandCSS(o.Branding.PrimaryColor)), "text/css; charset=utf-8"
	case name == "logo-light" && o.Branding.Logo != "" || name == "logo-dark" && o.Branding.LogoDark:
		l, err := s.Svc.OrgLogo(r.Context(), o.ID)
		if errors.Is(err, service.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			WriteError(w, err)
			return
		}
		body, typ = l.Light, l.LightType
		if name == "logo-dark" {
			body, typ = l.Dark, l.DarkType
		}
	default:
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", typ)
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox") // an SVG opened alone runs nothing
	h.Set("Cache-Control", "public, max-age=31536000, immutable")                              // named with ?v=<version>
	_, _ = w.Write(body)
}

// brandCSS is the stylesheet of a primary colour c (#rrggbb): the theme's accent tokens, and those the skins map
// them from, set from it. Buttons fill with c under white text (contrast checked when it was set); link text and focus
// rings take c darkened in the light theme and lightened in the dark one until it reads on the page at 4.5:1. It
// applies where <html> carries data-brand, and is loaded after the skin's stylesheet, which it overrides.
func brandCSS(c string) string {
	text := "light-dark(" + readable(c, "#000000", "#e6ebfc") + ", " + readable(c, "#ffffff", "#1c2944") + ")"
	return ":root[data-brand] {\n" +
		"  --accent: " + text + ";\n  --focus: " + text + ";\n" +
		"  --accent-solid: " + c + ";\n  --accent-solid-2: " + c + ";\n  --on-accent: #ffffff;\n" +
		"  --sk-accent: " + c + ";\n  --sk-accent-text: " + text + ";\n}\n"
}

// readable is c mixed toward `toward` in steps of 5% until it has a contrast of 4.5:1 with bg.
func readable(c, toward, bg string) string {
	for i := 0; i <= 20; i++ {
		m := mix(c, toward, float64(i)/20)
		if service.Contrast(m, bg) >= 4.5 {
			return m
		}
	}
	return toward
}

// mix is a + t·(b − a) per channel, of two #rrggbb colours.
func mix(a, b string, t float64) string {
	out := "#"
	for i := 1; i < 7; i += 2 {
		x, _ := strconv.ParseUint(a[i:i+2], 16, 8)
		y, _ := strconv.ParseUint(b[i:i+2], 16, 8)
		out += fmt.Sprintf("%02x", int(float64(x)+t*(float64(y)-float64(x))+0.5))
	}
	return out
}
