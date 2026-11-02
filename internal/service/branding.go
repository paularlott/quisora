package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// MaxLogoBytes is the largest logo image accepted (each of the light and dark one).
const MaxLogoBytes = 256 << 10

// logoTypes are the image types a logo may be.
var logoTypes = []string{"image/png", "image/jpeg", "image/webp", "image/svg+xml"}

// BrandingInput changes an organization's branding (UpdateBranding), or gives a new one its own (OrgInput.Branding).
// A field left out stays as it is, and "" removes it. Logos are data: URIs (PNG, JPEG, WebP or SVG, at most
// MaxLogoBytes); the dark one is shown in the dark theme and needs a light one.
type BrandingInput struct {
	LogoLight    *string `json:"logo_light"`
	LogoDark     *string `json:"logo_dark"`
	PrimaryColor *string `json:"primary_color"`
}

// OrgLogo returns organization orgID's logo (ErrNotFound when it has none).
func (s *Service) OrgLogo(ctx context.Context, orgID string) (*model.OrgLogo, error) {
	l, err := s.OrgLogos.Get(ctx, orgID)
	return l, mapStore(err)
}

// UpdateBranding changes organization orgID's logo and primary colour: its admins and the super admins, never a
// service account (it may give an organization it creates its branding, OrgInput.Branding; changes are a person's).
func (s *Service) UpdateBranding(ctx context.Context, a *Actor, orgID string, in BrandingInput) (*model.Org, error) {
	if !s.canAdminOrg(a, orgID) || a.ClientID != "" {
		return nil, ErrForbidden
	}
	o, err := s.Orgs.Get(ctx, orgID)
	if err != nil {
		return nil, mapStore(err)
	}
	logo, err := s.OrgLogos.Get(ctx, orgID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, mapStore(err)
	}
	was, wasLogo := snapshot(o), o.Branding.Logo
	if logo, err = applyBranding(o, logo, in); err != nil {
		return nil, err
	}
	detail := addChanges(nil, was, o)
	if o.Branding.Logo != wasLogo {
		if detail == nil {
			detail = map[string]string{}
		}
		detail["changed.logo"] = "new"
		if o.Branding.Logo == "" {
			detail["changed.logo"] = "removed"
		}
		if err := s.writeLogo(ctx, orgID, logo); err != nil {
			return nil, err
		}
	}
	err = s.audited(ctx, a, o.ID, "org.branding", o.Name, detail, func() error { return s.Orgs.Update(ctx, o) })
	s.InvalidateOrgs() // the pages show it at once here (also after a write that may have landed)
	if err != nil {
		return nil, mapStore(err)
	}
	return o, nil
}

// writeLogo stores organization orgID's logo, or removes it (nil). A logo read from the store is updated (unless
// changed since); one that is not there is created, also over a logo removed earlier (which a Put may not replace).
func (s *Service) writeLogo(ctx context.Context, orgID string, logo *model.OrgLogo) error {
	if logo == nil {
		if err := s.OrgLogos.Delete(ctx, orgID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return mapStore(err)
		}
		return nil
	}
	logo.ID = orgID
	if logo.Version == 0 {
		return mapStore(s.OrgLogos.Create(ctx, logo))
	}
	return mapStore(s.OrgLogos.Update(ctx, logo))
}

// applyBranding applies in to o's branding and its logo (nil: none), and returns the logo as it is now (nil: none).
// Nothing is changed when in is refused.
func applyBranding(o *model.Org, logo *model.OrgLogo, in BrandingInput) (*model.OrgLogo, error) {
	b := o.Branding
	if in.PrimaryColor != nil {
		c, err := primaryColor(*in.PrimaryColor)
		if err != nil {
			return nil, err
		}
		b.PrimaryColor = c
	}
	next := model.OrgLogo{}
	if logo != nil {
		next = *logo
	}
	for _, f := range []struct {
		field string
		in    *string
		body  *[]byte
		typ   *string
	}{{"logo_light", in.LogoLight, &next.Light, &next.LightType}, {"logo_dark", in.LogoDark, &next.Dark, &next.DarkType}} {
		if f.in == nil {
			continue
		}
		body, typ, err := logoImage(*f.in)
		if err != nil {
			return nil, Invalid(f.field, err.Error())
		}
		*f.body, *f.typ = body, typ
	}
	if len(next.Light) == 0 && len(next.Dark) > 0 {
		if in.LogoLight != nil { // the light one removed: the dark one goes with it
			next.Dark, next.DarkType = nil, ""
		} else {
			return nil, Invalid("logo_dark", "add a light logo first: the dark one is shown in the dark theme instead of it")
		}
	}
	b.Logo, b.LogoDark = "", len(next.Dark) > 0
	if len(next.Light) > 0 {
		h := sha256.New()
		for _, part := range [][]byte{[]byte(next.LightType), next.Light, []byte(next.DarkType), next.Dark} {
			h.Write([]byte(strconv.Itoa(len(part)) + ":"))
			h.Write(part)
		}
		b.Logo = hex.EncodeToString(h.Sum(nil))[:16]
	}
	o.Branding = b
	if b.Logo == "" {
		return nil, nil
	}
	return &next, nil
}

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// primaryColor checks a primary colour (#rrggbb; "" for the server's): buttons carry white text on it, which must
// keep a contrast of 4.5:1 at least (WCAG 2.2 AA).
func primaryColor(c string) (string, error) {
	c = strings.ToLower(strings.TrimSpace(c))
	if c == "" {
		return "", nil
	}
	if !hexColor.MatchString(c) {
		return "", Invalid("primary_color", "use a colour such as #1d4ed8")
	}
	if r := Contrast(c, "#ffffff"); r < 4.5 {
		return "", Invalid("primary_color", fmt.Sprintf("too light: white text on it has a contrast of %.1f:1, and needs "+
			"4.5:1; choose a darker colour", math.Floor(r*10)/10))
	}
	return c, nil
}

// logoImage decodes a logo given as a data: URI ("" for none) and checks that it is an image of an allowed type that
// is what the URI says, of at most MaxLogoBytes.
func logoImage(uri string) ([]byte, string, error) {
	if uri == "" {
		return nil, "", nil
	}
	rest, ok := strings.CutPrefix(uri, "data:")
	typ, data, ok2 := strings.Cut(rest, ";base64,")
	if !ok || !ok2 {
		return nil, "", errors.New("give the image as a data: URI (data:image/png;base64,...)")
	}
	typ = strings.ToLower(typ)
	if !slices.Contains(logoTypes, typ) {
		return nil, "", errors.New("use a PNG, JPEG, WebP or SVG image")
	}
	if base64.StdEncoding.DecodedLen(len(data)) > MaxLogoBytes+3 {
		return nil, "", fmt.Errorf("the image is larger than %d KB", MaxLogoBytes>>10)
	}
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, "", errors.New("the image is not valid base64")
	}
	if len(b) > MaxLogoBytes {
		return nil, "", fmt.Errorf("the image is larger than %d KB", MaxLogoBytes>>10)
	}
	if typ == "image/svg+xml" && !isSVG(b) || typ != "image/svg+xml" && http.DetectContentType(b) != typ {
		return nil, "", errors.New("the image is not the type it says it is")
	}
	return b, typ, nil
}

// isSVG reports whether b is an XML document whose root element is <svg>.
func isSVG(b []byte) bool {
	d := xml.NewDecoder(bytes.NewReader(b))
	for {
		t, err := d.Token()
		if err != nil {
			return false
		}
		if el, ok := t.(xml.StartElement); ok {
			return el.Name.Local == "svg"
		}
	}
}

// Contrast is the WCAG contrast ratio of two #rrggbb colours (1 to 21).
func Contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
}

// luminance is the WCAG relative luminance of a #rrggbb colour.
func luminance(c string) float64 {
	var rgb [3]float64
	for i := range rgb {
		v, _ := strconv.ParseUint(c[1+2*i:3+2*i], 16, 8)
		s := float64(v) / 255
		if s <= 0.04045 {
			rgb[i] = s / 12.92
		} else {
			rgb[i] = math.Pow((s+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*rgb[0] + 0.7152*rgb[1] + 0.0722*rgb[2]
}
