package service

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/skins"
	"github.com/paularlott/quisora/internal/store"
)

// SkinView is a skin as the management API shows it: a built-in one (compiled into the binary, not changed here) or a
// custom one (model.Skin). CSS is given to super admins only, one skin at a time (GetSkin).
type SkinView struct {
	Name        string     `json:"name"`
	DisplayName string     `json:"display_name"`
	Builtin     bool       `json:"builtin"`
	CSS         string     `json:"css,omitempty"`
	Updated     *time.Time `json:"updated,omitempty"`
}

// SkinInput adds a custom skin (CreateSkin: every field) or changes one (UpdateSkin: DisplayName and CSS, those given).
type SkinInput struct {
	Name        *string `json:"name"`
	DisplayName *string `json:"display_name"`
	CSS         *string `json:"css"`
}

func builtinView(b skins.Builtin, css bool) SkinView {
	v := SkinView{Name: b.Name, DisplayName: b.Title, Builtin: true}
	if css {
		v.CSS = string(b.CSS)
	}
	return v
}

func skinView(k *model.Skin, css bool) SkinView {
	upd := k.Updated
	v := SkinView{Name: k.ID, DisplayName: k.DisplayName, Updated: &upd}
	if css {
		v.CSS = k.CSS
	}
	return v
}

// canEditSkins: super admins, as people (a skin is a stylesheet on every page of the organizations that choose it).
func canEditSkins(a *Actor) bool { return a.IsSuper() && a.ClientID == "" }

// defaultView is Default (Quisora's own look, no skin) as the skins list shows it: built in, with its design tokens as
// the stylesheet to copy (skins.DefaultCSS).
func defaultView(css bool) SkinView {
	v := SkinView{Name: skins.Default, DisplayName: "Default", Builtin: true}
	if css {
		v.CSS = skins.DefaultCSS()
	}
	return v
}

// ListSkins lists the skins an organization may choose, Default and the built-in ones first, without their
// stylesheets: for super admins and organization administrators (who choose their organization's).
func (s *Service) ListSkins(ctx context.Context, a *Actor) ([]SkinView, error) {
	if !a.IsSuper() && !s.canAdminOrg(a, a.OrgID) {
		return nil, ErrForbidden
	}
	out := []SkinView{defaultView(false)}
	for _, b := range skins.Builtins() {
		out = append(out, builtinView(b, false))
	}
	list, _, err := s.Skins.List(ctx, store.ListQuery{Limit: 1000})
	if err != nil {
		return nil, mapStore(err)
	}
	slices.SortFunc(list, func(x, y *model.Skin) int {
		return cmp.Or(strings.Compare(strings.ToLower(x.DisplayName), strings.ToLower(y.DisplayName)), strings.Compare(x.ID, y.ID))
	})
	for _, k := range list {
		out = append(out, skinView(k, false))
	}
	return out, nil
}

// GetSkin returns a skin with its stylesheet: super admins.
func (s *Service) GetSkin(ctx context.Context, a *Actor, name string) (*SkinView, error) {
	if !a.IsSuper() {
		return nil, ErrForbidden
	}
	if name == skins.Default {
		v := defaultView(true)
		return &v, nil
	}
	if b, ok := skins.BuiltinNamed(name); ok {
		v := builtinView(b, true)
		return &v, nil
	}
	k, err := s.Skins.Get(ctx, name)
	if err != nil {
		return nil, mapStore(err)
	}
	v := skinView(k, true)
	return &v, nil
}

func checkSkinDisplayName(n string) (string, error) {
	n = strings.TrimSpace(n)
	if n == "" || utf8.RuneCountInString(n) > skins.MaxDisplayNameLen || strings.ContainsAny(n, "\r\n") {
		return "", Invalid("display_name", "1 to 60 characters, on one line")
	}
	return n, nil
}

// CreateSkin adds a custom skin: super admins. Its name is its id and never changes.
func (s *Service) CreateSkin(ctx context.Context, a *Actor, in SkinInput) (*SkinView, error) {
	if !canEditSkins(a) {
		return nil, ErrForbidden
	}
	if in.Name == nil || in.CSS == nil {
		return nil, Invalid("name", "a skin needs a name and a stylesheet")
	}
	name := strings.TrimSpace(*in.Name)
	if why := skins.NameError(name); why != "" {
		return nil, Invalid("name", why)
	}
	display := name
	if in.DisplayName != nil && strings.TrimSpace(*in.DisplayName) != "" {
		display = *in.DisplayName
	}
	display, err := checkSkinDisplayName(display)
	if err != nil {
		return nil, err
	}
	css := strings.ReplaceAll(*in.CSS, "\r\n", "\n")
	if why := skins.CSSError(name, css); why != "" {
		return nil, Invalid("css", why)
	}
	taken := Invalid("name", "a skin with this name already exists")
	if _, err := s.Skins.Get(ctx, name); err == nil {
		return nil, taken
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, mapStore(err)
	}
	k := &model.Skin{Meta: model.Meta{ID: name}, DisplayName: display, CSS: css, CSSVersion: skins.Version([]byte(css))}
	err = s.audited(ctx, a, "", "skin.create", name, map[string]string{"display_name": display}, func() error { return s.Skins.Create(ctx, k) })
	s.InvalidateSkins()
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrStale) {
		return nil, taken // added meanwhile
	}
	if err != nil {
		return nil, mapStore(err)
	}
	v := skinView(k, true)
	return &v, nil
}

// UpdateSkin changes a custom skin's display name or stylesheet: super admins. Built-in skins are not changed here.
func (s *Service) UpdateSkin(ctx context.Context, a *Actor, name string, in SkinInput) (*SkinView, error) {
	if !canEditSkins(a) {
		return nil, ErrForbidden
	}
	if _, ok := skins.BuiltinNamed(name); ok || name == skins.Default {
		return nil, Invalid("name", "a built-in skin cannot be changed: add a custom skin from a copy of it")
	}
	k, err := s.Skins.Get(ctx, name)
	if err != nil {
		return nil, mapStore(err)
	}
	if in.Name != nil && strings.TrimSpace(*in.Name) != name {
		return nil, Invalid("name", "a skin's name cannot change")
	}
	detail := map[string]string{}
	if in.DisplayName != nil {
		d, err := checkSkinDisplayName(*in.DisplayName)
		if err != nil {
			return nil, err
		}
		if d != k.DisplayName {
			detail["changed.display_name"] = k.DisplayName + " → " + d
			k.DisplayName = d
		}
	}
	if in.CSS != nil {
		css := strings.ReplaceAll(*in.CSS, "\r\n", "\n")
		if why := skins.CSSError(name, css); why != "" {
			return nil, Invalid("css", why)
		}
		if css != k.CSS {
			detail["changed.css"] = "changed"
			k.CSS, k.CSSVersion = css, skins.Version([]byte(css))
		}
	}
	if len(detail) == 0 {
		v := skinView(k, true)
		return &v, nil
	}
	err = s.audited(ctx, a, "", "skin.update", name, detail, func() error { return s.Skins.Update(ctx, k) })
	s.InvalidateSkins()
	if err != nil {
		return nil, mapStore(err)
	}
	v := skinView(k, true)
	return &v, nil
}

// DeleteSkin removes a custom skin: super admins. The organizations that chose it fall back to the primary
// organization's skin (or, for the primary organization, the built-in look) until they choose another.
func (s *Service) DeleteSkin(ctx context.Context, a *Actor, name string) error {
	if !canEditSkins(a) {
		return ErrForbidden
	}
	if _, ok := skins.BuiltinNamed(name); ok || name == skins.Default {
		return Invalid("name", "a built-in skin cannot be removed")
	}
	if _, err := s.Skins.Get(ctx, name); err != nil {
		return mapStore(err)
	}
	err := s.audited(ctx, a, "", "skin.delete", name, nil, func() error { return s.Skins.Delete(ctx, name) })
	s.InvalidateSkins()
	return mapStore(err)
}

// InvalidateSkins forgets the custom skins read (skin): call it when one changes, here or on another node.
func (s *Service) InvalidateSkins() { s.skinCache.Clear() }

// skin returns custom skin name (cached; nil when there is none), or the store's error.
func (s *Service) skin(ctx context.Context, name string) (*model.Skin, error) {
	if k, ok := s.skinCache.Get(name); ok {
		return k, nil
	}
	tok := s.skinCache.Token(name)
	k, err := s.Skins.Get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		k, err = nil, nil
	}
	if err != nil {
		return nil, mapStore(err)
	}
	s.skinCache.PutIf(name, k, tok)
	return k, nil
}

// SkinStylesheet returns skin name's stylesheet and its version (public: every page of an organization that chose it
// loads it): a built-in or custom skin, else ErrNotFound.
func (s *Service) SkinStylesheet(ctx context.Context, name string) ([]byte, string, error) {
	if b, ok := skins.BuiltinNamed(name); ok {
		return b.CSS, b.Version, nil
	}
	k, err := s.skin(ctx, name)
	if err != nil {
		return nil, "", err
	}
	if k == nil {
		return nil, "", ErrNotFound
	}
	return []byte(k.CSS), k.CSSVersion, nil
}

// SkinVersion returns the version of skin name's stylesheet, or "" when there is no such skin (or it cannot be read
// now: the page then shows the built-in look).
func (s *Service) SkinVersion(ctx context.Context, name string) string {
	if name == "" || name == skins.Default {
		return ""
	}
	_, v, err := s.SkinStylesheet(ctx, name)
	if err != nil {
		return ""
	}
	return v
}

// ResolveSkin returns the skin of organization o's pages and its version: its own choice, else the primary
// organization's, else none (""): a skin that is gone counts as none chosen. o may be nil (a page of no organization:
// the primary organization's).
func (s *Service) ResolveSkin(ctx context.Context, o *model.Org) (name, version string) {
	choice := ""
	if o != nil {
		choice = o.Branding.Skin
	}
	if choice != "" {
		if v := s.SkinVersion(ctx, choice); v != "" || choice == skins.Default {
			return skinOrNone(choice, v)
		}
	}
	if o != nil && o.Primary {
		return "", ""
	}
	id, err := s.PrimaryOrgID(ctx)
	if err != nil {
		return "", ""
	}
	p, err := s.Org(ctx, id)
	if err != nil || p.Branding.Skin == "" {
		return "", ""
	}
	return skinOrNone(p.Branding.Skin, s.SkinVersion(ctx, p.Branding.Skin))
}

func skinOrNone(name, version string) (string, string) {
	if name == skins.Default || version == "" {
		return "", ""
	}
	return name, version
}

// validSkinChoice checks an organization's skin choice (BrandingInput.Skin): "" (the primary organization's),
// skins.Default (the built-in look), or a skin there is.
func (s *Service) validSkinChoice(ctx context.Context, v *string) error {
	if v == nil {
		return nil
	}
	name := strings.TrimSpace(*v)
	if name == "" || name == skins.Default {
		return nil
	}
	if _, ok := skins.BuiltinNamed(name); ok {
		return nil
	}
	k, err := s.skin(ctx, name)
	if err != nil {
		return err
	}
	if k == nil {
		return Invalid("skin", "there is no skin "+name)
	}
	return nil
}
