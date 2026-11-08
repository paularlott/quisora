package web

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/skins"
)

// skinStylesheet serves a skin's stylesheet (GET /branding/skins/<name>.css): a built-in or custom skin. The pages name
// it with ?v=<version>, so a changed skin is a new address and this one may be kept.
func (s *Server) skinStylesheet(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutSuffix(r.PathValue("file"), ".css")
	if !ok {
		http.NotFound(w, r)
		return
	}
	css, _, err := s.Svc.SkinStylesheet(r.Context(), name)
	if errors.Is(err, service.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/css; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("v") != "" {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	_, _ = w.Write(css)
}

// SkinCSSPath is the address of skin name's stylesheet at version v.
func SkinCSSPath(name, v string) string { return "/branding/skins/" + name + ".css?v=" + v }

// withSkin sets the skin of a page of organization o: its own, else the primary organization's (service.ResolveSkin),
// or, for a preview, the skin named by the page's ?skin=: a skin there is, skins.Default (no skin) or skins.Inherit
// (the primary organization's, as an organization that has not chosen one).
func (s *Server) withSkin(ctx context.Context, st Site, o *model.Org, preview string) Site {
	name, v := s.Svc.ResolveSkin(ctx, o)
	switch {
	case preview == skins.Default:
		name, v = "", ""
	case preview == skins.Inherit:
		name, v = s.Svc.ResolveSkin(ctx, nil)
	case preview != "":
		if pv := s.Svc.SkinVersion(ctx, preview); pv != "" {
			name, v = preview, pv
		}
	}
	st.Skin, st.SkinCSS = name, ""
	if name != "" {
		st.SkinCSS = SkinCSSPath(name, v)
	}
	return st
}
