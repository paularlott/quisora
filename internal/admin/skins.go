package admin

import (
	"net/http"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// listSkins lists the skins an organization may choose (GET /api/skins): super admins and organization administrators.
func (m *Module) listSkins(w http.ResponseWriter, r *http.Request) {
	l, err := m.s.Svc.ListSkins(r.Context(), web.Actor(r))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": l, "total": len(l)})
}

// getSkin returns a skin with its stylesheet (GET /api/skins/{name}): super admins.
func (m *Module) getSkin(w http.ResponseWriter, r *http.Request) {
	v, err := m.s.Svc.GetSkin(r.Context(), web.Actor(r), r.PathValue("name"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, v)
}

// createSkin adds a custom skin (POST /api/skins): super admins.
func (m *Module) createSkin(w http.ResponseWriter, r *http.Request) {
	var in service.SkinInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	v, err := m.s.Svc.CreateSkin(r.Context(), web.Actor(r), in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusCreated, v)
}

// updateSkin changes a custom skin's display name or stylesheet (PATCH /api/skins/{name}): super admins.
func (m *Module) updateSkin(w http.ResponseWriter, r *http.Request) {
	var in service.SkinInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	v, err := m.s.Svc.UpdateSkin(r.Context(), web.Actor(r), r.PathValue("name"), in)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, http.StatusOK, v)
}

// deleteSkin removes a custom skin (DELETE /api/skins/{name}): super admins.
func (m *Module) deleteSkin(w http.ResponseWriter, r *http.Request) {
	if err := m.s.Svc.DeleteSkin(r.Context(), web.Actor(r), r.PathValue("name")); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}
