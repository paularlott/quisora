package admin

import (
	"net/http"

	"github.com/paularlott/quisora/internal/build"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// systemView is the server overview (GET /api/system) for the system page.
type systemView struct {
	Version           string              `json:"version"`
	Organizations     int                 `json:"organizations"`
	Users             int                 `json:"users"`
	Sessions          int                 `json:"sessions"` // browser sessions not yet removed (some may have expired)
	Clustered         bool                `json:"clustered"`
	KeyRotationDays   int                 `json:"key_rotation_days"`
	MasterKeyRotation bool                `json:"master_key_rotation"` // previous master keys are configured
	LastSignOut       *model.SignOutEvent `json:"last_sign_out,omitempty"`
}

// systemStatus handles GET /api/system: the server as a whole. Super admins only.
func (m *Module) systemStatus(w http.ResponseWriter, r *http.Request) {
	if !web.Actor(r).IsSuper() {
		web.WriteError(w, service.ErrForbidden)
		return
	}
	svc, ctx := m.s.Svc, r.Context()
	v := systemView{Version: build.Version, Clustered: m.s.Site.Clustered, KeyRotationDays: m.s.Cfg.Tokens.KeyRotationDays,
		MasterKeyRotation: svc.Sealer.Previous()}
	var err error
	if v.Organizations, err = svc.Orgs.Count(ctx, ""); err != nil {
		web.WriteError(w, err)
		return
	}
	if v.Users, err = svc.Users.Count(ctx, ""); err != nil {
		web.WriteError(w, err)
		return
	}
	if v.Sessions, err = svc.Sessions.Count(ctx, ""); err != nil {
		web.WriteError(w, err)
		return
	}
	if p, err := svc.PrimaryOrg(ctx); err == nil {
		v.LastSignOut = p.LastServerSignOut
	}
	web.WriteJSON(w, http.StatusOK, v)
}
