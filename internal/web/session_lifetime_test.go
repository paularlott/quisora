package web

import (
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A session lives as long as its organization says, never longer than the server allows, and for managers and above
// never longer than the privileged limits.
func TestSessionLifetime(t *testing.T) {
	cfg := config.Default()
	cfg.Session.TTL, cfg.Session.Idle, cfg.Session.PrivilegedTTL, cfg.Session.PrivilegedIdle = 7*86400, 86400, 12*3600, 3600
	m := &Sessions{svc: &service.Service{Cfg: cfg}}
	user, admin := &model.User{Role: model.RoleUser}, &model.User{Role: model.RoleAdmin}
	org := func(ttl, idle int) *model.Org {
		return &model.Org{Settings: model.OrgSettings{SessionTTL: ttl, SessionIdle: idle}}
	}
	for _, tc := range []struct {
		name      string
		org       *model.Org
		u         *model.User
		ttl, idle int
	}{
		{"server defaults", org(0, 0), user, 7 * 86400, 86400},
		{"shorter org", org(3600, 600), user, 3600, 600},
		{"org above the server is capped", org(30*86400, 7*86400), user, 7 * 86400, 86400},
		{"privileged", org(0, 0), admin, 12 * 3600, 3600},
		{"privileged under a shorter org", org(1800, 300), admin, 1800, 300},
	} {
		if ttl, idle := m.lifetime(tc.org, tc.u); ttl != tc.ttl || idle != tc.idle {
			t.Errorf("%s: %d/%d, want %d/%d", tc.name, ttl, idle, tc.ttl, tc.idle)
		}
	}
}
