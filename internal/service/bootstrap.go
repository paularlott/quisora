package service

import (
	"context"
	"errors"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Bootstrap creates the primary organization (multi-factor sign-in required), its default tenant and its first super
// admin when they do not exist yet ("quisora bootstrap"; serving never creates them). The admin has no password: it
// returns an invitation link through which they set one (or create a passkey). Returns nil, "" when nothing was
// created. Each is a create guarded by a unique value (the primary organization's model.PrimaryOrgKey, the default
// tenant's name, the admin's email), so a second or concurrent run (several nodes of a shared database) makes no
// second one and overwrites nothing; one that stopped part-way is completed by the next.
func (s *Service) Bootstrap(ctx context.Context, adminEmail string) (*model.User, string, error) {
	org, err := s.PrimaryOrg(ctx)
	if errors.Is(err, ErrNotFound) {
		settings := model.DefaultOrgSettings()
		settings.RequireMFA = true // the first administrator always uses a second factor
		org = &model.Org{Name: "primary", DisplayName: "Primary", Settings: settings, Primary: true}
		if err := s.Orgs.Create(ctx, org); err != nil && !errors.Is(err, store.ErrConflict) {
			return nil, "", mapStore(err)
		}
		// A new store has no accounts from before the provider that set up their credentials was recorded: the pass
		// that marks those (MarkLegacySetUpBy) has nothing to do, and promotions need not judge accounts by its rule.
		if err := s.putLock(ctx, legacySetUpByID, "done", time.Now().AddDate(100, 0, 0)); err != nil {
			return nil, "", err
		}
		if org, err = s.PrimaryOrg(ctx); err != nil { // ours, or one created at the same moment elsewhere
			return nil, "", err
		}
	} else if err != nil {
		return nil, "", err
	}
	if _, err := s.DefaultTenant(ctx, org.ID); err != nil {
		return nil, "", err
	}
	// The first super admin, only into an organization without users: one that has any has had its first admin
	// (whatever their role now; "quisora invite --break-glass --super-admin" recovers a lost one).
	if n, err := s.Users.Count(ctx, org.ID); err != nil || n > 0 {
		return nil, "", mapStore(err)
	}
	if adminEmail == "" {
		adminEmail = "admin@example.com"
	}
	first := "Admin"
	u := &model.User{OrgID: org.ID, Role: model.RoleSuperAdmin, Active: true}
	if err := s.apply(ctx, u, UserInput{Email: &adminEmail, GivenName: &first}); err != nil {
		return nil, "", err
	}
	if err := s.AuditedUser(ctx, System, u, "bootstrap", nil, func() error { return s.Users.Create(ctx, u) }); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, "", nil // made elsewhere at the same moment
		}
		return nil, "", mapStore(err)
	}
	link, _, err := s.CreateInvite(ctx, System, u.ID)
	if err != nil {
		return nil, "", err
	}
	return u, link, nil
}
