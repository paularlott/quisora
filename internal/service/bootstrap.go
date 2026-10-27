package service

import (
	"context"
	"errors"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Kept for callers that name them through this package.
const (
	PrimaryOrgID     = model.PrimaryOrgID
	BootstrapAdminID = model.BootstrapAdminID
)

// Bootstrap creates the primary organization (multi-factor sign-in required), its default tenant and its first super
// admin when they do not exist yet ("quisora bootstrap"; serving never creates them). The admin has no password: it
// returns an invitation link through which they set one (or create a passkey). Returns nil, "" when nothing was
// created. Everything is written create-only, with fixed ids and the oldest possible version (model.PrimaryOrgID):
// whatever already exists in the store wins, so a mistaken run
// cannot overwrite anything.
func (s *Service) Bootstrap(ctx context.Context, adminEmail string) (*model.User, string, error) {
	now := time.Now().UTC()
	org, err := s.PrimaryOrg(ctx)
	if errors.Is(err, ErrNotFound) {
		settings := model.DefaultOrgSettings()
		settings.RequireMFA = true // the first administrator always uses a second factor
		org = &model.Org{Name: "primary", DisplayName: "Primary", Primary: true, Settings: settings}
		if err := s.createBootstrap(ctx, org, model.PrimaryOrgID, now); err != nil && !errors.Is(err, errExists) {
			return nil, "", err
		}
		if org, err = s.PrimaryOrg(ctx); err != nil { // ours, or one created at the same moment elsewhere
			return nil, "", err
		}
	} else if err != nil {
		return nil, "", err
	}
	if org.ID == model.PrimaryOrgID {
		t := &model.Tenant{OrgID: org.ID, Name: model.DefaultTenantName, DisplayName: "Default", Settings: model.DefaultTenantSettings()}
		if err := s.createBootstrap(ctx, t, model.PrimaryTenantID, now); err != nil && !errors.Is(err, errExists) {
			return nil, "", err
		}
	}
	if _, err := s.DefaultTenant(ctx, org.ID); err != nil {
		return nil, "", err
	}
	// The first super admin, unless the organization already has one (any super admin, the bootstrap one or later).
	supers, _, err := s.Users.List(ctx, store.ListQuery{Scope: org.ID,
		Filters: []store.Filter{{Field: "role", Value: string(model.RoleSuperAdmin)}}, Limit: 1})
	if err != nil {
		return nil, "", mapStore(err)
	}
	if len(supers) > 0 {
		return nil, "", nil
	}
	if _, err := s.Users.Get(ctx, model.BootstrapAdminID); err == nil {
		return nil, "", nil // exists (no longer a super admin): it is not made again
	}
	if adminEmail == "" {
		adminEmail = "admin@example.com"
	}
	first := "Admin"
	u := &model.User{OrgID: org.ID, Role: model.RoleSuperAdmin, Active: true}
	if err := s.apply(ctx, u, UserInput{Email: &adminEmail, GivenName: &first}); err != nil {
		return nil, "", err
	}
	if err := s.audited(ctx, System, org.ID, "bootstrap", u.Username, nil, func() error {
		return s.createBootstrap(ctx, u, model.BootstrapAdminID, now)
	}); err != nil {
		if errors.Is(err, errExists) {
			return nil, "", nil // made elsewhere at the same moment
		}
		return nil, "", err
	}
	link, _, err := s.CreateInvite(ctx, System, u.ID)
	if err != nil {
		return nil, "", err
	}
	return u, link, nil
}

var errExists = errors.New("already exists")

// createBootstrap writes e with id only when no record with that id exists (a create: the store refuses it over one).
func (s *Service) createBootstrap(ctx context.Context, e model.Entity, id string, now time.Time) error {
	m := e.GetMeta()
	m.ID, m.Created, m.Updated = id, now, now
	rec, err := store.Encode(e)
	if err != nil {
		return err
	}
	if _, err := s.Store.Get(ctx, rec.Kind, id); err == nil {
		return errExists
	}
	if err := s.Store.CompareAndPut(ctx, rec, 0); err != nil {
		if errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrConflict) {
			return errExists
		}
		return mapStore(err)
	}
	m.Version = rec.Version // as the store stamped it: the caller's next compare-and-swap is on it
	return nil
}
