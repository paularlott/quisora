package service

import (
	"context"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
)

// An organization's password, lockout and API token policy: its own setting (model.OrgSettings), else the server's.
// o may be nil (an organization that could not be read): the server's then.

// PasswordMinLength is the shortest password organization o accepts: its own, else limits.password_min_length.
func (s *Service) PasswordMinLength(o *model.Org) int {
	if o != nil && o.Settings.PasswordMinLength > 0 {
		return o.Settings.PasswordMinLength
	}
	return s.Cfg.Limits.PasswordMinLength
}

// Lockout is how many wrong credentials lock an account of organization o (0: never) and for how long: its own,
// else limits.lockout_attempts and limits.lockout_minutes.
func (s *Service) Lockout(o *model.Org) (attempts int, window time.Duration) {
	attempts, mins := s.Cfg.Limits.LockoutAttempts, s.Cfg.Limits.LockoutMinutes
	if o != nil && o.Settings.LockoutAttempts > 0 {
		attempts = o.Settings.LockoutAttempts
	}
	if o != nil && o.Settings.LockoutMinutes > 0 {
		mins = o.Settings.LockoutMinutes
	}
	if mins <= 0 {
		mins = 15
	}
	return attempts, time.Duration(mins) * time.Minute
}

// APITokenMaxDays is the longest lifetime of a personal API token of organization o, in days (0: no limit): its own
// (model.APITokensNoLimit: none), else tokens.api_token_max_days.
func (s *Service) APITokenMaxDays(o *model.Org) int {
	if o != nil && o.Settings.APITokenMaxDays == model.APITokensNoLimit {
		return 0
	}
	if o != nil && o.Settings.APITokenMaxDays > 0 {
		return o.Settings.APITokenMaxDays
	}
	return s.Cfg.Tokens.APITokenMaxDays
}

// GrantsPerUser is how many refresh grants a user of organization o may hold: its own, else limits.grants_per_user.
func (s *Service) GrantsPerUser(o *model.Org) int {
	if o != nil && o.Settings.GrantsPerUser > 0 {
		return o.Settings.GrantsPerUser
	}
	return s.Cfg.Limits.GrantsPerUser
}

// OrgPolicy returns organization id as stored now, for its policy: not the cached copy (Org), so a policy just changed
// applies at once. A read that fails is an error, never the server's policy in its place: an organization stricter
// than the server (a longer password, a shorter token, a higher cap of grants) must not be judged by the server's
// defaults because its record could not be read. The server's apply only where the organization was read and sets
// none, or where there is no organization (id ""): nil, nil.
func (s *Service) OrgPolicy(ctx context.Context, id string) (*model.Org, error) {
	if id == "" {
		return nil, nil
	}
	o, err := s.Orgs.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	return o, nil
}

// Bounds of an organization's own policy (validOrgSettings).
const (
	maxLockoutAttempts = 100
	maxLockoutMinutes  = 1440
)

// validOrgPolicy checks an organization's own password, lockout, API token and privileged session policy: each 0
// (the server's) or within bounds; the privileged session lengths no longer than the server's session.ttl and
// session.idle, as the organization's other session lengths (a value saved before is not held to a lowered limit).
func (s *Service) validOrgPolicy(st model.OrgSettings, old *model.OrgSettings) error {
	in := func(field string, v, lo, hi int) error {
		if v != 0 && (v < lo || v > hi) {
			return Invalid(field, "must be between "+itoa(lo)+" and "+itoa(hi)+", or empty for the server's")
		}
		return nil
	}
	if st.APITokenMaxDays == model.APITokensNoLimit {
		st.APITokenMaxDays = 0 // no limit: checked
	} else if st.APITokenMaxDays < 0 {
		return Invalid("api_token_max_days", "must be between 1 and "+itoa(maxTokenDays)+", -1 for no limit, or empty for the server's")
	}
	for _, c := range []struct {
		field     string
		v, lo, hi int
	}{
		{"password_min_length", st.PasswordMinLength, 8, 64},
		{"lockout_attempts", st.LockoutAttempts, 1, maxLockoutAttempts},
		{"lockout_minutes", st.LockoutMinutes, 1, maxLockoutMinutes},
		{"api_token_max_days", st.APITokenMaxDays, 1, maxTokenDays},
		{"grants_per_user", st.GrantsPerUser, config.MinGrantsPerUser, config.MaxGrantsPerUser},
	} {
		if err := in(c.field, c.v, c.lo, c.hi); err != nil {
			return err
		}
	}
	if st.PrivilegedTTL < 0 || st.PrivilegedIdle < 0 {
		return Invalid("settings", "lifetimes cannot be negative")
	}
	if st.PrivilegedTTL > s.Cfg.Session.TTL && (old == nil || st.PrivilegedTTL != old.PrivilegedTTL) {
		return Invalid("privileged_ttl", "at most "+itoa(s.Cfg.Session.TTL)+" seconds (the server's session.ttl)")
	}
	if s.Cfg.Session.Idle > 0 && st.PrivilegedIdle > s.Cfg.Session.Idle && (old == nil || st.PrivilegedIdle != old.PrivilegedIdle) {
		return Invalid("privileged_idle", "at most "+itoa(s.Cfg.Session.Idle)+" seconds (the server's session.idle)")
	}
	return nil
}
