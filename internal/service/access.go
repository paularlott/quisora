package service

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Tenant access: which users and groups may sign in to a tenant's applications (when the tenant is members-only),
// and the application roles and tags they carry there.

// AccessInput is the editable part of a TenantAccess. On create SubjectType and SubjectID are required; on update
// they are ignored (delete and add again to change who it is for). Nil leaves a field unchanged.
type AccessInput struct {
	SubjectType string    `json:"subject_type"`
	SubjectID   string    `json:"subject_id"`
	Roles       *[]string `json:"roles"`
	Tags        *[]string `json:"tags"`
	// AuthorizationDetails are RFC 9396 authorization details for the access tokens of the applications registered
	// for their types (model.NormAuthDetails); [] removes them.
	AuthorizationDetails *json.RawMessage `json:"authorization_details"`
	AllClients           *bool            `json:"all_clients"`
	Clients              *[]string        `json:"clients"`
	// Expires is when the access ends: an RFC 3339 time with its offset (2026-11-17T15:00:00+08:00, or Z for UTC),
	// stored in UTC; "" for no end. A new end must be in the future: to end access now, remove it.
	Expires *string `json:"expires"`
	// Reason is why the access was given or changed (a ticket number, an approval), recorded in the audit log only.
	Reason *string `json:"reason"`
}

// maxAccessReason bounds AccessInput.Reason.
const maxAccessReason = 500

// AccessEntry is a TenantAccess with the subject resolved for display.
type AccessEntry struct {
	*model.TenantAccess
	Name    string `json:"name"`             // the user's full name or the group's name ("" when it no longer exists)
	Detail  string `json:"detail,omitempty"` // the user's email address
	Expired bool   `json:"expired"`
}

// withDefaults copies t's access defaults into acc, a new entry: a snapshot, so a later change of the defaults
// changes no entry.
func withDefaults(acc *model.TenantAccess, t *model.Tenant) {
	if d := t.AccessDefaults; d != nil {
		acc.Roles, acc.Tags = slices.Clone(d.Roles), slices.Clone(d.Tags)
		acc.AuthorizationDetails = slices.Clone(d.AuthorizationDetails)
	}
}

// MaxRoles is the most application roles one access may carry.
const MaxRoles = 50

// applyRoles validates role names (the same characters as tags) and stores them normalized.
func applyRoles(dst *[]string, in *[]string) error {
	if in == nil {
		return nil
	}
	for _, r := range *in {
		if !model.ValidTag(r) {
			return Invalid("roles", strconv.Quote(r)+" is not a valid role: use letters, digits and . _ : / - "+
				"(1–64 characters, starting and ending with a letter or digit)")
		}
	}
	out := model.NormTags(*in)
	if len(out) > MaxRoles {
		return Invalid("roles", "at most "+itoa(MaxRoles)+" roles are allowed")
	}
	*dst = out
	return nil
}

// applyAuthDetails validates authorization details and stores them normalized (model.NormAuthDetails).
func applyAuthDetails(dst *json.RawMessage, in *json.RawMessage) error {
	if in == nil {
		return nil
	}
	ad, err := model.NormAuthDetails(*in)
	if err != nil {
		return Invalid("authorization_details", err.Error())
	}
	*dst = ad
	return nil
}

func (s *Service) applyAccess(ctx context.Context, t *model.Tenant, acc *model.TenantAccess, in AccessInput) error {
	if err := applyRoles(&acc.Roles, in.Roles); err != nil {
		return err
	}
	if err := applyTags(&acc.Tags, in.Tags); err != nil {
		return err
	}
	if err := applyAuthDetails(&acc.AuthorizationDetails, in.AuthorizationDetails); err != nil {
		return err
	}
	if in.AllClients != nil {
		acc.AllClients = *in.AllClients
	}
	if in.Clients != nil {
		ids := []string{}
		for _, id := range *in.Clients {
			c, err := s.Clients.Get(ctx, id)
			if err != nil || c.OrgID != t.OrgID || c.TenantID != t.ID {
				return Invalid("clients", "unknown client "+id+" for this tenant")
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		acc.Clients = ids
	}
	if acc.AllClients {
		acc.Clients = nil
	} else if len(acc.Clients) == 0 {
		return Invalid("clients", "choose at least one application, or allow all of them")
	}
	if in.Expires != nil {
		end, err := parseAccessEnd(*in.Expires)
		if err != nil {
			return err
		}
		// An end being set must be ahead: one already passed would give nothing, and the sweep would remove the
		// entry at once. An end unchanged (an edit of something else of an entry the sweep has not removed yet) is
		// kept as it is.
		if !end.IsZero() && !end.Equal(acc.Expires) && !end.After(time.Now()) {
			return Invalid("expires", "must be in the future: to end access now, remove it")
		}
		acc.Expires = end
	}
	if in.Reason != nil && len(*in.Reason) > maxAccessReason {
		return Invalid("reason", "at most "+itoa(maxAccessReason)+" characters")
	}
	return nil
}

// parseAccessEnd reads an access entry's end (AccessInput.Expires): an RFC 3339 time, which always names its offset,
// so the instant is never a guess about the caller's time zone; returned in UTC, to the second. "" is no end.
func parseAccessEnd(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, Invalid("expires", "use an RFC 3339 time with its offset, such as 2026-11-17T15:00:00+08:00 "+
			"or 2026-11-17T07:00:00Z, or leave it empty for no end")
	}
	if t.Year() > 9999 || t.Year() < 2000 {
		return time.Time{}, Invalid("expires", "out of range")
	}
	return t.UTC().Truncate(time.Second), nil
}

// accessAudit is the audit detail of a change of an access entry: who it is for, its end (UTC) and the reason given.
func accessAudit(subjectType, name string, acc *model.TenantAccess, in AccessInput) map[string]string {
	d := map[string]string{subjectType: name}
	if !acc.Expires.IsZero() {
		d["expires"] = acc.Expires.UTC().Format(time.RFC3339)
	}
	if in.Reason != nil {
		if r := strings.TrimSpace(*in.Reason); r != "" {
			d["reason"] = r
		}
	}
	return d
}

// accessSubject resolves the user or group an access is for, within the tenant's org.
func (s *Service) accessSubject(ctx context.Context, a *Actor, orgID, typ, id string) (name, detail string, err error) {
	switch typ {
	case model.SubjectUser:
		u, err := s.Users.Get(ctx, id)
		if err != nil || u.OrgID != orgID || s.Visibility(a, u) == Hidden {
			return "", "", Invalid("subject_id", "unknown user") // a super admin is unknown below them
		}
		return u.FullName(), u.Email, nil
	case model.SubjectGroup:
		g, err := s.Groups.Get(ctx, id)
		if err != nil || g.OrgID != orgID {
			return "", "", Invalid("subject_id", "unknown group")
		}
		return g.DisplayName, "", nil
	}
	return "", "", Invalid("subject_type", "must be user or group")
}

// ListAccess lists who has access to a tenant, with names resolved. Search matches the name and email address; sort
// is "name" (default), "type", "expires" or "created". Tenants hold at most a few thousand entries, so the list is
// filtered and paged in memory after one indexed read.
func (s *Service) ListAccess(ctx context.Context, a *Actor, tenantID string, q store.ListQuery) ([]*AccessEntry, int, error) {
	t, err := s.GetTenant(ctx, a, tenantID)
	if err != nil {
		return nil, 0, err
	}
	all, _, err := s.Access.List(ctx, store.ListQuery{Scope: t.OrgID, Filters: []store.Filter{{Field: "tenant_id", Value: t.ID}}})
	if err != nil {
		return nil, 0, mapStore(err)
	}
	now := time.Now()
	search := strings.ToLower(strings.TrimSpace(q.Search))
	out := make([]*AccessEntry, 0, len(all))
	for _, acc := range all {
		if acc.SubjectType == model.SubjectUser && s.hiddenSubject(ctx, a, acc.SubjectID) {
			continue // a super admin's access is not listed below them
		}
		e := &AccessEntry{TenantAccess: acc, Expired: !acc.Live(now)}
		var serr error
		if e.Name, e.Detail, serr = s.accessSubject(ctx, a, t.OrgID, acc.SubjectType, acc.SubjectID); serr != nil {
			continue // its user or group was deleted: it counts for nothing (the orphan sweep removes it)
		}
		if search != "" && !strings.Contains(strings.ToLower(e.Name), search) && !strings.Contains(strings.ToLower(e.Detail), search) {
			continue
		}
		if acc.Clients == nil {
			acc.Clients = []string{}
		}
		out = append(out, e)
	}
	less := func(x, y *AccessEntry) bool { return strings.ToLower(x.Name) < strings.ToLower(y.Name) }
	switch q.Sort {
	case "type":
		less = func(x, y *AccessEntry) bool {
			if x.SubjectType != y.SubjectType {
				return x.SubjectType > y.SubjectType // users first
			}
			return strings.ToLower(x.Name) < strings.ToLower(y.Name)
		}
	case "expires":
		less = func(x, y *AccessEntry) bool { // no end sorts last
			if x.Expires.IsZero() != y.Expires.IsZero() {
				return !x.Expires.IsZero()
			}
			return x.Expires.Before(y.Expires)
		}
	case "created":
		less = func(x, y *AccessEntry) bool { return x.Created.Before(y.Created) }
	case "", "name":
	default:
		return nil, 0, Invalid("sort", "cannot sort by "+q.Sort)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if q.Desc {
			return less(out[j], out[i])
		}
		return less(out[i], out[j])
	})
	total := len(out)
	if q.Offset > 0 {
		if q.Offset >= len(out) {
			out = out[:0]
		} else {
			out = out[q.Offset:]
		}
	}
	if q.Limit > 0 && q.Limit < len(out) {
		out = out[:q.Limit]
	}
	return out, total, nil
}

// GetAccess returns one access entry of a tenant.
func (s *Service) GetAccess(ctx context.Context, a *Actor, tenantID, id string) (*AccessEntry, error) {
	t, err := s.GetTenant(ctx, a, tenantID)
	if err != nil {
		return nil, err
	}
	acc, err := s.Access.Get(ctx, id)
	if err != nil || acc.TenantID != t.ID {
		return nil, ErrNotFound
	}
	if acc.SubjectType == model.SubjectUser && s.hiddenSubject(ctx, a, acc.SubjectID) {
		return nil, ErrNotFound // nor read, changed or removed: a super admin's access, below them
	}
	e := &AccessEntry{TenantAccess: acc, Expired: !acc.Live(time.Now())}
	e.Name, e.Detail, _ = s.accessSubject(ctx, a, t.OrgID, acc.SubjectType, acc.SubjectID)
	return e, nil
}

// hiddenSubject reports whether the user with id exists but a may not see them.
func (s *Service) hiddenSubject(ctx context.Context, a *Actor, id string) bool {
	u, err := s.Users.Get(ctx, id)
	return err == nil && s.Visibility(a, u) == Hidden
}

// AddAccess gives a user or group access to a tenant.
func (s *Service) AddAccess(ctx context.Context, a *Actor, tenantID string, in AccessInput) (*AccessEntry, error) {
	t, err := s.GetTenant(ctx, a, tenantID)
	if err != nil {
		return nil, err
	}
	name, detail, err := s.accessSubject(ctx, a, t.OrgID, in.SubjectType, in.SubjectID)
	if err != nil {
		return nil, err
	}
	acc := &model.TenantAccess{OrgID: t.OrgID, TenantID: t.ID, SubjectType: in.SubjectType, SubjectID: in.SubjectID,
		AllClients: true}
	withDefaults(acc, t) // a field given below replaces its default
	acc.ID = model.AccessID(t.ID, in.SubjectID)
	if err := s.applyAccess(ctx, t, acc, in); err != nil {
		return nil, err
	}
	// The id is deterministic, so a removed entry leaves a tombstone: adding it again is a create, which starts a new
	// generation of the record whose epoch is the removal this node has seen (a plain put over the tombstone is
	// refused: store.ErrDeleted). A removal made elsewhere that this node had not seen yet still wins: the add is then
	// refused (ErrDeleted from the owner), reported as a concurrent change to retry.
	alreadyThere := &conflictErr{Invalid("subject_id", name+" already has access to this tenant")}
	if _, err := s.Access.Get(ctx, acc.ID); err == nil {
		return nil, alreadyThere
	}
	if err := s.audited(ctx, a, t.OrgID, "tenant.access.add", t.Name, accessAudit(in.SubjectType, name, acc, in),
		func() error { return s.Access.Create(ctx, acc) }); err != nil {
		if errors.Is(err, store.ErrStale) {
			return nil, alreadyThere // added concurrently
		}
		if errors.Is(err, store.ErrDeleted) {
			return nil, ErrStale
		}
		return nil, mapStore(err)
	}
	return &AccessEntry{TenantAccess: acc, Name: name, Detail: detail, Expired: !acc.Live(time.Now())}, nil
}

// UpdateAccess changes the roles, tags, authorization details, applications or end of an access.
func (s *Service) UpdateAccess(ctx context.Context, a *Actor, tenantID, id string, in AccessInput) (*AccessEntry, error) {
	e, err := s.GetAccess(ctx, a, tenantID, id)
	if err != nil {
		return nil, err
	}
	t, err := s.Tenants.Get(ctx, e.TenantID)
	if err != nil {
		return nil, mapStore(err)
	}
	before := *e.TenantAccess
	before.Clients = slices.Clone(before.Clients)
	if err := s.applyAccess(ctx, t, e.TenantAccess, in); err != nil {
		return nil, err
	}
	if err := s.audited(ctx, a, t.OrgID, "tenant.access.update", t.Name, accessAudit(e.SubjectType, e.Name, e.TenantAccess, in),
		func() error { return s.Access.Update(ctx, e.TenantAccess) }); err != nil {
		return nil, mapStore(err)
	}
	if narrower(&before, e.TenantAccess) {
		s.endLostAccessLater(ctx, t, &before)
	}
	e.Expired = !e.Live(time.Now())
	return e, nil
}

// narrower reports whether access entry after gives less than before did: fewer applications, or an end where there
// was none or an earlier one. The people it let in may then have lost an application (endLostAccess).
func narrower(before, after *model.TenantAccess) bool {
	if before.AllClients && !after.AllClients {
		return true
	}
	if !before.AllClients {
		for _, c := range before.Clients {
			if !after.AllClients && !slices.Contains(after.Clients, c) {
				return true
			}
		}
	}
	return !after.Expires.IsZero() && (before.Expires.IsZero() || after.Expires.Before(before.Expires))
}

// RemoveAccess takes a user's or group's access away.
func (s *Service) RemoveAccess(ctx context.Context, a *Actor, tenantID, id string) error {
	e, err := s.GetAccess(ctx, a, tenantID, id)
	if err != nil {
		return err
	}
	name := e.TenantID
	if t, _ := s.Tenants.Get(ctx, e.TenantID); t != nil {
		name = t.Name
	}
	if err := s.audited(ctx, a, e.OrgID, "tenant.access.remove", name, map[string]string{e.SubjectType: e.Name},
		func() error { return s.Access.Delete(ctx, id) }); err != nil {
		return mapStore(err)
	}
	if t, err := s.Tenants.Get(ctx, e.TenantID); err == nil {
		s.endLostAccessLater(ctx, t, e.TenantAccess)
	}
	return nil
}

// AppAccess is what a user gets for one application: whether they may sign in to it, and the roles, tags and
// authorization details (placeholders filled in, duplicates dropped) that their live access entries for it carry.
type AppAccess struct {
	Allowed bool
	Roles   []string
	Tags    []string
	Details []model.AuthDetail
	// Until is when the access ends when only entries with an end allow it: the latest of their ends. Zero when an
	// entry without an end allows it (or the tenant is open). What is issued under the access (access tokens, SSH
	// certificates) expires by it.
	Until time.Time
}

// ClientAccess decides a user's access to client c of tenant t: the union of the user's own entry and
// those of their groups that are live and cover the client. A tenant open to everyone allows every user of its
// organization and does not use its access entries at all (they are kept for when it is made members-only again). A
// user of another organization is never allowed: every caller refuses one before asking, and this does too, so one
// missed check cannot open a tenant to the whole server.
func (s *Service) ClientAccess(ctx context.Context, t *model.Tenant, c *model.Client, u *model.User, groupIDs []string) (*AppAccess, error) {
	return s.clientAccess(ctx, t, c, u, groupIDs, map[string]*model.TenantAccess{})
}

// clientAccess is ClientAccess reading the access entries of t through read, by user or group id (nil: none), each
// once: a decision for several users (sshDecideAll) shares it, so an entry of a group is read once, not once for each
// member.
func (s *Service) clientAccess(ctx context.Context, t *model.Tenant, c *model.Client, u *model.User, groupIDs []string,
	read map[string]*model.TenantAccess) (*AppAccess, error) {
	if u.OrgID != t.OrgID {
		return &AppAccess{}, nil
	}
	if !t.Settings.MembersOnly {
		return &AppAccess{Allowed: true}, nil
	}
	res := &AppAccess{}
	ids := make([]string, 0, len(groupIDs)+1)
	ids = append(ids, u.ID)
	ids = append(ids, groupIDs...)
	now := time.Now()
	var roles, tags [][]string
	standing := false // an entry without an end allows it
	var until time.Time
	for _, id := range ids {
		acc, seen := read[id]
		if !seen {
			var err error
			if acc, err = s.Access.Get(ctx, model.AccessID(t.ID, id)); err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			read[id] = acc
		}
		if acc == nil || !acc.Live(now) || !acc.Covers(c.ID) {
			continue
		}
		res.Allowed = true
		if acc.Expires.IsZero() {
			standing = true
		} else if acc.Expires.After(until) {
			until = acc.Expires
		}
		roles = append(roles, acc.Roles)
		tags = append(tags, acc.Tags)
		// Validated when saved, so one that no longer reads is skipped rather than failing the user's sign-in.
		ds, _ := model.ExpandAuthDetails(acc.AuthorizationDetails, model.AuthDetailVars{Sub: u.ID, Org: t.OrgID, Tenant: t.ID})
		for _, d := range ds {
			if !slices.ContainsFunc(res.Details, func(x model.AuthDetail) bool { return string(x.JSON) == string(d.JSON) }) {
				res.Details = append(res.Details, d)
			}
		}
	}
	if res.Allowed && !standing {
		res.Until = until
	}
	res.Roles = model.MergeTags(roles...)
	res.Tags = model.MergeTags(tags...)
	return res, nil
}
