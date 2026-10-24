package service

import (
	"context"
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
	AllClients  *bool     `json:"all_clients"`
	Clients     *[]string `json:"clients"`
	Expires     *string   `json:"expires"` // RFC 3339 time or a date (YYYY-MM-DD, ends at the start of that day UTC); "" = no end
}

// AccessEntry is a TenantAccess with the subject resolved for display.
type AccessEntry struct {
	*model.TenantAccess
	Name    string `json:"name"`             // the user's full name or the group's name ("" when it no longer exists)
	Detail  string `json:"detail,omitempty"` // the user's email address
	Expired bool   `json:"expired"`
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

func (s *Service) applyAccess(ctx context.Context, t *model.Tenant, acc *model.TenantAccess, in AccessInput) error {
	if err := applyRoles(&acc.Roles, in.Roles); err != nil {
		return err
	}
	if err := applyTags(&acc.Tags, in.Tags); err != nil {
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
		v := strings.TrimSpace(*in.Expires)
		switch {
		case v == "":
			acc.Expires = time.Time{}
		default:
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				if t, err = time.Parse(time.DateOnly, v); err != nil {
					return Invalid("expires", "use a date (YYYY-MM-DD) or an RFC 3339 time, or leave it empty for no end")
				}
			}
			acc.Expires = t.UTC()
		}
	}
	return nil
}

// tenantForAccess returns the tenant when the actor may administer it.
func (s *Service) tenantForAccess(ctx context.Context, a *Actor, tenantID string) (*model.Tenant, error) {
	return s.GetTenant(ctx, a, tenantID)
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
	t, err := s.tenantForAccess(ctx, a, tenantID)
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
		e.Name, e.Detail, _ = s.accessSubject(ctx, a, t.OrgID, acc.SubjectType, acc.SubjectID)
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
	t, err := s.tenantForAccess(ctx, a, tenantID)
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
	t, err := s.tenantForAccess(ctx, a, tenantID)
	if err != nil {
		return nil, err
	}
	name, detail, err := s.accessSubject(ctx, a, t.OrgID, in.SubjectType, in.SubjectID)
	if err != nil {
		return nil, err
	}
	acc := &model.TenantAccess{OrgID: t.OrgID, TenantID: t.ID, SubjectType: in.SubjectType, SubjectID: in.SubjectID,
		AllClients: true}
	acc.ID = model.AccessID(t.ID, in.SubjectID)
	if err := s.applyAccess(ctx, t, acc, in); err != nil {
		return nil, err
	}
	// The id is deterministic, so a removed entry leaves a tombstone: adding it again is a create, which starts a new
	// generation of the record whose epoch is the removal this node has seen (a plain put over the tombstone is
	// refused: store.ErrDeleted). A removal made elsewhere that this node had not seen yet still wins: the add is then
	// refused (ErrDeleted from the quorum), reported as a concurrent change to retry.
	alreadyThere := &conflictErr{Invalid("subject_id", name+" already has access to this tenant")}
	if _, err := s.Access.Get(ctx, acc.ID); err == nil {
		return nil, alreadyThere
	}
	if err := s.Access.Create(Durable(ctx), acc); err != nil {
		if errors.Is(err, store.ErrStale) {
			return nil, alreadyThere // added concurrently
		}
		if errors.Is(err, store.ErrDeleted) {
			return nil, ErrStale
		}
		return nil, mapStore(err)
	}
	s.Audit(ctx, a, t.OrgID, "tenant.access.add", t.Name, map[string]string{in.SubjectType: name})
	return &AccessEntry{TenantAccess: acc, Name: name, Detail: detail, Expired: !acc.Live(time.Now())}, nil
}

// UpdateAccess changes the roles, tags, applications or end of an access.
func (s *Service) UpdateAccess(ctx context.Context, a *Actor, tenantID, id string, in AccessInput) (*AccessEntry, error) {
	e, err := s.GetAccess(ctx, a, tenantID, id)
	if err != nil {
		return nil, err
	}
	t, err := s.Tenants.Get(ctx, e.TenantID)
	if err != nil {
		return nil, mapStore(err)
	}
	if err := s.applyAccess(ctx, t, e.TenantAccess, in); err != nil {
		return nil, err
	}
	if err := s.Access.Update(Durable(ctx), e.TenantAccess); err != nil {
		return nil, mapStore(err)
	}
	e.Expired = !e.Live(time.Now())
	s.Audit(ctx, a, t.OrgID, "tenant.access.update", t.Name, map[string]string{e.SubjectType: e.Name})
	return e, nil
}

// RemoveAccess takes a user's or group's access away.
func (s *Service) RemoveAccess(ctx context.Context, a *Actor, tenantID, id string) error {
	e, err := s.GetAccess(ctx, a, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.Access.Delete(Durable(ctx), id); err != nil {
		return mapStore(err)
	}
	t, _ := s.Tenants.Get(ctx, e.TenantID)
	name := e.TenantID
	if t != nil {
		name = t.Name
	}
	s.Audit(ctx, a, e.OrgID, "tenant.access.remove", name, map[string]string{e.SubjectType: e.Name})
	return nil
}

// deleteAccessWhere removes the access records of an org matching one field (a deleted user, group or tenant). It
// is cleanup: an entry left behind names a subject or tenant that no longer exists, so no access decision reads it
// (ClientAccess looks entries up by the user and their current groups, in the client's tenant). Failures are
// returned so the caller can record that the deletion did not finish.
func (s *Service) deleteAccessWhere(ctx context.Context, orgID, field, value string) error {
	l, _, err := s.Access.List(ctx, store.ListQuery{Scope: orgID, Filters: []store.Filter{{Field: field, Value: value}}})
	if err != nil {
		return mapStore(err)
	}
	var errs []error
	for _, acc := range l {
		if err := s.Access.Delete(ctx, acc.ID); err != nil && !store.Applied(err) && !errors.Is(err, store.ErrStale) {
			errs = append(errs, mapStore(err))
		}
	}
	return errors.Join(errs...)
}

// AppAccess is what a user gets for one application: whether they may sign in to it, and the roles and tags that
// their live access entries for it carry.
type AppAccess struct {
	Allowed bool
	Roles   []string
	Tags    []string
}

// ClientAccess decides a user's access to client c of tenant t: the union of the user's own entry and
// those of their groups that are live and cover the client. A tenant open to everyone allows every user of its
// organization and does not use its access entries at all (they are kept for when it is made members-only again).
// Users of other organizations (signing in to an all-orgs client) are governed by their own organization.
func (s *Service) ClientAccess(ctx context.Context, t *model.Tenant, c *model.Client, u *model.User, groupIDs []string) (*AppAccess, error) {
	if !t.Settings.MembersOnly || u.OrgID != t.OrgID {
		return &AppAccess{Allowed: true}, nil
	}
	res := &AppAccess{}
	ids := make([]string, 0, len(groupIDs)+1)
	ids = append(ids, u.ID)
	ids = append(ids, groupIDs...)
	now := time.Now()
	var roles, tags [][]string
	for _, id := range ids {
		acc, err := s.Access.Get(ctx, model.AccessID(t.ID, id))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if !acc.Live(now) || !acc.Covers(c.ID) {
			continue
		}
		res.Allowed = true
		roles = append(roles, acc.Roles)
		tags = append(tags, acc.Tags)
	}
	res.Roles = model.MergeTags(roles...)
	res.Tags = model.MergeTags(tags...)
	return res, nil
}
