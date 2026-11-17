package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Access requests (docs/design/access-requests.md): a member of a group whose settings let its members ask
// (model.GroupRequests) asks for access to a members-only tenant of the organization for a while; a member of the
// approver group decides (or a service account, where the group allows it); approving gives a timed access entry on
// the tenant, which then ends as any timed entry does (ExpireAccess).

const (
	// ScopeAccessRequests lets a personal API token ask for access, and list and cancel its owner's requests.
	ScopeAccessRequests = "access_requests"
	// ScopeAccessRequestsApprove lets a service account decide the requests of the groups that allow it.
	ScopeAccessRequestsApprove = "access_requests:approve"
)

// maxPendingRequests bounds the requests one person may have waiting.
const maxPendingRequests = 10

// AccessRequestNotice is what Service.OnAccessRequest hears: a request made ("new"), decided ("approved",
// "denied"), or the access it gave ended early by someone else ("ended"); By names who did it.
type AccessRequestNotice struct {
	Event   string
	Request *model.AccessRequest
	By      string
}

// RequestApprovers is one choice of who approves a person's request: an approver group, and the lengths the person's
// groups that it approves for offer.
type RequestApprovers struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Lengths []int  `json:"lengths"`
}

// AccessRequestInput is a request: the tenant (id or name), who approves it (an approver group's id; may be left out
// when there is one choice), the length in seconds and why.
type AccessRequestInput struct {
	TenantID  string `json:"tenant_id"`
	Approvers string `json:"approvers"`
	Length    int    `json:"length"`
	Reason    string `json:"reason"`
}

// requester is the account the actor asks as: a person of the organization, signed in as themselves (a guest from
// another organization asks there, not here). A personal API token asks for its owner.
func (s *Service) requester(ctx context.Context, a *Actor) (*model.User, error) {
	if a == nil || a.UserID == "" || a.ClientID != "" {
		return nil, ErrForbidden
	}
	if len(a.Sources) > 0 {
		return nil, Invalid("tenant_id", "a guest from another organization asks for access there, not here")
	}
	u, err := s.Users.Get(ctx, a.UserID)
	if err != nil {
		return nil, mapStore(err)
	}
	if !u.Active {
		return nil, ErrForbidden
	}
	return u, nil
}

// RequestApproversFor lists who may approve u's requests: one entry per approver group of u's groups that let their
// members ask, with the lengths those groups offer. Empty when u may not ask for access.
func (s *Service) RequestApproversFor(ctx context.Context, u *model.User) ([]RequestApprovers, error) {
	groups, err := s.UserGroups(ctx, u)
	if err != nil {
		return nil, err
	}
	var out []RequestApprovers
	for _, g := range groups {
		if g.Requests == nil {
			continue
		}
		i := slices.IndexFunc(out, func(o RequestApprovers) bool { return o.ID == g.Requests.Approvers })
		if i < 0 {
			ag, err := s.Groups.Get(ctx, g.Requests.Approvers)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, mapStore(err)
			}
			out = append(out, RequestApprovers{ID: ag.ID, Name: ag.DisplayName})
			i = len(out) - 1
		}
		for _, l := range g.Requests.Lengths {
			if !slices.Contains(out[i].Lengths, l) {
				out[i].Lengths = append(out[i].Lengths, l)
			}
		}
	}
	for i := range out {
		slices.Sort(out[i].Lengths)
	}
	slices.SortFunc(out, func(x, y RequestApprovers) int {
		return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
	})
	return out, nil
}

// AccessRequestRoles reports whether u may ask for access (a member of a group whose members may) and whether u
// approves requests (a member of a group that approves another's): what shows the account menu's Request access and
// Approvals. Kept for a few seconds per user: the pages and every call check again.
func (s *Service) AccessRequestRoles(ctx context.Context, u *model.User) (requester, approver bool) {
	if v, ok := s.requestRoles.Get(u.ID); ok {
		return v[0], v[1]
	}
	tok := s.requestRoles.Token(u.ID)
	groups, err := s.UserGroups(ctx, u)
	if err != nil {
		return false, false
	}
	for _, g := range groups {
		if g.Requests != nil {
			requester = true
		}
		if !approver {
			if l, _, err := s.Groups.List(ctx, store.ListQuery{Scope: g.OrgID, Limit: 1, Filters: []store.Filter{{Field: "approvers", Value: g.ID}}}); err == nil && len(l) > 0 {
				approver = true
			}
		}
	}
	s.requestRoles.PutIf(u.ID, [2]bool{requester, approver}, tok)
	return requester, approver
}

// RequestableTenant is a tenant a person may ask for access to.
type RequestableTenant struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
}

// RequestableTenants finds the members-only tenants of the actor's organization whose name starts with q (all of
// them when q is empty), up to limit, for the request form: the tenants a person can be given access to. Open ones
// let everyone in already.
func (s *Service) RequestableTenants(ctx context.Context, a *Actor, q string, limit int) ([]RequestableTenant, error) {
	u, err := s.requester(ctx, a)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	out := []RequestableTenant{}
	const page = 200
	for offset := 0; len(out) < limit; offset += page {
		ts, _, err := s.Tenants.List(ctx, store.ListQuery{Scope: u.OrgID, Search: strings.TrimSpace(q), Sort: "name", Offset: offset, Limit: page})
		if err != nil {
			return nil, mapStore(err)
		}
		for _, t := range ts {
			if t.Settings.MembersOnly && len(out) < limit {
				out = append(out, RequestableTenant{ID: t.ID, Name: t.Name, DisplayName: t.DisplayName, Description: t.Description})
			}
		}
		if len(ts) < page {
			break
		}
	}
	return out, nil
}

// CreateAccessRequest is the actor asking for access to a tenant of their organization: checked (a members-only
// tenant; one of their approver choices and its lengths; a reason; not when they have access with no end, nor a
// request waiting for it already), recorded, and announced to the approvers.
func (s *Service) CreateAccessRequest(ctx context.Context, a *Actor, in AccessRequestInput) (*model.AccessRequest, error) {
	u, err := s.requester(ctx, a)
	if err != nil {
		return nil, err
	}
	choices, err := s.RequestApproversFor(ctx, u)
	if err != nil {
		return nil, err
	}
	if len(choices) == 0 {
		return nil, ErrForbidden
	}
	var chosen *RequestApprovers
	for i := range choices {
		if choices[i].ID == strings.TrimSpace(in.Approvers) || in.Approvers == "" && len(choices) == 1 {
			chosen = &choices[i]
		}
	}
	if chosen == nil {
		return nil, Invalid("approvers", "choose who approves the request")
	}
	if !slices.Contains(chosen.Lengths, in.Length) {
		return nil, Invalid("length", "choose how long you need access for")
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || len(reason) > 500 {
		return nil, Invalid("reason", "say why you need access, in at most 500 characters")
	}
	t, err := s.tenantOf(ctx, u.OrgID, in.TenantID)
	if err != nil {
		return nil, err
	}
	if !t.Settings.MembersOnly {
		return nil, Invalid("tenant_id", "everyone in the organization can use "+t.DisplayName+" already")
	}
	if acc, err := s.Access.Get(ctx, model.AccessID(t.ID, u.ID)); err == nil && acc.Expires.IsZero() {
		return nil, Invalid("tenant_id", "you have access to "+t.DisplayName+" already, with no end")
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, mapStore(err)
	}
	if _, n, err := s.Requests.List(ctx, store.ListQuery{Scope: u.OrgID, Limit: 1, Filters: []store.Filter{
		{Field: "user_id", Value: u.ID}, {Field: "pending", Value: true}}}); err != nil {
		return nil, mapStore(err)
	} else if n >= maxPendingRequests {
		return nil, Invalid("tenant_id", "you have "+itoa(n)+" requests waiting already: cancel one, or wait for them to be decided")
	}
	now := time.Now().UTC()
	r := &model.AccessRequest{Meta: model.Meta{ID: model.NewID()}, OrgID: u.OrgID, TenantID: t.ID, UserID: u.ID,
		Approvers: chosen.ID, Length: in.Length, Reason: reason, State: model.RequestPending, Lapses: now.Add(model.RequestPendingFor)}
	err = s.audited(ctx, a, u.OrgID, "access_request.create", t.Name, map[string]string{"request": r.ID, "length": LengthText(in.Length),
		"approvers": chosen.Name, "reason": reason}, func() error { return s.Requests.Create(ctx, r) })
	if errors.Is(err, store.ErrConflict) {
		return nil, &conflictErr{Invalid("tenant_id", "you asked for access to "+t.DisplayName+" already: wait for it to be decided, or cancel it")}
	}
	if err != nil {
		return nil, mapStore(err)
	}
	s.noticeRequest(ctx, "new", r, a.Name)
	return r, nil
}

// tenantOf is the tenant of orgID that ref names (its id or name).
func (s *Service) tenantOf(ctx context.Context, orgID, ref string) (*model.Tenant, error) {
	ref = strings.TrimSpace(ref)
	var t *model.Tenant
	var err error
	if model.IsID(ref) {
		t, err = s.Tenants.Get(ctx, ref)
	} else {
		t, err = s.Tenants.GetByUnique(ctx, model.TenantNameKey(orgID, ref))
	}
	if errors.Is(err, store.ErrNotFound) || err == nil && t.OrgID != orgID || ref == "" {
		return nil, Invalid("tenant_id", "choose a tenant of your organization")
	}
	if err != nil {
		return nil, mapStore(err)
	}
	return t, nil
}

// OwnAccessRequests lists the actor's requests, newest first.
func (s *Service) OwnAccessRequests(ctx context.Context, a *Actor) ([]*model.AccessRequest, error) {
	u, err := s.requester(ctx, a)
	if err != nil {
		return nil, err
	}
	l, _, err := s.Requests.List(ctx, store.ListQuery{Scope: u.OrgID, Sort: "created", Desc: true, Limit: 100,
		Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
	return l, mapStore(err)
}

// AccessRequestsOf lists the requests of organization orgID for its administrators, newest first: state "" for all.
func (s *Service) AccessRequestsOf(ctx context.Context, a *Actor, orgID, state string, q store.ListQuery) ([]*model.AccessRequest, int, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, 0, ErrForbidden
	}
	q.Scope, q.Sort, q.Desc = orgID, "created", true
	if state != "" {
		q.Filters = append(q.Filters, store.Filter{Field: "state", Value: state})
	}
	l, n, err := s.Requests.List(ctx, q)
	return l, n, mapStore(err)
}

// ApprovalQueue lists the pending requests the actor may decide: for a person, those of the approver groups they are
// a member of (never their own); for a service account with access_requests:approve, those of the groups that let
// service accounts approve. Oldest first.
func (s *Service) ApprovalQueue(ctx context.Context, a *Actor) ([]*model.AccessRequest, error) {
	now := time.Now()
	var out []*model.AccessRequest
	switch {
	case a.ClientID != "":
		if !a.HasScope(ScopeAccessRequestsApprove) {
			return nil, ErrForbidden
		}
		l, _, err := s.Requests.List(ctx, store.ListQuery{Scope: a.OrgID, Limit: 500, Filters: []store.Filter{{Field: "pending", Value: true}}})
		if err != nil {
			return nil, mapStore(err)
		}
		for _, r := range l {
			if ok, err := s.serviceAccountsMayDecide(ctx, r); err != nil {
				return nil, err
			} else if ok && r.Pending(now) {
				out = append(out, r)
			}
		}
	default:
		u, err := s.approver(ctx, a)
		if err != nil {
			return nil, err
		}
		groups, err := s.UserGroups(ctx, u)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			l, _, err := s.Requests.List(ctx, store.ListQuery{Scope: u.OrgID, Limit: 500, Filters: []store.Filter{
				{Field: "approvers", Value: g.ID}, {Field: "pending", Value: true}}})
			if err != nil {
				return nil, mapStore(err)
			}
			for _, r := range l {
				if r.UserID != u.ID && r.Pending(now) {
					out = append(out, r)
				}
			}
		}
	}
	slices.SortFunc(out, func(x, y *model.AccessRequest) int { return x.Created.Compare(y.Created) })
	return out, nil
}

// approver is the account the actor decides as: a person of the organization signed in as themselves (never a guest
// from another organization), never through a personal API token (which cannot show a recent second factor).
func (s *Service) approver(ctx context.Context, a *Actor) (*model.User, error) {
	if a == nil || a.UserID == "" || a.TokenID != "" || len(a.Sources) > 0 {
		return nil, ErrForbidden
	}
	u, err := s.Users.Get(ctx, a.UserID)
	if err != nil {
		return nil, mapStore(err)
	}
	if !u.Active {
		return nil, ErrForbidden
	}
	return u, nil
}

// stillMayAsk reports whether r's requester is still a member of a group whose requests r's approvers decide (and
// whether one of those groups lets service accounts approve).
func (s *Service) stillMayAsk(ctx context.Context, r *model.AccessRequest) (may, serviceAccounts bool, err error) {
	u, err := s.Users.Get(ctx, r.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, mapStore(err)
	}
	if !u.Active {
		return false, false, nil
	}
	groups, err := s.UserGroups(ctx, u)
	if err != nil {
		return false, false, err
	}
	for _, g := range groups {
		if g.ApproverGroup() == r.Approvers {
			may = true
			serviceAccounts = serviceAccounts || g.Requests.ServiceAccounts
		}
	}
	return may, serviceAccounts, nil
}

func (s *Service) serviceAccountsMayDecide(ctx context.Context, r *model.AccessRequest) (bool, error) {
	may, sa, err := s.stillMayAsk(ctx, r)
	return may && sa, err
}

// mayDecide checks that the actor may decide r: a member of its approver group who is not the requester, or a
// service account with access_requests:approve where the requester's group allows it. reauthed tells whether a
// person confirmed it is them (their second factor) just now: the caller checks it.
func (s *Service) mayDecide(ctx context.Context, a *Actor, r *model.AccessRequest, reauthed bool) (name string, err error) {
	if a.ClientID != "" {
		if !a.HasScope(ScopeAccessRequestsApprove) || a.OrgID != r.OrgID {
			return "", ErrForbidden
		}
		if ok, err := s.serviceAccountsMayDecide(ctx, r); err != nil {
			return "", err
		} else if !ok {
			return "", Invalid("state", "service accounts may not decide this request: its group's settings do not allow it")
		}
		return a.Name, nil
	}
	u, err := s.approver(ctx, a)
	if err != nil {
		return "", err
	}
	if u.OrgID != r.OrgID {
		return "", ErrNotFound
	}
	if u.ID == r.UserID {
		return "", Invalid("state", "someone else must decide your own request")
	}
	if member, err := s.isMemberOf(ctx, r.Approvers, u.ID); err != nil {
		return "", err
	} else if !member {
		return "", ErrForbidden
	}
	if !reauthed {
		return "", ErrReauth
	}
	return u.FullName(), nil
}

// ErrReauth: the person must confirm it is them (their second factor) before deciding.
var ErrReauth = errors.New("service: confirm it is you first")

// isMemberOf reports whether userID is a member of group groupID.
func (s *Service) isMemberOf(ctx context.Context, groupID, userID string) (bool, error) {
	g, err := s.Groups.Get(ctx, groupID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, mapStore(err)
	}
	return s.isMember(ctx, g, userID)
}

// requestFor reads request id of the actor's organization.
func (s *Service) requestFor(ctx context.Context, a *Actor, id string) (*model.AccessRequest, error) {
	r, err := s.Requests.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && a.OrgID != "" && r.OrgID != a.OrgID {
		return nil, ErrNotFound
	}
	return r, mapStore(err)
}

// DecideAccessRequest approves or denies request id, with an optional note for the requester. Approving gives the
// requester a timed access entry on the tenant (with its access defaults), or moves the end of the timed one they
// have later; an entry with no end is left alone. The entry and the request are written in one transaction.
func (s *Service) DecideAccessRequest(ctx context.Context, a *Actor, id string, approve bool, note string, reauthed bool) (*model.AccessRequest, error) {
	note = strings.TrimSpace(note)
	if len(note) > 500 {
		return nil, Invalid("note", "at most 500 characters")
	}
	for range 3 {
		r, err := s.requestFor(ctx, a, id)
		if err != nil {
			return nil, err
		}
		name, err := s.mayDecide(ctx, a, r, reauthed)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		if r.State != model.RequestPending {
			return nil, Invalid("state", "this request was "+r.State+" already")
		}
		if !r.Pending(now) {
			return nil, Invalid("state", "this request has lapsed: nobody decided it within a day")
		}
		t, err := s.Tenants.Get(ctx, r.TenantID)
		if err != nil {
			return nil, mapStore(err)
		}
		r.DecidedBy, r.DecidedName, r.DecidedAt, r.Note = a.UserID, name, now, note
		r.DecidedVia = "account"
		if a.ClientID != "" {
			r.DecidedBy, r.DecidedVia = a.ClientID, "api"
		}
		detail := map[string]string{"request": r.ID, "user": r.UserID, "length": LengthText(r.Length), "reason": r.Reason}
		if note != "" {
			detail["note"] = note
		}
		if !approve {
			r.State = model.RequestDenied
			err := s.audited(ctx, a, r.OrgID, "access_request.deny", t.Name, detail, func() error { return s.Requests.Update(ctx, r) })
			if errors.Is(err, store.ErrStale) {
				continue
			}
			if err != nil {
				return nil, mapStore(err)
			}
			s.noticeRequest(ctx, "denied", r, name)
			return r, nil
		}
		if may, _, err := s.stillMayAsk(ctx, r); err != nil {
			return nil, err
		} else if !may {
			return nil, Invalid("state", "the person who asked may no longer ask through these approvers: deny it")
		}
		ends := now.Add(time.Duration(r.Length) * time.Second).Truncate(time.Second)
		acc, err := s.Access.Get(ctx, model.AccessID(t.ID, r.UserID))
		var ops []store.Op
		accAction := ""
		switch {
		case errors.Is(err, store.ErrNotFound):
			acc = &model.TenantAccess{Meta: model.Meta{ID: model.AccessID(t.ID, r.UserID)}, OrgID: t.OrgID, TenantID: t.ID,
				SubjectType: model.SubjectUser, SubjectID: r.UserID, AllClients: true, Expires: ends}
			withDefaults(acc, t)
			accAction = "tenant.access.add"
		case err != nil:
			return nil, mapStore(err)
		case acc.Expires.IsZero():
			ends = time.Time{} // access with no end already: nothing to give
		case acc.Expires.Before(ends):
			acc.Expires = ends
			accAction = "tenant.access.update"
		default:
			ends = acc.Expires // it lasts longer already
		}
		if accAction != "" {
			accExpect := acc.Version // Encode stamps the new one
			rec, err := store.Encode(acc)
			if err != nil {
				return nil, err
			}
			ops = append(ops, store.Op{Rec: rec, Match: true, Expect: accExpect})
		}
		r.State, r.Ends = model.RequestApproved, ends
		expect := r.Version
		rec, err := store.Encode(r)
		if err != nil {
			return nil, err
		}
		ops = append(ops, store.Op{Rec: rec, Match: true, Expect: expect})
		if !ends.IsZero() {
			detail["ends"] = ends.Format(time.RFC3339)
		}
		events := []change{{r.OrgID, "access_request.approve", t.Name, detail, nil}}
		if accAction != "" {
			events = append(events, change{r.OrgID, accAction, t.Name, map[string]string{"user": r.UserID,
				"expires": ends.Format(time.RFC3339), "reason": "access request " + r.ID + ": " + r.Reason}, nil})
		}
		err = s.Requests.S.Tx(ctx, ops)
		s.auditOutcome(ctx, a, err, events...)
		if errors.Is(err, store.ErrStale) {
			continue // decided, or the entry changed, meanwhile: look again
		}
		if err != nil {
			return nil, mapStore(err)
		}
		r.Version = rec.Version
		s.noticeRequest(ctx, "approved", r, name)
		return r, nil
	}
	return nil, ErrStale
}

// CancelAccessRequest is the requester withdrawing their pending request id.
func (s *Service) CancelAccessRequest(ctx context.Context, a *Actor, id string) (*model.AccessRequest, error) {
	u, err := s.requester(ctx, a)
	if err != nil {
		return nil, err
	}
	r, err := s.requestFor(ctx, a, id)
	if err != nil {
		return nil, err
	}
	if r.UserID != u.ID {
		return nil, ErrNotFound
	}
	if r.State != model.RequestPending {
		return nil, Invalid("state", "this request was "+r.State+" already")
	}
	r.State, r.DecidedBy, r.DecidedName, r.DecidedAt = model.RequestCancelled, u.ID, u.FullName(), time.Now().UTC()
	name := r.TenantID
	if t, err := s.Tenants.Get(ctx, r.TenantID); err == nil {
		name = t.Name
	}
	err = s.audited(ctx, a, r.OrgID, "access_request.cancel", name, map[string]string{"request": r.ID},
		func() error { return s.Requests.Update(ctx, r) })
	if err != nil {
		return nil, mapStore(err)
	}
	return r, nil
}

// EndAccessRequest ends the access approved request id gave, now: by the requester, a member of its approver group,
// a service account that may decide it, or an administrator. The requester's timed access entry on the tenant is
// removed and they are signed out of its clients; access with no end (given by an administrator meanwhile) is left,
// and refused.
func (s *Service) EndAccessRequest(ctx context.Context, a *Actor, id string, reauthed bool) (*model.AccessRequest, error) {
	r, err := s.requestFor(ctx, a, id)
	if err != nil {
		return nil, err
	}
	// who may end it: the requester themselves; an administrator; or whoever may decide it (an approver, or a
	// service account where the group allows it)
	name := a.Name
	requester := a.ClientID == "" && a.UserID != "" && a.UserID == r.UserID
	if !requester && !(a.ClientID == "" && s.canAdminOrg(a, r.OrgID)) {
		if name, err = s.mayDecide(ctx, a, r, reauthed); err != nil {
			return nil, err
		}
	}
	if r.State != model.RequestApproved {
		return nil, Invalid("state", "only approved access can be ended")
	}
	now := time.Now().UTC()
	if !r.Ends.IsZero() && !now.Before(r.Ends) {
		return nil, Invalid("state", "this access has ended already")
	}
	t, err := s.Tenants.Get(ctx, r.TenantID)
	if err != nil {
		return nil, mapStore(err)
	}
	acc, err := s.Access.Get(ctx, model.AccessID(t.ID, r.UserID))
	switch {
	case errors.Is(err, store.ErrNotFound):
		acc = nil // removed already
	case err != nil:
		return nil, mapStore(err)
	case acc.Expires.IsZero():
		return nil, Invalid("state", "this access has no end now (an administrator gave it): remove it from the tenant's access list")
	}
	r.State, r.EndedBy, r.EndedName, r.EndedAt = model.RequestEnded, cmpOr(a.UserID, a.ClientID), name, now
	detail := map[string]string{"request": r.ID, "user": r.UserID}
	events := []change{{r.OrgID, "access_request.end", t.Name, detail, nil}}
	expect := r.Version
	rec, err := store.Encode(r)
	if err != nil {
		return nil, err
	}
	ops := []store.Op{{Rec: rec, Match: true, Expect: expect}}
	if acc != nil {
		ops = append(ops, store.Op{Rec: store.Tombstone(model.KindAccess, acc.ID), Match: true, Expect: acc.Version})
		events = append(events, change{r.OrgID, "tenant.access.remove", t.Name, map[string]string{"user": r.UserID,
			"reason": "access request " + r.ID + " ended"}, nil})
	}
	err = s.Requests.S.Tx(ctx, ops)
	s.auditOutcome(ctx, a, err, events...)
	if err != nil {
		r.Version = expect
		return nil, mapStore(err)
	}
	r.Version = rec.Version
	if acc != nil {
		s.endLostAccessLater(ctx, t, acc)
		s.endOtherRequests(ctx, r, name)
	}
	if a.UserID != r.UserID {
		s.noticeRequest(ctx, "ended", r, name)
	}
	return r, nil
}

// endOtherRequests marks ended the other approved requests of r's requester for r's tenant whose access had not ended:
// an extension's, whose access went with the entry r's ending removed. Best effort: one missed still shows its own end.
func (s *Service) endOtherRequests(ctx context.Context, r *model.AccessRequest, name string) {
	l, _, err := s.Requests.List(ctx, store.ListQuery{Scope: r.OrgID, Limit: 100, Filters: []store.Filter{
		{Field: "user_id", Value: r.UserID}, {Field: "state", Value: model.RequestApproved}}})
	if err != nil {
		return
	}
	for _, o := range l {
		if o.ID == r.ID || o.TenantID != r.TenantID || o.Ends.IsZero() || !r.EndedAt.Before(o.Ends) {
			continue
		}
		o.State, o.EndedBy, o.EndedName, o.EndedAt = model.RequestEnded, r.EndedBy, name, r.EndedAt
		_ = s.Requests.Update(ctx, o)
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// noticeRequest tells OnAccessRequest (the emails), when set.
func (s *Service) noticeRequest(ctx context.Context, event string, r *model.AccessRequest, by string) {
	if s.OnAccessRequest != nil {
		s.OnAccessRequest(context.WithoutCancel(ctx), AccessRequestNotice{Event: event, Request: r, By: by})
	}
}

// ExpireAccessRequests is the housekeeping of access requests: a pending request nobody decided within
// model.RequestPendingFor lapses, and a closed one is removed once model.RequestKeptFor has passed (the audit log
// keeps the history). It returns how many it changed.
func (s *Service) ExpireAccessRequests(ctx context.Context) (int, error) {
	n := 0
	stuck := map[string]bool{}
	for {
		due, err := s.dueRequests(ctx, 200)
		if err != nil {
			return n, err
		}
		progressed := false
		for _, r := range due {
			if stuck[r.ID] {
				continue
			}
			var err error
			if r.State == model.RequestPending {
				r.State = model.RequestLapsed
				name := r.TenantID
				if t, e := s.Tenants.Get(ctx, r.TenantID); e == nil {
					name = t.Name
				}
				err = s.audited(ctx, System, r.OrgID, "access_request.lapse", name, map[string]string{"request": r.ID, "user": r.UserID},
					func() error { return s.Requests.Update(ctx, r) })
			} else {
				err = s.Requests.DeleteIf(ctx, r.ID, r.Version)
			}
			if err != nil && !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrNotFound) {
				stuck[r.ID] = true
				s.Log.WithError(err).Warn("an access request could not be closed; housekeeping tries again", "request", r.ID)
				continue
			}
			n++
			progressed = true
		}
		if len(due) < 200 || !progressed {
			return n, nil
		}
	}
}

// dueRequests lists up to limit requests due now (model.Due): from the due index where the store keeps one.
func (s *Service) dueRequests(ctx context.Context, limit int) ([]*model.AccessRequest, error) {
	now := time.Now()
	if dl, ok := s.Requests.S.(store.DueLister); ok {
		recs, err := dl.ListDue(ctx, model.KindAccessRequest, now, limit)
		if err == nil {
			out := make([]*model.AccessRequest, 0, len(recs))
			for _, rec := range recs {
				var r model.AccessRequest
				if err := store.Decode(rec, &r); err == nil {
					out = append(out, &r)
				}
			}
			return out, nil
		}
		if !errors.Is(err, store.ErrNoDueIndex) {
			return nil, mapStore(err)
		}
	}
	l, _, err := s.Requests.List(ctx, store.ListQuery{Sort: "due", Limit: limit, Filters: []store.Filter{{Field: "due", Op: store.OpLT, Value: now}}})
	return l, mapStore(err)
}

// LengthText names a length of access in seconds: "1 hour", "3 days", "1 week", "1 month".
func LengthText(secs int) string {
	switch {
	case secs%(30*86400) == 0:
		return plural(secs/(30*86400), "month")
	case secs%(7*86400) == 0:
		return plural(secs/(7*86400), "week")
	case secs%86400 == 0:
		return plural(secs/86400, "day")
	case secs%3600 == 0:
		return plural(secs/3600, "hour")
	}
	return plural(secs/60, "minute")
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return itoa(n) + " " + unit + "s"
}

// AccessRequestView is a request with the names a page shows: the person who asked, the tenant and the approvers.
type AccessRequestView struct {
	*model.AccessRequest
	UserName          string `json:"user_name"`
	UserEmail         string `json:"user_email,omitempty"`
	TenantName        string `json:"tenant_name"`
	TenantDisplayName string `json:"tenant_display_name"`
	ApproversName     string `json:"approvers_name"`
	LengthText        string `json:"length_text"`
	// Live is true while the access an approved request gave lasts.
	Live bool `json:"live"`
}

// AccessRequestViews names the people, tenants and approver groups of rs (a removed one by its id).
func (s *Service) AccessRequestViews(ctx context.Context, rs []*model.AccessRequest) []AccessRequestView {
	users, tenants, groups := map[string]*model.User{}, map[string]*model.Tenant{}, map[string]*model.Group{}
	now := time.Now()
	out := make([]AccessRequestView, 0, len(rs))
	for _, r := range rs {
		v := AccessRequestView{AccessRequest: r, UserName: "a deleted user", TenantName: r.TenantID, TenantDisplayName: "a deleted tenant",
			ApproversName: "a deleted group", LengthText: LengthText(r.Length)}
		if _, ok := users[r.UserID]; !ok {
			users[r.UserID], _ = s.Users.Get(ctx, r.UserID)
		}
		if u := users[r.UserID]; u != nil {
			v.UserName, v.UserEmail = u.FullName(), u.Email
		}
		if _, ok := tenants[r.TenantID]; !ok {
			tenants[r.TenantID], _ = s.Tenants.Get(ctx, r.TenantID)
		}
		if t := tenants[r.TenantID]; t != nil {
			v.TenantName, v.TenantDisplayName = t.Name, t.DisplayName
		}
		if _, ok := groups[r.Approvers]; !ok {
			groups[r.Approvers], _ = s.Groups.Get(ctx, r.Approvers)
		}
		if g := groups[r.Approvers]; g != nil {
			v.ApproversName = g.DisplayName
		}
		v.Live = r.State == model.RequestApproved && (r.Ends.IsZero() || now.Before(r.Ends))
		if r.State == model.RequestPending && !now.Before(r.Lapses) {
			v.State = model.RequestLapsed // not yet tidied by housekeeping
		}
		out = append(out, v)
	}
	return out
}

// ApprovedByGroups lists the approved requests of the approver groups the actor is a member of whose access still
// lasts, newest first: what an approver may end early.
func (s *Service) ApprovedByGroups(ctx context.Context, a *Actor) ([]*model.AccessRequest, error) {
	u, err := s.approver(ctx, a)
	if err != nil {
		return nil, err
	}
	groups, err := s.UserGroups(ctx, u)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []*model.AccessRequest
	for _, g := range groups {
		l, _, err := s.Requests.List(ctx, store.ListQuery{Scope: u.OrgID, Limit: 500, Filters: []store.Filter{
			{Field: "approvers", Value: g.ID}, {Field: "state", Value: model.RequestApproved}}})
		if err != nil {
			return nil, mapStore(err)
		}
		for _, r := range l {
			if !r.Ends.IsZero() && now.Before(r.Ends) {
				out = append(out, r)
			}
		}
	}
	slices.SortFunc(out, func(x, y *model.AccessRequest) int { return y.DecidedAt.Compare(x.DecidedAt) })
	return out, nil
}
