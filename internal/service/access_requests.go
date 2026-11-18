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

// requestGroupsTTL is how long the account menu's view of who asks and approves is kept (requestGroups): a group
// change drops it at once, on every node told of it.
const requestGroupsTTL = time.Hour

// requestGroups are an organization's groups whose members may ask for access (requesters) and the groups whose
// members approve access requests (approvers: model.Group.ApprovesRequests, which every group named as approvers is).
type requestGroups struct {
	requesters, approvers map[string]bool
}

// InvalidateRequestGroups drops what is kept of who asks for and approves access (requestGroups, requestRoles): call
// it when a group's record changes, here or on another node (its settings, or its members: a change of members is
// written on the group's record). Each organization's groups and each user's roles are read again when next needed.
func (s *Service) InvalidateRequestGroups() {
	s.requestGroups.Clear()
	s.requestRoles.Clear()
}

// orgRequestGroups reads organization orgID's requester and approver groups: an indexed read of each, kept an hour
// (requestGroupsTTL) unless a group changes.
func (s *Service) orgRequestGroups(ctx context.Context, orgID string) (*requestGroups, error) {
	if v, ok := s.requestGroups.Get(orgID); ok {
		return v, nil
	}
	tok := s.requestGroups.Token(orgID)
	rg := &requestGroups{requesters: map[string]bool{}, approvers: map[string]bool{}}
	const page = 500
	for _, field := range []string{"requests", "approves"} {
		for offset := 0; ; offset += page {
			l, _, err := s.Groups.List(ctx, store.ListQuery{Scope: orgID, Offset: offset, Limit: page, Filters: []store.Filter{{Field: field, Value: true}}})
			if err != nil {
				return nil, mapStore(err)
			}
			for _, g := range l {
				if g.Requests != nil {
					rg.requesters[g.ID], rg.approvers[g.Requests.Approvers] = true, true
				}
				if g.ApprovesRequests {
					rg.approvers[g.ID] = true
				}
			}
			if len(l) < page {
				break
			}
		}
	}
	s.requestGroups.PutIf(orgID, rg, tok)
	return rg, nil
}

// waitingPerPerson is how many requests one person may have waiting (limits.access_requests_waiting).
func (s *Service) waitingPerPerson() int {
	if s.Cfg != nil {
		if n := s.Cfg.LiveLimits().AccessRequestsWaiting; n > 0 {
			return n
		}
	}
	return 10
}

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
	bots    bool   // a group naming these approvers lets service accounts decide
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
		out[i].bots = out[i].bots || g.Requests.ServiceAccounts
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
// approves requests (a member of a group whose members approve them): what shows the account menu's Request
// access and Approvals. Kept an hour per user, dropped when a group changes (InvalidateRequestGroups): a page render
// reads nothing for it, and a miss reads u's memberships (and, once an hour, the organization's request groups). The
// pages and every call check again.
func (s *Service) AccessRequestRoles(ctx context.Context, u *model.User) (requester, approver bool) {
	if v, ok := s.requestRoles.Get(u.ID); ok {
		return v[0], v[1]
	}
	tok := s.requestRoles.Token(u.ID)
	rg, err := s.orgRequestGroups(ctx, u.OrgID)
	if err != nil {
		return false, false
	}
	if len(rg.requesters)+len(rg.approvers) > 0 { // an organization without access requests reads nothing more
		ms, _, err := s.Members.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
		if err != nil {
			return false, false
		}
		for _, m := range ms {
			requester = requester || rg.requesters[m.GroupID]
			approver = approver || rg.approvers[m.GroupID]
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
// let everyone in already. One indexed read (members_only), however many tenants are open.
func (s *Service) RequestableTenants(ctx context.Context, a *Actor, q string, limit int) ([]RequestableTenant, error) {
	u, err := s.requester(ctx, a)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	ts, _, err := s.Tenants.List(ctx, store.ListQuery{Scope: u.OrgID, Search: strings.TrimSpace(q), Sort: "name", Limit: limit,
		Filters: []store.Filter{{Field: "members_only", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	out := make([]RequestableTenant, 0, len(ts))
	for _, t := range ts {
		out = append(out, RequestableTenant{ID: t.ID, Name: t.Name, DisplayName: t.DisplayName, Description: t.Description})
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
		{Field: "waiting_user", Value: u.ID}}}); err != nil {
		return nil, mapStore(err)
	} else if n >= s.waitingPerPerson() {
		return nil, Invalid("tenant_id", "you have "+itoa(n)+" requests waiting already: cancel one, or wait for them to be decided")
	}
	now := time.Now().UTC()
	r := &model.AccessRequest{Meta: model.Meta{ID: model.NewID()}, OrgID: u.OrgID, TenantID: t.ID, UserID: u.ID,
		Approvers: chosen.ID, Length: in.Length, Reason: reason, State: model.RequestPending, Lapses: now.Add(model.RequestPendingFor),
		Bots: chosen.bots}
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

// OwnAccessRequests lists a page of the actor's requests, newest first, and how many they have.
func (s *Service) OwnAccessRequests(ctx context.Context, a *Actor, q store.ListQuery) ([]*model.AccessRequest, int, error) {
	u, err := s.requester(ctx, a)
	if err != nil {
		return nil, 0, err
	}
	l, n, err := s.Requests.List(ctx, store.ListQuery{Scope: u.OrgID, Sort: "created", Desc: true, Offset: q.Offset, Limit: pageLimit(q),
		Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
	return l, n, mapStore(err)
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

// pageLimit is q's page size: 50 when it gives none, at most 500.
func pageLimit(q store.ListQuery) int {
	if q.Limit <= 0 {
		return 50
	}
	return min(q.Limit, 500)
}

// ApprovalQueue lists a page of the pending requests the actor may decide, oldest first, and how many there are: for
// a person, those of the approver groups they are a member of (their own among them, which someone else decides); for
// a service account with access_requests:approve, those of the groups that let service accounts decide. Each is one
// exact indexed read (queue, bots): the page costs what it shows, however many requests the organization keeps.
func (s *Service) ApprovalQueue(ctx context.Context, a *Actor, q store.ListQuery) ([]*model.AccessRequest, int, error) {
	waiting := store.Filter{Field: "due", Op: store.OpGTE, Value: time.Now()} // not lapsed (a pending one is due when it lapses)
	if a.ClientID != "" {
		if !a.HasScope(ScopeAccessRequestsApprove) {
			return nil, 0, ErrForbidden
		}
		l, n, err := s.Requests.List(ctx, store.ListQuery{Scope: a.OrgID, Sort: "created", Offset: q.Offset, Limit: pageLimit(q),
			Filters: []store.Filter{{Field: "bots", Value: true}, waiting}})
		return l, n, mapStore(err)
	}
	u, err := s.approver(ctx, a)
	if err != nil {
		return nil, 0, err
	}
	groups, err := s.approverGroupsOf(ctx, u)
	if err != nil {
		return nil, 0, err
	}
	return s.pageAcross(ctx, u.OrgID, groups, model.RequestPending, waiting, false, q)
}

// ApprovedByGroups lists a page of the requests the approver groups the actor is a member of approved whose access
// still runs, newest first, and how many there are: what an approver may end early.
func (s *Service) ApprovedByGroups(ctx context.Context, a *Actor, q store.ListQuery) ([]*model.AccessRequest, int, error) {
	u, err := s.approver(ctx, a)
	if err != nil {
		return nil, 0, err
	}
	groups, err := s.approverGroupsOf(ctx, u)
	if err != nil {
		return nil, 0, err
	}
	running := store.Filter{Field: "ends", Op: store.OpGTE, Value: time.Now()} // not yet marked expired by housekeeping
	return s.pageAcross(ctx, u.OrgID, groups, model.RequestApproved, running, true, q)
}

// approverGroupsOf lists the ids of u's groups whose members approve access requests, in id order: every member of
// such a group sees its waiting requests and the access it gave that runs, named by a group now or not.
func (s *Service) approverGroupsOf(ctx context.Context, u *model.User) ([]string, error) {
	rg, err := s.orgRequestGroups(ctx, u.OrgID)
	if err != nil {
		return nil, err
	}
	if len(rg.approvers) == 0 {
		return nil, nil
	}
	groups, err := s.UserGroups(ctx, u)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, g := range groups {
		if rg.approvers[g.ID] {
			out = append(out, g.ID)
		}
	}
	slices.Sort(out)
	return out, nil
}

// pageAcross pages the requests in state of several approver groups' queues (model.AccessRequestQueue) as one list,
// sorted by when they were made (newest first when desc), with filter applied too: q's offset and limit over them
// all, and the total. One approver group, the usual case, is one read of the page; with more, each queue is read up
// to the end of the page and the pages merged.
func (s *Service) pageAcross(ctx context.Context, orgID string, groups []string, state string, filter store.Filter, desc bool,
	q store.ListQuery) ([]*model.AccessRequest, int, error) {
	limit, offset := pageLimit(q), max(q.Offset, 0)
	if len(groups) == 0 {
		return []*model.AccessRequest{}, 0, nil
	}
	read := func(g string, offset, limit int) ([]*model.AccessRequest, int, error) {
		l, n, err := s.Requests.List(ctx, store.ListQuery{Scope: orgID, Sort: "created", Desc: desc, Offset: offset, Limit: limit,
			Filters: []store.Filter{{Field: "queue", Value: model.AccessRequestQueue(g, state)}, filter}})
		return l, n, mapStore(err)
	}
	if len(groups) == 1 {
		return read(groups[0], offset, limit)
	}
	var all []*model.AccessRequest
	total := 0
	for _, g := range groups {
		l, n, err := read(g, 0, offset+limit)
		if err != nil {
			return nil, 0, err
		}
		all, total = append(all, l...), total+n
	}
	slices.SortStableFunc(all, func(x, y *model.AccessRequest) int {
		if c := x.Created.Compare(y.Created); c != 0 {
			if desc {
				return -c
			}
			return c
		}
		return strings.Compare(x.ID, y.ID)
	})
	if offset >= len(all) {
		return []*model.AccessRequest{}, total, nil
	}
	return all[offset:min(offset+limit, len(all))], total, nil
}

// refreshRequestBots sets again, on the pending requests the approver groups decide, whether service accounts may
// decide each (model.AccessRequest.Bots: their queue), after a group's access request settings changed or a group
// with them was removed. Each requester's groups are read once. Best effort: deciding checks the groups again anyway.
func (s *Service) refreshRequestBots(ctx context.Context, orgID string, approvers ...string) {
	type verdict struct{ may, bots bool }
	seen := map[string]verdict{}
	for _, g := range slices.Compact(slices.Sorted(slices.Values(approvers))) {
		const page = 500
		for offset := 0; ; offset += page {
			l, _, err := s.Requests.List(ctx, store.ListQuery{Scope: orgID, Offset: offset, Limit: page,
				Filters: []store.Filter{{Field: "queue", Value: model.AccessRequestQueue(g, model.RequestPending)}}})
			if err != nil {
				s.Log.WithError(err).Warn("access requests: could not read the pending requests of an approver group", "group", g)
				return
			}
			for _, r := range l {
				v, ok := seen[r.UserID+"/"+r.Approvers]
				if !ok {
					may, bots, err := s.stillMayAsk(ctx, r)
					if err != nil {
						continue
					}
					v = verdict{may, bots}
					seen[r.UserID+"/"+r.Approvers] = v
				}
				if want := v.may && v.bots; want != r.Bots {
					r.Bots = want
					_ = s.Requests.Update(ctx, r) // one changed meanwhile was decided, or set by another refresh
				}
			}
			if len(l) < page {
				break
			}
		}
	}
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
	switch r.State {
	case model.RequestApproved:
	case model.RequestExpired, model.RequestEnded:
		return nil, Invalid("state", "this access has ended already")
	default:
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

// endOtherRequests marks ended the other running requests of r's requester for r's tenant: an extension's, or the
// one it extended, whose access went with the entry r's ending removed. They are read by their exact index value
// (running), however many requests the person has made. Best effort: one missed shows Active until its own end.
func (s *Service) endOtherRequests(ctx context.Context, r *model.AccessRequest, name string) {
	l, _, err := s.Requests.List(ctx, store.ListQuery{Scope: r.OrgID, Limit: 500, Filters: []store.Filter{
		{Field: "running", Value: model.AccessRequestRunning(r.UserID, r.TenantID)}}})
	if err != nil {
		return
	}
	for _, o := range l {
		if o.ID == r.ID || !o.Running() {
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
// model.RequestPendingFor lapses, a running one whose access reached its end is marked expired (the access entry ends
// by itself: ExpireAccess), and a closed one is removed once model.RequestKeptFor has passed (the audit log keeps the
// history). It returns how many it changed.
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
			switch {
			case r.Running():
				r.State = model.RequestExpired // it leaves the approvers' and the person's running lists
				err = s.Requests.Update(ctx, r)
			case r.State == model.RequestPending:
				r.State = model.RequestLapsed
				name := r.TenantID
				if t, e := s.Tenants.Get(ctx, r.TenantID); e == nil {
					name = t.Name
				}
				err = s.audited(ctx, System, r.OrgID, "access_request.lapse", name, map[string]string{"request": r.ID, "user": r.UserID},
					func() error { return s.Requests.Update(ctx, r) })
			default:
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
	// Yours marks, in an approver's lists, the approver's own request (someone else decides it).
	Yours bool `json:"yours,omitempty"`
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
