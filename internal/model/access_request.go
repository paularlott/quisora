package model

import (
	"encoding/json"
	"time"
)

// KindAccessRequest holds people's requests for access to a tenant (AccessRequest).
const KindAccessRequest Kind = "accessrequest"

// AccessLengths are the lengths of access a request may ask for, in seconds: 1 hour, 4 hours, 8 hours, 1 day,
// 3 days, 1 week, 2 weeks and 1 month (30 days). A group offers some or all of them (GroupRequests.Lengths).
var AccessLengths = []int{3600, 4 * 3600, 8 * 3600, 86400, 3 * 86400, 7 * 86400, 14 * 86400, 30 * 86400}

// GroupRequests are a group's access request settings: its members may ask for access to a members-only tenant of
// the organization, for one of Lengths, and a member of the Approvers group decides (or, when ServiceAccounts, a
// service account holding the access_requests:approve scope). While a group's settings name them, both groups are
// protected: only administrators and provisioning change their members.
type GroupRequests struct {
	Approvers       string `msgpack:"a" json:"approvers"`                   // the approver group's id
	Lengths         []int  `msgpack:"l,omitempty" json:"lengths"`           // seconds, a subset of AccessLengths
	ServiceAccounts bool   `msgpack:"sa,omitempty" json:"service_accounts"` // service accounts may approve
}

// AccessDefaults are a tenant's defaults for its new access entries, however they are made (the console, the API,
// an approved request): each field not given when an entry is made is copied from here into it, so a later change of
// the defaults changes no entry.
type AccessDefaults struct {
	Roles                []string        `msgpack:"r,omitempty" json:"roles"`
	Tags                 []string        `msgpack:"tg,omitempty" json:"tags"`
	AuthorizationDetails json.RawMessage `msgpack:"ad,omitempty" json:"authorization_details,omitempty"`
}

// The states of an access request.
const (
	RequestPending   = "pending"
	RequestApproved  = "approved"
	RequestDenied    = "denied"
	RequestCancelled = "cancelled"
	RequestLapsed    = "lapsed"  // not decided within its time (Lapses)
	RequestEnded     = "ended"   // approved, then ended early
	RequestExpired   = "expired" // approved, and its access ran to its end (housekeeping marks it at Ends)
)

// RequestPendingFor is how long a request waits to be decided before it lapses; RequestKeptFor how long a closed
// one is kept (the audit log keeps the history).
const (
	RequestPendingFor = 24 * time.Hour
	RequestKeptFor    = 90 * 24 * time.Hour
)

// AccessRequest is one person asking for access to a tenant of their organization for a while, to be decided by a
// member of the approver group (Approvers). Approving it gives them a timed access entry on the tenant (or moves the
// end of the one they have later).
type AccessRequest struct {
	Meta
	OrgID     string    `msgpack:"o" json:"org_id"`
	TenantID  string    `msgpack:"t" json:"tenant_id"`
	UserID    string    `msgpack:"ui" json:"user_id"`
	Approvers string    `msgpack:"a" json:"approvers"` // the group whose members decide
	Length    int       `msgpack:"l" json:"length"`    // seconds
	Reason    string    `msgpack:"rs" json:"reason"`
	State     string    `msgpack:"s" json:"state"`
	Lapses    time.Time `msgpack:"lp" json:"lapses"` // when a pending request lapses
	// Bots is whether service accounts holding access_requests:approve may decide it: a group of the requester naming
	// these approvers allowed it when it was made (or when that group's settings last changed). Their queue lists
	// these; deciding checks the groups again.
	Bots bool `msgpack:"bt,omitempty" json:"service_accounts"`
	// DecidedBy is who approved, denied or ended it: a user id, or a service account's client id (DecidedVia "api");
	// DecidedName their name as recorded then; DecidedAt when; Note what they wrote (shown to the requester).
	DecidedBy   string    `msgpack:"db,omitempty" json:"decided_by,omitempty"`
	DecidedName string    `msgpack:"dn,omitempty" json:"decided_by_name,omitempty"`
	DecidedVia  string    `msgpack:"dv,omitempty" json:"decided_via,omitempty"`
	DecidedAt   time.Time `msgpack:"da,omitempty" json:"decided_at,omitempty"`
	Note        string    `msgpack:"n,omitempty" json:"note,omitempty"`
	// Ends is when the access the approval gave ends (approved and ended requests); EndedBy, EndedName and EndedAt
	// who ended it early, and when.
	Ends      time.Time `msgpack:"e,omitempty" json:"ends,omitempty"`
	EndedBy   string    `msgpack:"eb,omitempty" json:"ended_by,omitempty"`
	EndedName string    `msgpack:"en,omitempty" json:"ended_by_name,omitempty"`
	EndedAt   time.Time `msgpack:"ea,omitempty" json:"ended_at,omitempty"`
}

func (r *AccessRequest) Kind() Kind { return KindAccessRequest }

// Pending reports whether r waits to be decided (and has not lapsed by its time).
func (r *AccessRequest) Pending(now time.Time) bool {
	return r.State == RequestPending && now.Before(r.Lapses)
}

// Running reports whether r is approved and the access it gave has an end still to come (or not yet marked expired).
func (r *AccessRequest) Running() bool { return r.State == RequestApproved && !r.Ends.IsZero() }

// due is when housekeeping must look at r: a pending one when it lapses, a running one when its access ends (to mark
// it expired), a closed one when it is no longer kept.
func (r *AccessRequest) due() time.Time {
	switch r.State {
	case RequestPending:
		return r.Lapses
	case RequestApproved, RequestEnded, RequestExpired:
		if r.Running() {
			return r.Ends
		}
		last := r.Ends
		if r.EndedAt.After(last) || last.IsZero() {
			last = r.EndedAt
		}
		if last.IsZero() {
			last = r.DecidedAt
		}
		return last.Add(RequestKeptFor)
	}
	at := r.DecidedAt
	if at.IsZero() {
		at = r.Lapses
	}
	return at.Add(RequestKeptFor)
}

func (r *AccessRequest) Index() Index {
	var uq []string
	if r.State == RequestPending { // one pending request per person and tenant
		uq = []string{AccessRequestPendingKey(r.OrgID, r.UserID, r.TenantID)}
	}
	return Index{
		Scope:     r.OrgID,
		Partition: r.OrgID,
		Unique:    uq,
		Fields: map[string]any{"user_id": r.UserID, "tenant_id": r.TenantID, "waiting_user": r.waitingUser(), "queue": r.queue(),
			"running": r.running(), "bots": r.State == RequestPending && r.Bots, "state": r.State, "created": r.Created,
			"ends": r.Ends, "due": r.due()},
	}
}

func (r *AccessRequest) waitingUser() string {
	if r.State == RequestPending {
		return r.UserID
	}
	return ""
}

// queue is the approver list r is in: its approver group's pending requests, or the access the group gave that runs.
func (r *AccessRequest) queue() string {
	switch {
	case r.State == RequestPending:
		return AccessRequestQueue(r.Approvers, RequestPending)
	case r.Running():
		return AccessRequestQueue(r.Approvers, RequestApproved)
	}
	return ""
}

func (r *AccessRequest) running() string {
	if r.Running() {
		return AccessRequestRunning(r.UserID, r.TenantID)
	}
	return ""
}

// AccessRequestQueue is the "queue" index value of the requests approver group groupID has in state (pending, or
// approved and running).
func AccessRequestQueue(groupID, state string) string { return groupID + "/" + state }

// AccessRequestRunning is the "running" index value of userID's running requests for tenantID.
func AccessRequestRunning(userID, tenantID string) string { return userID + "/" + tenantID }

// AccessRequestPendingKey is the unique value a pending request of userID for tenantID holds.
func AccessRequestPendingKey(orgID, userID, tenantID string) string {
	return orgID + "/reqp/" + userID + "/" + tenantID
}
