// Package model holds the persisted entity types and how each one is indexed by the store.
package model

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/paularlott/gossip/hlc"
)

// Kind names a type of stored record.
type Kind string

const (
	KindOrg      Kind = "org"
	KindUser     Kind = "user"
	KindGroup    Kind = "group"
	KindMember   Kind = "member"
	KindTenant   Kind = "tenant"
	KindAccess   Kind = "access"
	KindClient   Kind = "client"
	KindProvider Kind = "provider"
	KindPasskey  Kind = "passkey"
	KindIdentity Kind = "identity"
	KindSession  Kind = "session"
	KindGrant    Kind = "grant"
	KindAPIToken Kind = "apitoken"
	KindKey      Kind = "key"
	KindAudit    Kind = "audit"
	KindLink     Kind = "link"
	KindSignIn   Kind = "signin" // a user's sign-in stamps (SignIn)
	KindLock     Kind = "lock"   // cluster-wide locks (Lock)
	KindReplay   Kind = "replay" // single-use values seen, until they expire (Replay)
	// KindEphemeral holds short-lived sign-in state (codes, flows, challenges, counters) in a shared database, so
	// every node of a cluster without gossip sees it. Never backed up or replicated.
	KindEphemeral Kind = "eph"
)

// QuorumCAS reports whether writes of kind k are security-sensitive: in a replicated cluster each one is a
// cluster-wide compare-and-swap that a majority of the nodes must confirm before it succeeds (see
// docs/REPLICATION.md, "Quorum compare-and-swap"), so a concurrent change made on another node from an older copy is
// refused instead of overwriting it. Refresh grants are among them: rotating a refresh token advances the grant's
// counter, and a node that had not seen the advance must not accept the old token. Groups are too: a group's version
// is the lock on a change of its members (service.ChangeGroup), which must hold across the cluster.
func QuorumCAS(k Kind) bool {
	switch k {
	case KindUser, KindPasskey, KindAPIToken, KindClient, KindProvider, KindTenant, KindAccess, KindOrg, KindMember,
		KindGroup, KindSignIn, KindLock, KindGrant, KindReplay:
		return true
	}
	return false
}

// Meta is embedded in every stored entity.
type Meta struct {
	ID      string        `msgpack:"id" json:"id"`
	Version hlc.Timestamp `msgpack:"v" json:"-"`
	Created time.Time     `msgpack:"c" json:"created"`
	Updated time.Time     `msgpack:"u" json:"updated"`
	// Conflict is set when the cluster replicated this record and another one, created before it, claiming the
	// same unique value (an email address, a name): the value was removed from this record (ReleaseUnique) and
	// this says so, for administrators. Cleared by nothing: the audit log has the event too.
	Conflict string `msgpack:"cf,omitempty" json:"conflict,omitempty"`
}

// GetMeta returns the entity's metadata; every entity gets it by embedding Meta.
func (m *Meta) GetMeta() *Meta { return m }

// Index describes how a record is found: the listing scope, unique lookup values, queryable fields and expiry.
type Index struct {
	Scope   string
	Unique  []string
	Fields  map[string]any // values: string, int64, bool or time.Time
	Expires time.Time
}

// Due reports when a housekeeping job must look at a record of kind k with index fields f, and whether it must at
// all. Backends whose filtered queries read a whole kind index records by it (store.DueLister). Users: an active
// account with an end date is disabled then (Service.ExpireUsers).
func Due(k Kind, f map[string]any) (time.Time, bool) {
	if k == KindUser && f["expiring"] == true && f["active"] == true {
		if t, ok := f["valid_until"].(time.Time); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

// Entity is implemented by every stored type.
type Entity interface {
	GetMeta() *Meta
	Kind() Kind
	Index() Index
}

// NewID returns a time-ordered UUIDv7 string.
func NewID() string {
	return uuid.Must(uuid.NewV7()).String()
}

// ClientIDPrefix starts every client ID, so a client ID is recognizable where it is pasted (an application's config,
// a log line) and cannot be mistaken for the client secret.
const ClientIDPrefix = "c_"

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" // ASCII order

// NewClientID returns a client ID: ClientIDPrefix and a UUIDv7 in 22 base-62 characters (c_0dk2Yv…). It carries the
// same 128 bits as NewID and, being fixed-width in an alphabet in ASCII order, sorts byte-wise in the same order, so
// clients still list and page in creation order. It has no hyphens, so a double-click selects all of it.
func NewClientID() string { return ClientIDFromUUID(uuid.Must(uuid.NewV7())) }

// ClientIDFromUUID formats u as a client ID (see NewClientID).
func ClientIDFromUUID(u uuid.UUID) string {
	var out [22]byte
	n := u // a 128-bit big-endian number, divided down by 62 in place
	for i := len(out) - 1; i >= 0; i-- {
		rem := 0
		for j := range n {
			v := rem<<8 | int(n[j])
			n[j], rem = byte(v/62), v%62
		}
		out[i] = base62[rem]
	}
	return ClientIDPrefix + string(out[:])
}

// Lower is used for case-insensitive unique keys.
func Lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// MFA reports whether a sign-in's amr shows two factors: "mfa", a password with a one-time code, or a passkey that
// verified its user ("hwk"/"swk" with "user"; a passkey without user verification is one factor).
func MFA(amr []string) bool {
	var pwd, otp, key, uv bool
	for _, a := range amr {
		switch a {
		case "mfa":
			return true
		case "pwd":
			pwd = true
		case "otp":
			otp = true
		case "hwk", "swk":
			key = true
		case "user":
			uv = true
		}
	}
	return (pwd && otp) || (key && uv)
}

// Fixed ids of what "quisora bootstrap" creates, and the version it writes them with: the oldest possible, so a record
// that already exists anywhere — on this node, in a shared database, or on any peer of a gossip cluster — is newer
// and wins. Bootstrapping by mistake (a new node of a running cluster, a second run) can never overwrite the primary
// organization (however renamed), its default tenant or the first super admin. Any later change has a normal,
// newer version.
const (
	PrimaryOrgID     = "00000000-0000-7000-8000-000000000001"
	BootstrapAdminID = "00000000-0000-7000-8000-000000000002"
	PrimaryTenantID  = "00000000-0000-7000-8000-000000000003"
)

// BootstrapVersion is the version of records written by bootstrap (see PrimaryOrgID): the smallest there is (the
// clock's own epoch, counter 1). Every version any node mints is larger.
const BootstrapVersion hlc.Timestamp = 1

// IsBootstrapRecord reports whether a record is one bootstrap wrote and nobody has changed since. Peers accept such
// a record although its version is older than the tombstone retention (it is not a deleted record coming back: its
// version is the fixed bootstrap one).
func IsBootstrapRecord(kind Kind, id string, version hlc.Timestamp) bool {
	return version == BootstrapVersion && IsBootstrapID(kind, id)
}

// IsBootstrapID reports whether kind and id name one of the records "quisora bootstrap" creates, at any version.
func IsBootstrapID(kind Kind, id string) bool {
	switch {
	case kind == KindOrg && id == PrimaryOrgID, kind == KindUser && id == BootstrapAdminID, kind == KindTenant && id == PrimaryTenantID:
		return true
	}
	return false
}
