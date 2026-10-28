// Package model holds the persisted entity types and how each one is indexed by the store.
package model

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/paularlott/gossip/hlc"
	"golang.org/x/text/unicode/norm"
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
	KindLock     Kind = "lock"   // leases (Lock), such as each node's master key report
	KindReplay   Kind = "replay" // single-use values seen, until they expire (Replay)
	// KindEphemeral holds short-lived sign-in state (codes, flows, challenges, counters) in a shared database, so
	// every node of a cluster without gossip sees it. Never backed up or replicated.
	KindEphemeral Kind = "eph"
)

// Meta is embedded in every stored entity.
type Meta struct {
	ID      string        `msgpack:"id" json:"id"`
	Version hlc.Timestamp `msgpack:"v" json:"-"`
	Created time.Time     `msgpack:"c" json:"created"`
	Updated time.Time     `msgpack:"u" json:"updated"`
}

// GetMeta returns the entity's metadata; every entity gets it by embedding Meta.
func (m *Meta) GetMeta() *Meta { return m }

// Index describes how a record is found: the listing scope, unique lookup values, queryable fields and expiry.
type Index struct {
	Scope   string
	Unique  []string
	Fields  map[string]any // values: string, int64, bool or time.Time
	Expires time.Time
	// Partition is the record's partition key: the records with one key are replicated, ordered and owned together
	// (docs/design/partitioned-replication.md). The empty key is the global partition (partition 0); any other key is
	// hashed to a partition by the cluster layer. A record never changes its key. Per kind:
	//
	//   - everything scoped to an organization (an entity with an OrgID: users, groups, memberships, tenants, access,
	//     clients, providers, passkeys, identities, sessions, grants, API tokens, audit events, link tokens, sign-in
	//     records): the OrgID, so an organization's records, and every unique value scoped to it, share a partition.
	//     An entity whose OrgID is empty (a server-level audit event) is global;
	//   - KindOrg and KindKey (organizations, signing keys): "". They are read by every organization and by pages that
	//     have no organization yet, and the organization list is one record set;
	//   - KindReplay and KindLock: the record's own ID. Each is one compare-and-swap on one record, independent of every
	//     other, so they spread over the partitions instead of loading partition 0 (an organization's deletion guard,
	//     a Lock whose id is the organization's, is so in the organization's partition, with its users);
	//   - KindEphemeral: "". It is node-local (or shared-database) state that is never replicated by partition, so the
	//     key is never used.
	Partition string
}

// UniquePartition is the partition key (Index.Partition) of the record of kind k that holds unique value v, when v
// names it: "" for an organization's name (organizations are global), and the organization's id for the values of
// users, groups, tenants and providers, which all start with it (UserUsernameKey, GroupNameKey, TenantNameKey, ...). A
// cluster node answers a value found nowhere from that one partition's copy. ok is false where v does not name the
// organization (a passkey's, an identity's or a link token's value is scoped by a user, a provider or nothing), or
// where its first segment is not an id.
func UniquePartition(k Kind, v string) (key string, ok bool) {
	switch k {
	case KindOrg:
		return "", true
	case KindUser, KindGroup, KindTenant, KindProvider:
		org, _, found := strings.Cut(v, "/")
		return org, found && IsID(org)
	}
	return "", false
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

// IsID reports whether s has the form of an id (NewID: a UUID in its canonical form). An organization's name never
// does (ValidOrgName), so a path segment names an organization by id or by name unambiguously (/o/<id or name>).
func IsID(s string) bool {
	if len(s) != 36 {
		return false
	}
	_, err := uuid.Parse(s)
	return err == nil
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

// Lower is the form of a value in a unique key: case-insensitive, and compatibility forms folded (NFKC), so that a
// full-width "ａｄｍｉｎ" or a ligature claims the same key as "admin" instead of passing for another name. The value
// itself is stored as given.
func Lower(s string) string { return strings.ToLower(norm.NFKC.String(strings.TrimSpace(s))) }

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

// Fixed ids of what "quisora bootstrap" creates, each written only where no record with its id exists (a create):
// bootstrapping by mistake (a new node of a running cluster, a second run) can never overwrite the primary organization
// (however renamed), its default tenant or the first super admin.
const (
	PrimaryOrgID     = "00000000-0000-7000-8000-000000000001"
	BootstrapAdminID = "00000000-0000-7000-8000-000000000002"
	PrimaryTenantID  = "00000000-0000-7000-8000-000000000003"
)
