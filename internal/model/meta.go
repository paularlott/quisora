// Package model holds the persisted entity types and how each one is indexed by the store.
package model

import (
	"encoding/binary"
	"math/bits"
	"slices"
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
	KindSSHKey   Kind = "sshkey"  // a tenant's SSH CA keys (SSHKey)
	KindSSHCert  Kind = "sshcert" // the SSH certificates issued, until they expire (SSHCert)
	KindAudit    Kind = "audit"
	KindLink     Kind = "link"
	KindSignIn   Kind = "signin" // a user's sign-in stamps (SignIn)
	KindLock     Kind = "lock"   // leases (Lock), such as each node's master key report
	KindReplay   Kind = "replay" // single-use values seen, until they expire (Replay)
	// KindEphemeral holds short-lived sign-in state (codes, flows, challenges, counters) in a shared database, so
	// every node of a cluster without gossip sees it. Never backed up or replicated.
	KindEphemeral Kind = "eph"
	// KindQueue holds the items of a node's retry queues (QueueItem): emails waiting for SMTP, back-channel logouts
	// waiting for their application. Node-local: never replicated, backed up or delivered by another node.
	KindQueue Kind = "queue"
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
	//     clients, providers, passkeys, identities, sessions, grants, API tokens, SSH CA keys and certificates, audit
	//     events, link tokens, sign-in records): the OrgID, so an organization's records, and every unique value scoped to it, share a partition.
	//     An entity whose OrgID is empty (a server-level audit event) is global;
	//   - KindOrg and KindKey (organizations, signing keys): "". They are read by every organization and by pages that
	//     have no organization yet, and the organization list is one record set;
	//   - KindReplay and KindLock: the record's own ID. Each is one compare-and-swap on one record, independent of every
	//     other, so they spread over the partitions instead of loading partition 0 (an organization's deletion guard,
	//     a Lock whose id is the organization's, is so in the organization's partition, with its users);
	//   - KindEphemeral and KindQueue: "". They are node-local (or shared-database) state that is never replicated by
	//     partition, so the key is never used.
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

// base62 spells ids: the 62 letters and digits in ASCII order.
const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// IDLen is the length of every id (NewID): 22 base-62 digits hold 128 bits (62^22 > 2^128).
const IDLen = 22

// NewID returns a new id: the 16 bytes of a UUIDv7 (a 48-bit millisecond timestamp, then random bits) in 22
// characters (FormatID). An id made in a later millisecond, or later by this process, sorts after an earlier one.
func NewID() string { return FormatID(uuid.Must(uuid.NewV7())) }

// pow62x10 is 62^10, the largest power of 62 a uint64 holds: FormatID divides the 128-bit value by it twice and so
// spells ten digits at a time in plain 64-bit arithmetic.
const pow62x10 = 839299365868340224

// FormatID spells 16 bytes as an id: their big-endian 128-bit value in base 62, left-padded with '0' to IDLen. Being
// fixed-width in an alphabet in ASCII order, the string order of two ids is the numeric order of their bytes, so the
// store, which lists and pages a scope in id order, lists it in creation order. Letters and digits only: a
// double-click selects a whole id, and it needs no escaping in a URL, a path, a file name or a token (qsr_<id>_...).
func FormatID(b [16]byte) string {
	hi, lo := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
	var out [IDLen]byte
	i := IDLen
	for range 2 {
		var r uint64
		hi, r = hi/pow62x10, hi%pow62x10
		lo, r = bits.Div64(r, lo, pow62x10)
		for range 10 {
			i--
			out[i] = base62[r%62]
			r /= 62
		}
	}
	// What is left is below 2^128 / 62^20 (under 500): the two leading digits, hi now 0.
	out[1], out[0] = base62[lo%62], base62[lo/62]
	return string(out[:])
}

// maxID is the id of the largest 128-bit value (FormatID of 16 bytes 0xff). A string of IDLen base-62 digits that
// sorts after it is a value no 16 bytes hold, so not an id: each id has exactly one spelling.
const maxID = "7n42DGM5Tflk9n8mt7Fhc7"

// IsID reports whether s is an id in its one spelling (FormatID). An organization's name never is (ValidOrgName), so a
// path segment names an organization by id or by name unambiguously (/o/<id or name>).
func IsID(s string) bool {
	if len(s) != IDLen || s > maxID {
		return false
	}
	for i := range len(s) {
		if c := s[i]; !('0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z') {
			return false
		}
	}
	return true
}

// ClientIDPrefix starts every client ID, so a client ID is recognizable where it is pasted (an application's config,
// a log line) and cannot be mistaken for the client secret.
const ClientIDPrefix = "c_"

// NewClientID returns a client ID: ClientIDPrefix and a new id (NewID), so clients still list and page in creation
// order.
func NewClientID() string { return ClientIDPrefix + NewID() }

// Lower is the form of a value in a unique key: case-insensitive, and compatibility forms folded (NFKC), so that a
// full-width "ａｄｍｉｎ" or a ligature claims the same key as "admin" instead of passing for another name. The value
// itself is stored as given.
func Lower(s string) string { return strings.ToLower(norm.NFKC.String(strings.TrimSpace(s))) }

// UpstreamAMRMax is the most authentication method references kept from an upstream provider's ID token.
const UpstreamAMRMax = 16

// CleanAMR returns the authentication method references an upstream provider reported (its ID token's amr claim, a
// list of strings: RFC 8176 values such as "pwd" and "mfa", or the provider's own), as Quisora passes them on in its
// tokens: values of 1 to 32 letters, digits, '_', '-', '.' or ':', each once, in the provider's order, at most
// UpstreamAMRMax of them; anything else is left out, and nil when nothing is left. They are what the provider says,
// never what Quisora's own decisions read (Session.AMR).
func CleanAMR(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		s, ok := x.(string)
		if !ok || len(s) == 0 || len(s) > 32 || len(out) == UpstreamAMRMax || slices.Contains(out, s) {
			continue
		}
		if strings.IndexFunc(s, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-.:", r))
		}) >= 0 {
			continue
		}
		out = append(out, s)
	}
	return out
}

// TokenAMR is the amr of tokens issued for a sign-in: Quisora's own references (amr, what its decisions read) and
// then those the upstream provider reported (upstream) that are not among them, except "mfa": a token says a second
// factor was used only when Quisora's own references do (Quisora asked for one, or trusts the provider's), never on
// the provider's word alone, which applications reading amr for "mfa" would take for a fact.
func TokenAMR(amr, upstream []string) []string {
	out := slices.Clone(amr)
	for _, a := range upstream {
		if a != "mfa" && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

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
