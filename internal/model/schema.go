package model

// FieldType is the type of a queryable field.
type FieldType int

const (
	FieldString FieldType = iota
	FieldInt              // int64
	FieldBool
	FieldTime // time.Time, stored with at least millisecond precision
)

// Field is a queryable column of a kind. Search fields take part in search: a case-insensitive prefix match on any of
// them (the key-value stores answer it from the fields' sort indexes when every Search field of the kind has one,
// reading only the matches, not the scope); Sort fields
// may be used to order a listing (strings compare case-insensitively); every field can be used as an equality filter.
// Index fields are equality filters that must not read the whole kind: the key-value stores, which otherwise answer a
// filter by reading every record of the kind (or scope), keep one index bucket per value of the field (an index write
// per record write); the SQL backends keep an index on it (a partial one of the true values for a bool, where the
// database has them). Mark one only where a filter on it runs on a large
// kind or scope. An indexed bool field marks a small set (the records with true): a filter on false is served as the
// scope with that set left out, so the field must be set on every record of the kind (only the records with true are
// indexed). SortIndex fields are Sort fields that listings of a large kind order by: the key-value stores keep an
// ordered index per (kind, field) so such a listing pages without reading its scope (one more index write per record
// write); the SQL backends index every Sort field already. Mark the sort fields the consoles and APIs use on kinds
// that grow with the number of users or organizations, not those of small or write-heavy kinds.
type Field struct {
	Name      string
	Type      FieldType
	Search    bool
	Sort      bool
	Index     bool
	SortIndex bool
	// Words marks a string field holding a space-separated list (tags): an equality filter matches a record holding
	// the value as one of its words, ignoring case (the same on every backend), and an Index field is indexed once per
	// word.
	Words bool
}

// Schema lists a kind's queryable fields. Backends create their columns/indexes from it.
type Schema struct {
	Kind   Kind
	Fields []Field
}

// Field returns the named field.
func (s Schema) Field(name string) (Field, bool) {
	for _, f := range s.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// Schemas is the registry of every kind the store must handle. A field is listed only where a query uses it (a
// filter, a sort or a search of a listing: each costs a column and an index in the SQL stores, and an index write
// per record write in the key-value stores): a kind that is only read by id and scope has none.
var Schemas = map[Kind]Schema{
	KindOrg: {KindOrg, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "display_name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "created", Type: FieldTime, Sort: true, SortIndex: true},
	}},
	// Sort indexes: the user console's columns (username, role, active; last sign-in lives on the sign-in records),
	// SCIM's sortBy attributes (userName, displayName, emails, active, meta.created) and the management API's sorts.
	KindUser: {KindUser, []Field{
		{Name: "username", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "email", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "family_name", Type: FieldString, Search: true, Sort: true, SortIndex: true}, // "Smith" finds John Smith
		{Name: "tags", Type: FieldString, Index: true, Words: true},                         // the console's tag filter, without reading the org
		{Name: "role", Type: FieldString, Sort: true, SortIndex: true, Index: true},         // role filters (SCIM, console)
		{Name: "active", Type: FieldBool, Sort: true, SortIndex: true},
		// disabled accounts: the few, so the indexed set (a filter on active is one on inactive: service.ActiveFilter)
		{Name: "inactive", Type: FieldBool, Index: true},
		{Name: "created", Type: FieldTime, Sort: true, SortIndex: true},
		{Name: "manager_id", Type: FieldString, Index: true}, // a user's reports (deleting the manager): sparse, as empty strings are never indexed
		{Name: "expiring", Type: FieldBool, Index: true},     // the end-date sweep (ExpireUsers), across organizations
		{Name: "valid_until", Type: FieldTime, Sort: true},
		// who may see the user (service.Visibility): super admins are hidden below them, administrators are a
		// directory entry to managers. Indexed: every user listing of an ordinary administrator leaves the super
		// admins out, and must not read the organization to do so.
		{Name: "super_admin", Type: FieldBool, Index: true},
		{Name: "admin_rank", Type: FieldBool, Index: true},
	}},
	KindGroup: {KindGroup, []Field{
		{Name: "display_name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "tags", Type: FieldString, Words: true},
		{Name: "created", Type: FieldTime, Sort: true, SortIndex: true},
		{Name: "pending", Type: FieldBool, Index: true}, // groups with committed member changes not yet materialized
	}},
	KindMember: {KindMember, []Field{
		{Name: "group_id", Type: FieldString, Index: true}, // a group's members (SCIM, counts)
		{Name: "user_id", Type: FieldString, Index: true},  // a user's groups (tokens, SCIM, admin views)
	}},
	KindTenant: {KindTenant, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true},
		{Name: "display_name", Type: FieldString, Search: true, Sort: true},
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "ssh_enabled", Type: FieldBool, Index: true}, // the tenants with SSH on (housekeeping: EnsureSSHKeys)
	}},
	KindAccess: {KindAccess, []Field{
		{Name: "tenant_id", Type: FieldString, Index: true}, // a tenant's access entries (ListAccess)
	}},
	KindClient: {KindClient, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "tenant_id", Type: FieldString, Index: true},                                // a tenant's applications (the tenants page, deleting a tenant)
		{Name: "auth_method", Type: FieldString, Sort: true, Index: true, SortIndex: true}, // public clients' origins (CORS)
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "self_registered", Type: FieldBool, Index: true}, // self-registered applications (purge)
		{Name: "service_account", Type: FieldBool, Index: true}, // the organization's service accounts, listed apart
		// those nobody has let sign in yet: what the registration cap counts (service.MaxSelfRegistered), on an
		// open endpoint, so it reads at most the cap's worth, not every application ever registered
		{Name: "unused_self_registered", Type: FieldBool, Index: true},
	}},
	KindProvider: {KindProvider, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true},
		{Name: "type", Type: FieldString, Sort: true},
		{Name: "enabled", Type: FieldBool},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindPasskey: {KindPasskey, nil},
	KindIdentity: {KindIdentity, []Field{
		{Name: "provider_id", Type: FieldString, Index: true}, // a provider's links, when it is deleted
	}},
	KindSession: {KindSession, nil},
	KindGrant: {KindGrant, []Field{
		{Name: "client_id", Type: FieldString, Index: true}, // an application's users (self-registered apps)
	}},
	KindAPIToken: {KindAPIToken, []Field{
		{Name: "created", Type: FieldTime, Sort: true}, // the console lists the newest first
	}},
	KindKey: {KindKey, nil},
	// A tenant's CA keys, listed by tenant (the published keys, rotation); the certificates by tenant (user certificates
	// under tenant_id, host certificates under host_tenant_id: the KRL reads the first and the revoked of the second),
	// by user (the account page, the user's access ending) and the revoked ones, and searched by key id, fingerprint,
	// serial and principal (the tenant's certificate list).
	KindSSHKey: {KindSSHKey, []Field{
		{Name: "tenant_id", Type: FieldString, Index: true},
	}},
	KindSSHCert: {KindSSHCert, []Field{
		{Name: "tenant_id", Type: FieldString, Index: true},
		{Name: "host_tenant_id", Type: FieldString, Index: true},
		{Name: "user_id", Type: FieldString, Index: true},
		{Name: "revoked", Type: FieldBool, Index: true},
		{Name: "created", Type: FieldTime, Sort: true},
		// the console's search: the key id (it starts with the username), the key's fingerprint and the serial by their
		// start; a principal, one of the words of principals, by the whole of it
		{Name: "key_id", Type: FieldString, Search: true},
		{Name: "fingerprint", Type: FieldString, Search: true},
		{Name: "serial", Type: FieldString, Search: true},
		{Name: "principals", Type: FieldString, Words: true},
	}},
	KindEphemeral: {KindEphemeral, nil},
	KindLink:      {KindLink, nil},
	KindSignIn:    {KindSignIn, nil},
	KindLock: {KindLock, []Field{
		{Name: "org_deleted", Type: FieldBool, Index: true}, // deletions of organizations that decided (Lock.Holder)
	}},
	KindReplay: {KindReplay, nil},
	// Audit search covers who and what (actor, target) and where from (ip); the action and outcome are filters.
	KindAudit: {KindAudit, []Field{
		{Name: "action", Type: FieldString, Sort: true, SortIndex: true, Index: true}, // action= reads only those events
		{Name: "actor", Type: FieldString, Search: true},
		{Name: "target", Type: FieldString, Search: true},
		{Name: "created", Type: FieldTime, Sort: true, SortIndex: true},
		{Name: "outcome", Type: FieldString, Index: true},
		{Name: "ip", Type: FieldString, Search: true},
		// Every reader below super admin filters on false: the indexed set is the events of super admins, which such a
		// page leaves out (Audit.SuperAdmin).
		{Name: "super_admin", Type: FieldBool, Index: true},
	}},
	// A node's queue reads its items in the order they come due (due: what it delivers next), and one key's in that
	// order (slot: an organization's next logouts, when its share of the workers frees up), each a range of a sort
	// index of the node's own scope, never the whole queue (package queue).
	KindQueue: {KindQueue, []Field{
		{Name: "due", Type: FieldTime, Sort: true, SortIndex: true},
		{Name: "slot", Type: FieldString, Sort: true, SortIndex: true},
	}},
}

// Expiry says whether the records of a kind carry an expiry (Index.Expires): the stores keep what only a kind with
// expiring records needs (the SQL stores an index on it), and keep no counters of the ranges of a kind whose records
// all expire, which never answer a total (the key-value store).
type Expiry int

const (
	NeverExpires  Expiry = iota // no record sets an expiry
	MayExpire                   // some do (a removed member, a token with an end date, a key, a lease)
	AlwaysExpires               // every one does: audit events, links, replay marks, sessions, grants and queue items
)

// expiries is the Expiry of the kinds that are not NeverExpires.
var expiries = map[Kind]Expiry{
	KindMember: MayExpire, KindAPIToken: MayExpire, KindKey: MayExpire, KindSSHKey: MayExpire, KindEphemeral: MayExpire,
	KindSSHCert: AlwaysExpires,
	KindSession: AlwaysExpires, KindGrant: AlwaysExpires, KindLink: AlwaysExpires, KindAudit: AlwaysExpires,
	KindReplay: AlwaysExpires, KindQueue: AlwaysExpires,
}

// ExpiryOf is the Expiry of kind k.
func ExpiryOf(k Kind) Expiry { return expiries[k] }

// unscopedKinds are the kinds whose records have no scope (Index.Scope ""): a query with Scope "" selects the whole
// kind, which is also the empty scope.
var unscopedKinds = map[Kind]bool{KindOrg: true, KindKey: true, KindSignIn: true, KindLock: true, KindReplay: true, KindEphemeral: true}

// Unscoped reports whether every record of kind k has Scope "".
func Unscoped(k Kind) bool { return unscopedKinds[k] }

// Kinds returns every registered kind in a stable order.
func Kinds() []Kind {
	return []Kind{KindOrg, KindUser, KindGroup, KindMember, KindTenant, KindAccess, KindClient, KindProvider, KindPasskey, KindIdentity, KindSession,
		KindGrant, KindAPIToken, KindKey, KindSSHKey, KindSSHCert, KindAudit, KindLink, KindSignIn, KindLock, KindReplay, KindEphemeral, KindQueue}
}

// NewEntity returns an empty entity of kind k, or nil for an unknown kind.
func NewEntity(k Kind) Entity {
	switch k {
	case KindOrg:
		return &Org{}
	case KindUser:
		return &User{}
	case KindGroup:
		return &Group{}
	case KindMember:
		return &Member{}
	case KindTenant:
		return &Tenant{}
	case KindAccess:
		return &TenantAccess{}
	case KindClient:
		return &Client{}
	case KindProvider:
		return &Provider{}
	case KindPasskey:
		return &Passkey{}
	case KindIdentity:
		return &Identity{}
	case KindSession:
		return &Session{}
	case KindGrant:
		return &Grant{}
	case KindAPIToken:
		return &APIToken{}
	case KindKey:
		return &SigningKey{}
	case KindSSHKey:
		return &SSHKey{}
	case KindSSHCert:
		return &SSHCert{}
	case KindAudit:
		return &Audit{}
	case KindLink:
		return &LinkToken{}
	case KindSignIn:
		return &SignIn{}
	case KindLock:
		return &Lock{}
	case KindReplay:
		return &Replay{}
	case KindEphemeral:
		return &Ephemeral{}
	case KindQueue:
		return &QueueItem{}
	}
	return nil
}
