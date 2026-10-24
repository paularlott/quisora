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
// per record write); the SQL backends index every field already. Mark one only where a filter on it runs on a large
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

// Schemas is the registry of every kind the store must handle.
var Schemas = map[Kind]Schema{
	KindOrg: {KindOrg, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "display_name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "primary", Type: FieldBool},
		{Name: "created", Type: FieldTime, Sort: true, SortIndex: true},
	}},
	// Sort indexes: the user console's columns (username, role, active; last sign-in lives on the sign-in records),
	// SCIM's sortBy attributes (userName, displayName, emails, active, meta.created) and the management API's sorts.
	KindUser: {KindUser, []Field{
		{Name: "username", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "email", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "family_name", Type: FieldString, Search: true, Sort: true, SortIndex: true}, // "Smith" finds John Smith
		{Name: "external_id", Type: FieldString},
		{Name: "tags", Type: FieldString, Index: true, Words: true}, // the console's tag filter, without reading the org
		{Name: "role", Type: FieldString, Sort: true, SortIndex: true},
		{Name: "active", Type: FieldBool, Sort: true, SortIndex: true},
		{Name: "created", Type: FieldTime, Sort: true, SortIndex: true},
		{Name: "user_type", Type: FieldString, Sort: true},
		{Name: "department", Type: FieldString, Sort: true},
		{Name: "manager_id", Type: FieldString},
		{Name: "employee_number", Type: FieldString},
		{Name: "expiring", Type: FieldBool},
		{Name: "valid_until", Type: FieldTime, Sort: true},
		// who may see the user (service.Visibility): super admins are hidden below them, administrators are a
		// directory entry to managers. Indexed: every user listing of an ordinary administrator leaves the super
		// admins out, and must not read the organization to do so.
		{Name: "super_admin", Type: FieldBool, Index: true},
		{Name: "admin_rank", Type: FieldBool, Index: true},
	}},
	KindGroup: {KindGroup, []Field{
		{Name: "display_name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "external_id", Type: FieldString},
		{Name: "tags", Type: FieldString, Words: true},
		{Name: "created", Type: FieldTime, Sort: true, SortIndex: true},
		{Name: "pending", Type: FieldBool, Index: true}, // groups with committed member changes not yet materialized
	}},
	KindMember: {KindMember, []Field{
		{Name: "group_id", Type: FieldString, Index: true}, // a group's members (SCIM, counts)
		{Name: "user_id", Type: FieldString, Index: true},  // a user's groups (tokens, SCIM, admin views)
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindTenant: {KindTenant, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true},
		{Name: "display_name", Type: FieldString, Search: true, Sort: true},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindAccess: {KindAccess, []Field{
		{Name: "tenant_id", Type: FieldString},
		{Name: "subject_id", Type: FieldString},
		{Name: "subject_type", Type: FieldString},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindClient: {KindClient, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true, SortIndex: true},
		{Name: "tenant_id", Type: FieldString},
		{Name: "auth_method", Type: FieldString, Sort: true, Index: true, SortIndex: true}, // public clients' origins (CORS)
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "self_registered", Type: FieldBool, Index: true}, // self-registered applications (cap, purge)
	}},
	KindProvider: {KindProvider, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true},
		{Name: "type", Type: FieldString, Sort: true},
		{Name: "enabled", Type: FieldBool},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindPasskey: {KindPasskey, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true},
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "last_used", Type: FieldTime, Sort: true},
	}},
	KindIdentity: {KindIdentity, []Field{
		{Name: "provider_id", Type: FieldString, Index: true}, // a provider's links, when it is deleted
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindSession: {KindSession, []Field{
		{Name: "ip", Type: FieldString, Search: true},
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "last_seen", Type: FieldTime, Sort: true},
	}},
	KindGrant: {KindGrant, []Field{
		{Name: "client_id", Type: FieldString, Index: true}, // an application's users (self-registered apps)
		{Name: "session_id", Type: FieldString},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindAPIToken: {KindAPIToken, []Field{
		{Name: "name", Type: FieldString, Search: true, Sort: true},
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "last_used", Type: FieldTime, Sort: true},
	}},
	KindKey: {KindKey, []Field{
		{Name: "alg", Type: FieldString},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindEphemeral: {KindEphemeral, nil},
	KindLink: {KindLink, []Field{
		{Name: "purpose", Type: FieldString},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindSignIn: {KindSignIn, []Field{
		{Name: "last_login", Type: FieldTime, Sort: true},
	}},
	KindLock:   {KindLock, nil},
	KindReplay: {KindReplay, nil},
	// Audit search covers who and what (actor, target) and where from (ip); the action and outcome are filters.
	KindAudit: {KindAudit, []Field{
		{Name: "action", Type: FieldString, Sort: true, SortIndex: true},
		{Name: "actor", Type: FieldString, Search: true},
		{Name: "target", Type: FieldString, Search: true},
		{Name: "created", Type: FieldTime, Sort: true, SortIndex: true},
		{Name: "outcome", Type: FieldString},
		{Name: "ip", Type: FieldString, Search: true},
	}},
}

// unscopedKinds are the kinds whose records have no scope (Index.Scope ""): a query with Scope "" selects the whole
// kind, which is also the empty scope.
var unscopedKinds = map[Kind]bool{KindOrg: true, KindKey: true, KindLock: true, KindReplay: true, KindEphemeral: true}

// Unscoped reports whether every record of kind k has Scope "".
func Unscoped(k Kind) bool { return unscopedKinds[k] }

// Kinds returns every registered kind in a stable order.
func Kinds() []Kind {
	return []Kind{KindOrg, KindUser, KindGroup, KindMember, KindTenant, KindAccess, KindClient, KindProvider, KindPasskey, KindIdentity, KindSession,
		KindGrant, KindAPIToken, KindKey, KindAudit, KindLink, KindSignIn, KindLock, KindReplay, KindEphemeral}
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
	}
	return nil
}
