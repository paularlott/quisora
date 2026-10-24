package model

// FieldType is the type of a queryable field.
type FieldType int

const (
	FieldString FieldType = iota
	FieldInt              // int64
	FieldBool
	FieldTime // time.Time, stored with at least millisecond precision
)

// Field is a queryable column of a kind. Search fields take part in case-insensitive substring search; Sort fields
// may be used to order a listing (strings compare case-insensitively); every field can be used as an equality filter.
type Field struct {
	Name   string
	Type   FieldType
	Search bool
	Sort   bool
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
		{Name: "name", Type: FieldString, Search: true, Sort: true},
		{Name: "display_name", Type: FieldString, Search: true, Sort: true},
		{Name: "primary", Type: FieldBool},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindUser: {KindUser, []Field{
		{Name: "username", Type: FieldString, Search: true, Sort: true},
		{Name: "email", Type: FieldString, Search: true, Sort: true},
		{Name: "name", Type: FieldString, Search: true, Sort: true},
		{Name: "external_id", Type: FieldString},
		{Name: "tags", Type: FieldString, Search: true},
		{Name: "role", Type: FieldString, Sort: true},
		{Name: "active", Type: FieldBool, Sort: true},
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "user_type", Type: FieldString, Sort: true},
		{Name: "department", Type: FieldString, Search: true, Sort: true},
		{Name: "manager_id", Type: FieldString},
		{Name: "employee_number", Type: FieldString},
		{Name: "expiring", Type: FieldBool},
		{Name: "valid_until", Type: FieldTime, Sort: true},
		// who may see the user (service.Visibility): super admins are hidden below them, administrators are a
		// directory entry to managers
		{Name: "super_admin", Type: FieldBool},
		{Name: "admin_rank", Type: FieldBool},
	}},
	KindGroup: {KindGroup, []Field{
		{Name: "display_name", Type: FieldString, Search: true, Sort: true},
		{Name: "external_id", Type: FieldString},
		{Name: "tags", Type: FieldString, Search: true},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindMember: {KindMember, []Field{
		{Name: "group_id", Type: FieldString},
		{Name: "user_id", Type: FieldString},
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
		{Name: "name", Type: FieldString, Search: true, Sort: true},
		{Name: "tenant_id", Type: FieldString},
		{Name: "auth_method", Type: FieldString, Sort: true},
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "self_registered", Type: FieldBool},
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
		{Name: "provider_id", Type: FieldString},
		{Name: "created", Type: FieldTime, Sort: true},
	}},
	KindSession: {KindSession, []Field{
		{Name: "ip", Type: FieldString, Search: true},
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "last_seen", Type: FieldTime, Sort: true},
	}},
	KindGrant: {KindGrant, []Field{
		{Name: "client_id", Type: FieldString},
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
		{Name: "action", Type: FieldString, Sort: true},
		{Name: "actor", Type: FieldString, Search: true},
		{Name: "target", Type: FieldString, Search: true},
		{Name: "created", Type: FieldTime, Sort: true},
		{Name: "outcome", Type: FieldString},
		{Name: "ip", Type: FieldString, Search: true},
	}},
}

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
