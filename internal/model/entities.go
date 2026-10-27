package model

import (
	"cmp"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------------------------------------------
// Organizations

// OrgSettings are per-organization sign-in and session policies. Zero durations mean "use the server default".
type OrgSettings struct {
	PasswordLogin bool `msgpack:"pw" json:"password_login"`
	PasswordReset bool `msgpack:"pr" json:"password_reset"` // users may reset a forgotten password by email
	PasskeyLogin  bool `msgpack:"pk" json:"passkey_login"`
	RequireMFA    bool `msgpack:"mfa" json:"require_mfa"`
	// EmailCodes lets people without an authenticator app or passkey give the second factor as a one-time code
	// emailed to their verified address (not managers and above). Off by default: weaker than an app or a passkey.
	EmailCodes  bool `msgpack:"ec,omitempty" json:"email_codes"`
	SessionTTL  int  `msgpack:"sttl" json:"session_ttl"`  // seconds
	SessionIdle int  `msgpack:"sidl" json:"session_idle"` // seconds
}

// DefaultOrgSettings is applied to new organizations.
func DefaultOrgSettings() OrgSettings {
	return OrgSettings{PasswordLogin: true, PasswordReset: true, PasskeyLogin: true}
}

type Org struct {
	Meta
	Name        string      `msgpack:"n" json:"name"`
	DisplayName string      `msgpack:"dn" json:"display_name"`
	Primary     bool        `msgpack:"p" json:"primary"`
	Settings    OrgSettings `msgpack:"s" json:"settings"`
	// SignOut are the organization's emergency sign-out counters (signout.go); LastSignOut the last pull.
	SignOut     SignOutCounters `msgpack:"so" json:"-"`
	LastSignOut *SignOutEvent   `msgpack:"lso,omitempty" json:"last_sign_out,omitempty"`
	// ServerSignOut and LastServerSignOut are the server's, kept on the primary organization (moved with the role).
	ServerSignOut     SignOutCounters `msgpack:"sso" json:"-"`
	LastServerSignOut *SignOutEvent   `msgpack:"lsso,omitempty" json:"-"`
}

func (o *Org) Kind() Kind { return KindOrg }
func (o *Org) Index() Index {
	return Index{
		Partition: "", // global: every organization's page and sign-in reads the organization list
		Unique:    []string{OrgNameKey(o.Name)},
		Fields:    map[string]any{"name": o.Name, "display_name": o.DisplayName, "primary": o.Primary, "created": o.Created},
	}
}

// OrgNameKey is the unique key for an organization name.
func OrgNameKey(name string) string { return Lower(name) }

var orgNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ReservedOrgNames cannot be used because they collide with routes or would confuse users.
var ReservedOrgNames = map[string]bool{
	"admin": true, "api": true, "login": true, "logout": true, "scim": true, "oauth": true, "static": true,
	"assets": true, "account": true, "health": true, "healthz": true, "readyz": true, "well-known": true,
	"www": true, "auth": true, "signin": true, "signup": true, "register": true, "system": true, "root": true,
	"null": true, "undefined": true, "callback": true, "invite": true, "reset": true, "verify-email": true,
	"api-docs": true, "branding": true, "oauth2": true, "openid": true, "well-known-openid": true, "new": true, "settings": true, "help": true, "docs": true,
}

// ValidOrgName reports whether name is a URL-safe, unreserved organization name.
func ValidOrgName(name string) bool {
	return orgNameRe.MatchString(name) && !ReservedOrgNames[name]
}

// ---------------------------------------------------------------------------------------------------------------
// Users

type Role string

const (
	RoleSuperAdmin Role = "super_admin"
	RoleAdmin      Role = "admin"
	RoleManager    Role = "manager"
	RoleUser       Role = "user"
)

// Rank orders roles: higher outranks lower.
func (r Role) Rank() int {
	switch r {
	case RoleSuperAdmin:
		return 3
	case RoleAdmin:
		return 2
	case RoleManager:
		return 1
	}
	return 0
}

// Privileged reports whether the role manages others (manager and above). Privileged users always sign in with a
// second factor, whatever their organization requires, and use the console and API tokens only from such a session.
func (r Role) Privileged() bool { return r.Rank() >= RoleManager.Rank() }

func (r Role) Valid() bool {
	switch r {
	case RoleSuperAdmin, RoleAdmin, RoleManager, RoleUser:
		return true
	}
	return false
}

type User struct {
	Meta
	OrgID         string `msgpack:"o" json:"org_id"`
	Username      string `msgpack:"un" json:"username"`
	Email         string `msgpack:"em" json:"email"`
	EmailVerified bool   `msgpack:"ev" json:"email_verified"`
	// PhoneNumber is a contact number in E.164 form (+441632960123), for applications' directories; it is never
	// used to sign in or to send codes.
	PhoneNumber   string `msgpack:"pn,omitempty" json:"phone_number,omitempty"`
	PhoneVerified bool   `msgpack:"pv,omitempty" json:"phone_number_verified"`
	GivenName     string `msgpack:"gn" json:"given_name"`
	FamilyName    string `msgpack:"fn" json:"family_name,omitempty"`
	Role          Role   `msgpack:"r" json:"role"`
	Active        bool   `msgpack:"a" json:"active"`
	PasswordHash  string `msgpack:"ph" json:"-"`
	TOTPSecret    string `msgpack:"ts" json:"-"` // sealed (the replay-protection step is SignIn.TOTPLastStep)
	ExternalID    string `msgpack:"x" json:"external_id,omitempty"`
	Locale        string `msgpack:"lc" json:"locale,omitempty"`   // BCP 47 language tag (NormalizeLocale)
	ZoneInfo      string `msgpack:"tz" json:"zoneinfo,omitempty"` // IANA time zone
	UserType      string `msgpack:"ut" json:"user_type,omitempty"`
	// ValidUntil ends the account at that moment: it can no longer sign in or use tokens, and the housekeeping sweep
	// disables it (ending its sessions, with back-channel logout). Nil: no end.
	ValidUntil *time.Time `msgpack:"vu,omitempty" json:"valid_until"`
	Work       Work       `msgpack:"wk" json:"work"`
	// LastLogin is not stored with the user: sign-in stamps live in the user's SignIn record, so a sign-in never
	// rewrites the user (and never races an administrator's change of it). Reads that show it fill it in
	// (service.Service.WithSignIn).
	LastLogin time.Time `msgpack:"-" json:"last_login"`
	Tags      []string  `msgpack:"tg" json:"tags"`
	// LinkedEmails are further addresses of the user. They share the per-org email namespace with Email (no address
	// is anyone's primary or linked address twice) and let upstream providers that report one of them find the user.
	LinkedEmails []LinkedEmail `msgpack:"le" json:"linked_emails"`
	// Lifecycle: the latest of each is kept on the user, for good; the audit log holds the history.
	// PasswordChangedAt is when the password was last set or removed; MFAEnrolledAt when the authenticator app was
	// last set up (nil without one).
	PasswordChangedAt *time.Time `msgpack:"pca,omitempty" json:"password_changed_at"`
	MFAEnrolledAt     *time.Time `msgpack:"mfa,omitempty" json:"mfa_enrolled_at"`
	// RecoveryCodes are the hashes of the user's recovery codes (service.CreateRecoveryCodes), each a second factor
	// once; RecoveryCreated is when they were made. The codes used are in SignIn.RecoveryUsed.
	RecoveryCodes   []string   `msgpack:"rc,omitempty" json:"-"`
	RecoveryCreated *time.Time `msgpack:"rct,omitempty" json:"-"`
	// StatusChanged records the last time the account was disabled or enabled again (Active says which).
	StatusChanged *StatusChange `msgpack:"stc,omitempty" json:"status_changed"`
	// SecurityGen is the account's security generation: a counter that moves on with every change of what signs the
	// account in — the password (set, changed, removed or reset), the authenticator app (set up, replaced or
	// removed), a passkey (added, removed or disabled), the recovery codes (made or dropped), a connected sign-in
	// provider, and the account being disabled or enabled again (service: securityState, AdvanceSecurity). Every
	// sign-in or set-up in flight — a ticket between the steps of a sign-in, an authenticator secret being confirmed,
	// a passkey ceremony, a re-authentication, a reset or invitation link — records the generation it started under
	// and is refused once the account's has moved on: whoever holds it must start again with the account's
	// credentials as they are now, so a step passed with a password that has since been changed, or a set-up begun
	// before the owner set up their own second factor, grants nothing. Written with the user, so it changes exactly
	// when the record it describes does; the write is a compare-and-swap on the user's version, so two completions
	// racing to set a first factor cannot both succeed. (The role, address and end date are not credentials: each
	// step judges them afresh from the live user.)
	SecurityGen uint64 `msgpack:"sg,omitempty" json:"-"`
	// CredEpoch and SessionEpoch say which of the account's credentials and sign-ins count. A passkey, connected
	// provider or API token works only while its Epoch is the account's CredEpoch (Holds); a session or refresh grant
	// only while its Epoch is the account's SessionEpoch (SessionHolds). Each is made with the account's epoch as it is
	// then. A change that ends them all gives the account a new random epoch in the same compare-and-swap of this
	// record that makes the change — an accepted invitation or a reset of the account's sign-in both epochs, a
	// password reset the session epoch — so the old ones stop working at that very write, and a passkey stored for the
	// new epoch beforehand starts working at it, whatever happens to the records themselves: removing them afterwards
	// is only tidying, of the epoch that write replaced and no other. The user record is the one commit point for which
	// credentials and sign-ins are valid.
	CredEpoch    uint64 `msgpack:"ce,omitempty" json:"-"`
	SessionEpoch uint64 `msgpack:"se,omitempty" json:"-"`
	// Removed lists the passkeys and provider links removed one by one in the current credential epoch. Removing one
	// is a compare-and-swap of this record that adds it here (service.removeWay): it stops counting at that write,
	// and a removal decided on an older copy of the account is refused, so two removals at once cannot each take
	// what the other counted on. The record is deleted after (the orphan sweep removes any left); an entry is dropped
	// once its record is gone for good (RemovalRetention). A new credential epoch clears the list (SetCredEpoch).
	Removed []Removal `msgpack:"rm,omitempty" json:"-"`
}

// Removal is one credential removed from an account (User.Removed).
type Removal struct {
	Kind Kind      `msgpack:"k"`
	ID   string    `msgpack:"i"`
	At   time.Time `msgpack:"t"`
}

// TombstoneRetention is how long a gossip cluster keeps tombstones before it purges them (cluster.Options): a node
// that has not synced for nearly that long stops serving. The fences below are kept exactly as long, so no node can
// still hand a record back once its fence goes: they are defined from it, never apart.
const TombstoneRetention = 7 * 24 * time.Hour

// RemovalRetention is how long a removal is listed after its record is gone (TombstoneRetention).
const RemovalRetention = TombstoneRetention

// SetCredEpoch gives the account credential epoch e: every credential made in another stops counting, and the
// removals listed for the old one are moot.
func (u *User) SetCredEpoch(e uint64) { u.CredEpoch, u.Removed = e, nil }

// removed reports whether the credential id is listed in Removed.
func (u *User) removed(id string) bool {
	for _, r := range u.Removed {
		if r.ID == id {
			return true
		}
	}
	return false
}

// Holds reports whether a credential (passkey, connected provider, API token) made in epoch still counts for the
// account (CredEpoch).
func (u *User) Holds(epoch uint64) bool { return epoch == u.CredEpoch }

// SessionHolds reports whether a session or refresh grant made in epoch still counts for the account (SessionEpoch).
func (u *User) SessionHolds(epoch uint64) bool { return epoch == u.SessionEpoch }

// Credential is a record that counts for its account only in the epoch it was made in: a passkey, connected provider
// or API token (the account's CredEpoch), a session or refresh grant (its SessionEpoch).
type Credential interface {
	Entity
	Owner() string                        // the user it belongs to
	MadeIn() (epoch uint64, session bool) // its epoch, and whether that is a session epoch
}

// Counts reports whether c, one of u's, still counts: made in the account's epoch of its kind, and not removed.
func (u *User) Counts(c Credential) bool {
	e, session := c.MadeIn()
	if session {
		return u.SessionHolds(e)
	}
	return u.Holds(e) && !u.removed(c.GetMeta().ID)
}

func (p *Passkey) Owner() string           { return p.UserID }
func (p *Passkey) MadeIn() (uint64, bool)  { return p.Epoch, false }
func (i *Identity) Owner() string          { return i.UserID }
func (i *Identity) MadeIn() (uint64, bool) { return i.Epoch, false }
func (t *APIToken) Owner() string          { return t.UserID }
func (t *APIToken) MadeIn() (uint64, bool) { return t.Epoch, false }
func (s *Session) Owner() string           { return s.UserID }
func (s *Session) MadeIn() (uint64, bool)  { return s.Epoch, true }
func (g *Grant) Owner() string             { return g.UserID }
func (g *Grant) MadeIn() (uint64, bool)    { return g.Epoch, true }

// BumpSecurity moves the account on to its next security generation (SecurityGen); the caller writes the user.
func (u *User) BumpSecurity() { u.SecurityGen++ }

// StatusChange is who disabled or re-enabled an account, when, and why.
type StatusChange struct {
	At     time.Time `msgpack:"t" json:"at"`
	By     string    `msgpack:"b" json:"by"`                        // the actor's name: a username, "client:<name>" or "system"
	ByID   string    `msgpack:"i,omitempty" json:"by_id,omitempty"` // their user or client id
	Reason string    `msgpack:"r,omitempty" json:"reason,omitempty"`
}

// MaxStatusReason is the longest reason recorded with a status change.
const MaxStatusReason = 500

// MaxLinkedEmails is the most linked addresses a user may have.
const MaxLinkedEmails = 10

// LinkedEmail is an additional address of a user.
type LinkedEmail struct {
	Address  string    `msgpack:"a" json:"address"`
	Verified bool      `msgpack:"v" json:"verified"`
	Added    time.Time `msgpack:"t" json:"added"`
}

// FullName is the given and family name, falling back to the username and then the email address.
func (u *User) FullName() string {
	if n := strings.TrimSpace(u.GivenName + " " + u.FamilyName); n != "" {
		return n
	}
	if u.Username != "" {
		return u.Username
	}
	return u.Email
}

func (u *User) LinkedEmail(addr string) (LinkedEmail, bool) {
	for _, l := range u.LinkedEmails {
		if strings.EqualFold(l.Address, addr) {
			return l, true
		}
	}
	return LinkedEmail{}, false
}

func (u *User) Kind() Kind { return KindUser }
func (u *User) Index() Index {
	uq := []string{UserUsernameKey(u.OrgID, u.Username)}
	if u.Email != "" {
		uq = append(uq, UserEmailKey(u.OrgID, u.Email))
	}
	for _, l := range u.LinkedEmails {
		uq = append(uq, UserEmailKey(u.OrgID, l.Address))
	}
	if u.ExternalID != "" {
		uq = append(uq, UserExternalIDKey(u.OrgID, u.ExternalID))
	}
	return Index{
		Scope:     u.OrgID,
		Partition: u.OrgID,
		Unique:    uq,
		Fields: map[string]any{
			"username": u.Username, "email": u.Email, "name": u.FullName(), "family_name": u.FamilyName,
			"external_id": u.ExternalID,
			"role":        string(u.Role), "active": u.Active, "inactive": !u.Active, "created": u.Created,
			"tags": strings.Join(u.Tags, " "), "user_type": u.UserType, "department": u.Work.Department,
			"manager_id": u.Work.ManagerID, "employee_number": u.Work.EmployeeNumber,
			"expiring": u.ValidUntil != nil, "valid_until": validUntilField(u.ValidUntil),
			"super_admin": u.Role == RoleSuperAdmin, "admin_rank": u.Role.Rank() >= RoleAdmin.Rank(),
		},
	}
}

func UserUsernameKey(orgID, username string) string { return orgID + "/u/" + Lower(username) }
func UserEmailKey(orgID, email string) string       { return orgID + "/e/" + Lower(email) }
func UserExternalIDKey(orgID, ext string) string    { return orgID + "/x/" + ext }

// HasMFA reports whether the user has a second factor other than a passkey.
func (u *User) HasTOTP() bool { return u.TOTPSecret != "" }

// ---------------------------------------------------------------------------------------------------------------
// Groups

// A Group's record is the single commit point of every change of the group, its member list included (see
// docs/REPLICATION.md, "Groups and their members"). A change of members is committed by one compare-and-swap of this
// record that appends a GroupChange to Pending; the Member records are a materialized view of the changes so
// committed, written afterwards (service.ChangeGroup) and finished by any later writer or by housekeeping should
// the writer die. Readers of memberships apply Pending over the Member records, so a committed change is visible to
// them whether or not it has been materialized yet.
type Group struct {
	Meta
	OrgID       string   `msgpack:"o" json:"org_id"`
	DisplayName string   `msgpack:"dn" json:"display_name"`
	ExternalID  string   `msgpack:"x" json:"external_id,omitempty"`
	Tags        []string `msgpack:"tg" json:"tags"`
	// Seq is the sequence number of the last member change committed on this group; every GroupChange carries the
	// one it was committed with, and every Member record the one that last wrote it (Member.Seq).
	Seq uint64 `msgpack:"sq,omitempty" json:"-"`
	// Pending holds the committed member changes not yet known to be materialized, oldest first; a writer removes
	// the entries it has applied with another compare-and-swap. It is normally empty, or one entry for the
	// milliseconds a change takes to materialize; only a writer that died leaves one behind.
	Pending []GroupChange `msgpack:"pc,omitempty" json:"-"`
}

// GroupChange is one committed change of a group's members (Group.Pending).
type GroupChange struct {
	Seq    uint64    `msgpack:"s"`           // the group's Seq when committed: materialized writes carry it
	At     time.Time `msgpack:"t"`           // when it was committed (housekeeping finishes old ones)
	Add    []string  `msgpack:"a,omitempty"` // user ids made members
	Remove []string  `msgpack:"r,omitempty"` // user ids removed
}

func (g *Group) Kind() Kind { return KindGroup }
func (g *Group) Index() Index {
	uq := []string{GroupNameKey(g.OrgID, g.DisplayName)}
	if g.ExternalID != "" {
		uq = append(uq, GroupExternalIDKey(g.OrgID, g.ExternalID))
	}
	return Index{
		Scope:     g.OrgID,
		Partition: g.OrgID,
		Unique:    uq,
		Fields: map[string]any{"display_name": g.DisplayName, "external_id": g.ExternalID, "created": g.Created,
			"tags": strings.Join(g.Tags, " "), "pending": len(g.Pending) > 0},
	}
}

// PendingMember reports what the group's pending (committed, perhaps not yet materialized) changes say about
// userID's membership: decided is false when none mentions the user, and the Member record alone decides.
func (g *Group) PendingMember(userID string) (member, decided bool) {
	for _, c := range g.Pending { // oldest first: the last word wins
		if slices.Contains(c.Remove, userID) {
			member, decided = false, true
		}
		if slices.Contains(c.Add, userID) {
			member, decided = true, true
		}
	}
	return member, decided
}

// Member is one user's membership of a group. Each membership is its own record so concurrent adds and removes on
// different nodes never overwrite each other. ID is MemberID(groupID, userID). Scoped by organization so both "members
// of a group" and "groups of a user" are org-bounded filters.
//
// A membership is a materialized view of its group's committed changes (Group.Pending): every write of it carries
// the Seq of the change it applies, and a write with an older Seq is refused (service.materializeMember), so a writer
// that stalled can never overwrite a newer state. A removal therefore does not delete the record: it sets Removed and
// keeps the record, out of the group_id and user_id indexes, for RemovedMemberRetention (then it expires), so the
// Seq fence outlasts any stalled writer. Only the deletion of the user, group or organization tombstones it.
type Member struct {
	Meta
	GroupID string `msgpack:"g" json:"group_id"`
	UserID  string `msgpack:"ui" json:"user_id"`
	OrgID   string `msgpack:"o" json:"org_id"`
	// Seq is the Group.Seq of the change that last wrote this record (0: written before changes were sequenced).
	Seq uint64 `msgpack:"s,omitempty" json:"-"`
	// Removed is when the membership was removed; zero while the user is a member.
	Removed time.Time `msgpack:"rm" json:"-"`
}

// RemovedMemberRetention is how long a removed membership's record is kept to fence stalled writers
// (TombstoneRetention).
const RemovedMemberRetention = TombstoneRetention

// Active reports whether the record is a current membership (not removed).
func (m *Member) Active() bool { return m.Removed.IsZero() }

func (m *Member) Kind() Kind { return KindMember }
func (m *Member) Index() Index {
	if !m.Active() {
		// Out of both membership indexes, so "members of a group" and "groups of a user" never list it, and it
		// expires once no writer could still be stalled on an older change.
		return Index{Scope: m.OrgID, Partition: m.OrgID, Fields: map[string]any{"group_id": "", "user_id": "", "created": m.Created},
			Expires: m.Removed.Add(RemovedMemberRetention)}
	}
	return Index{
		Scope:     m.OrgID,
		Partition: m.OrgID,
		Fields:    map[string]any{"group_id": m.GroupID, "user_id": m.UserID, "created": m.Created},
	}
}

// MemberID is the deterministic id of a membership, so the same add on two nodes is the same record.
func MemberID(groupID, userID string) string { return groupID + ":" + userID }

func GroupNameKey(orgID, name string) string      { return orgID + "/n/" + Lower(name) }
func GroupExternalIDKey(orgID, ext string) string { return orgID + "/x/" + ext }

// ---------------------------------------------------------------------------------------------------------------
// Tenants

// TenantSettings narrow the organization's sign-in methods for the clients of a tenant. A method is offered only
// when both the organization and the tenant allow it.
type TenantSettings struct {
	// MembersOnly limits sign-in to the tenant's applications to the users and groups given access (TenantAccess);
	// otherwise everyone in the organization may sign in.
	MembersOnly   bool     `msgpack:"mo" json:"members_only"`
	PasswordLogin bool     `msgpack:"pw" json:"password_login"`
	PasswordReset bool     `msgpack:"pr" json:"password_reset"` // "Forgot your password?" on the sign-in form
	PasskeyLogin  bool     `msgpack:"pk" json:"passkey_login"`
	AllProviders  bool     `msgpack:"ap" json:"all_providers"` // every enabled provider of the org, including future ones
	Providers     []string `msgpack:"p" json:"providers"`      // provider ids, when AllProviders is false
	RequireMFA    bool     `msgpack:"mfa" json:"require_mfa"`  // in addition to the organization's setting
	// SelfRegistration lets applications that registered themselves (Client.SelfRegistered, AI clients of an MCP
	// server, say) sign users in for the tenant's resources (Tenant.Resources). Off by default.
	SelfRegistration bool `msgpack:"sr,omitempty" json:"self_registration"`
}

// Equal reports whether s and o are the same settings.
func (s TenantSettings) Equal(o TenantSettings) bool {
	if len(s.Providers) == 0 && len(o.Providers) == 0 {
		s.Providers, o.Providers = nil, nil
	}
	return reflect.DeepEqual(s, o)
}

// DefaultTenantSettings allows every sign-in method the organization allows, for everyone in it, with a second
// factor.
func DefaultTenantSettings() TenantSettings {
	return TenantSettings{PasswordLogin: true, PasswordReset: true, PasskeyLogin: true, AllProviders: true, RequireMFA: true}
}

// DefaultTenantName is the tenant every organization starts with.
const DefaultTenantName = "default"

// Tenant groups an organization's applications (clients) that share sign-in rules.
type Tenant struct {
	Meta
	OrgID       string         `msgpack:"o" json:"org_id"`
	Name        string         `msgpack:"n" json:"name"` // URL-safe, unique within the org
	DisplayName string         `msgpack:"dn" json:"display_name"`
	Description string         `msgpack:"d" json:"description,omitempty"`
	Settings    TenantSettings `msgpack:"s" json:"settings"`
	// Resources are the APIs (resource indicators, RFC 8707: an MCP server's URL, say) the tenant owns: unique
	// across the server. A self-registered application asking for one of them is governed by this tenant.
	Resources []string `msgpack:"res,omitempty" json:"resources"`
}

func (t *Tenant) Kind() Kind { return KindTenant }
func (t *Tenant) Index() Index {
	uniq := []string{TenantNameKey(t.OrgID, t.Name)}
	for _, r := range t.Resources {
		uniq = append(uniq, TenantResourceKey(r))
	}
	return Index{
		Scope:     t.OrgID,
		Partition: t.OrgID,
		Unique:    uniq,
		Fields:    map[string]any{"name": t.Name, "display_name": t.DisplayName, "created": t.Created},
	}
}

func TenantNameKey(orgID, name string) string { return orgID + "/n/" + Lower(name) }

// TenantResourceKey is the unique value claiming a resource for one tenant (server-wide): its canonical form, so
// "https://MCP.example.com/mcp/" cannot be claimed by another tenant than "https://mcp.example.com/mcp".
func TenantResourceKey(resource string) string {
	return tenantResourcePrefix + CanonicalResource(resource)
}

// tenantResourcePrefix starts every TenantResourceKey. The other unique keys of a tenant start with an organization id,
// a UUID, which never reads "res/".
const tenantResourcePrefix = "res/"

// CanonicalResource is a resource indicator compared loosely: scheme and host lower case, no default port, no
// trailing slash on the path (the MCP authorization spec's canonical server URI). Not a URI: s itself.
func CanonicalResource(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}
	if len(u.Path) > 1 {
		u.Path = strings.TrimRight(u.Path, "/")
	} else {
		u.Path = ""
	}
	u.RawPath = ""
	return u.String()
}

// Access subject types.
const (
	SubjectUser  = "user"
	SubjectGroup = "group"
)

// TenantAccess gives a user, or every member of a group, access to a tenant's applications: all of them or the
// listed clients, until Expires (zero: no end). Roles and Tags go into the tokens issued for those applications (the
// "roles" claim, and merged into "tags"). ID is AccessID(tenantID, subjectID), so checking a user's access is a few
// direct reads (the user's own record and one per group) rather than a scan.
type TenantAccess struct {
	Meta
	OrgID       string    `msgpack:"o" json:"org_id"`
	TenantID    string    `msgpack:"t" json:"tenant_id"`
	SubjectType string    `msgpack:"st" json:"subject_type"` // SubjectUser or SubjectGroup
	SubjectID   string    `msgpack:"si" json:"subject_id"`
	Roles       []string  `msgpack:"r" json:"roles"`
	Tags        []string  `msgpack:"tg" json:"tags"`
	AllClients  bool      `msgpack:"ac" json:"all_clients"`
	Clients     []string  `msgpack:"cl" json:"clients"` // client ids, when AllClients is false
	Expires     time.Time `msgpack:"e" json:"expires,omitzero"`
}

func (a *TenantAccess) Kind() Kind { return KindAccess }
func (a *TenantAccess) Index() Index {
	return Index{
		Scope:     a.OrgID,
		Partition: a.OrgID,
		Fields: map[string]any{"tenant_id": a.TenantID, "subject_id": a.SubjectID, "subject_type": a.SubjectType,
			"created": a.Created},
	}
}

// AccessID is the deterministic id of a subject's access to a tenant.
func AccessID(tenantID, subjectID string) string { return tenantID + ":" + subjectID }

// Live reports whether the access has not expired at now.
func (a *TenantAccess) Live(now time.Time) bool { return a.Expires.IsZero() || now.Before(a.Expires) }

// Covers reports whether the access includes client id.
func (a *TenantAccess) Covers(clientID string) bool {
	return a.AllClients || slices.Contains(a.Clients, clientID)
}

// ---------------------------------------------------------------------------------------------------------------
// OAuth clients

const (
	AuthMethodSecretPost  = "client_secret_post"
	AuthMethodSecretBasic = "client_secret_basic"
	AuthMethodPrivateJWT  = "private_key_jwt"
	// AuthMethodNone is a public client (SPA, mobile or desktop app, CLI) that cannot keep a secret: PKCE is its
	// only proof, refresh tokens always rotate, and it can never use client_credentials, SCIM or serve every org.
	AuthMethodNone = "none"
)

type Client struct {
	Meta
	OrgID          string   `msgpack:"o" json:"org_id"`
	TenantID       string   `msgpack:"t" json:"tenant_id"`
	Name           string   `msgpack:"n" json:"name"`
	Description    string   `msgpack:"d" json:"description,omitempty"`
	SecretHash     string   `msgpack:"sh" json:"-"`
	RedirectURIs   []string `msgpack:"ru" json:"redirect_uris"`
	PostLogoutURIs []string `msgpack:"pl" json:"post_logout_redirect_uris"`
	BackchannelURI string   `msgpack:"bc" json:"backchannel_logout_uri,omitempty"`
	GrantTypes     []string `msgpack:"gt" json:"grant_types"`
	Scopes         []string `msgpack:"sc" json:"scopes"`
	AuthMethod     string   `msgpack:"am" json:"token_endpoint_auth_method"`
	SigningAlg     string   `msgpack:"sa" json:"id_token_signed_response_alg"`
	JWKS           string   `msgpack:"jw" json:"jwks,omitempty"` // for private_key_jwt
	JWKSURI        string   `msgpack:"ju" json:"jwks_uri,omitempty"`
	FirstParty     bool     `msgpack:"fp" json:"first_party"`           // skip consent
	SCIM           bool     `msgpack:"scim" json:"scim"`                // client_credentials tokens may call SCIM for its org
	RotateRefresh  bool     `msgpack:"rr" json:"rotate_refresh_tokens"` // one-time-use refresh tokens (costs a write per refresh)
	// IntrospectOrg lets the client introspect every access token of its organization (a resource server that serves
	// several applications); without it introspection answers active only for tokens issued for the client (aud).
	IntrospectOrg bool `msgpack:"io,omitempty" json:"introspect_org"`
	Enabled       bool `msgpack:"en" json:"enabled"`
	// Resources are the resource indicators (RFC 8707) the client may ask tokens for: absolute URIs of the APIs the
	// access tokens are meant for (their aud). A request may name only these; none listed: no resource parameter.
	Resources []string `msgpack:"res,omitempty" json:"resources"`
	// PKCEOptional lets a confidential client make authorization requests without PKCE (unset: PKCE required, as
	// OAuth 2.1 does; public clients always need it). The management API shows it as require_pkce.
	PKCEOptional bool `msgpack:"po" json:"-"`
	// RequirePAR makes the client send its authorization requests through the pushed authorization request endpoint
	// (RFC 9126): an authorization request carrying its parameters in the URL is refused.
	RequirePAR bool `msgpack:"par,omitempty" json:"require_pushed_authorization_requests"`
	// DPoPBound makes every token request of the client carry a DPoP proof (RFC 9449 §5.2): its access tokens are
	// always bound to a key it holds.
	DPoPBound bool `msgpack:"dpop,omitempty" json:"dpop_bound_access_tokens"`
	// FAPI applies the FAPI 2.0 Security Profile to the client: private_key_jwt with the issuer alone as the
	// assertion's audience, no RS256 anywhere (assertions, DPoP proofs, its ID tokens), pushed authorization requests
	// and DPoP-bound tokens, refresh tokens that do not rotate, and authorization codes that last at most 60 seconds.
	FAPI bool `msgpack:"fapi,omitempty" json:"fapi2_security_profile"`
	// DevicePrivileged lets managers and above approve the client's device sign-ins (the device authorization grant,
	// RFC 8628). Off: only plain users may, as a code someone was talked into entering would give their device an
	// administrator's tokens.
	DevicePrivileged bool `msgpack:"dvp,omitempty" json:"device_privileged_users"`

	// SelfRegistered marks an application that registered itself (RFC 7591), or whose client_id is the URL of its
	// metadata document (Client ID Metadata Document): an AI client connecting to an MCP server, say. It belongs to
	// no organization (OrgID and TenantID empty): each authorization request names resources, and the tenant that
	// owns them (Tenant.Resources), if it allows self-registered apps, decides who may sign in and how. Always a
	// public client with PKCE; consent is always asked.
	SelfRegistered bool `msgpack:"sr,omitempty" json:"self_registered,omitempty"`
	// MetadataFetched is when a metadata-document client's document was last read (zero for RFC 7591 ones).
	MetadataFetched time.Time `msgpack:"mf,omitempty" json:"metadata_fetched,omitzero"`
	// LastUsed is when a self-registered app was last given an authorization code; one never used is removed a day
	// after it registered.
	LastUsed time.Time `msgpack:"lu,omitempty" json:"last_used,omitzero"`
	// UsedIn lists the tenants a self-registered app has been authorized in (for their administrators' lists).
	UsedIn []string `msgpack:"ui,omitempty" json:"-"`
}

// SelfRegisteredClientID reports whether a client id is that of a self-registered application: a dynamically registered
// one ("dyn-" and a random part) or the URL of a Client ID Metadata Document. Such a client belongs to no organization,
// so its record (and its partition key) is global: partition 0.
func SelfRegisteredClientID(id string) bool {
	return strings.HasPrefix(id, DynamicClientPrefix) || strings.HasPrefix(id, "https://")
}

// DynamicClientPrefix starts the id of a dynamically registered (RFC 7591) client.
const DynamicClientPrefix = "dyn-"

// IsMetadataClient reports whether the client's id is the URL of its Client ID Metadata Document.
func (c *Client) IsMetadataClient() bool {
	return c.SelfRegistered && strings.HasPrefix(c.ID, "https://")
}

// RequirePKCE reports whether authorization requests of the client must use PKCE (S256).
func (c *Client) RequirePKCE() bool { return !c.PKCEOptional || c.Public() }

func (c *Client) Kind() Kind { return KindClient }
func (c *Client) Index() Index {
	return Index{
		Scope:     c.OrgID, // a self-registered client has none: global
		Partition: c.OrgID,
		Fields: map[string]any{"name": c.Name, "tenant_id": c.TenantID, "auth_method": c.AuthMethod,
			"created": c.Created, "self_registered": c.SelfRegistered,
			"unused_self_registered": c.SelfRegistered && c.LastUsed.IsZero()},
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Upstream sign-in providers

// Provider types. Every type but GitHub is OpenID Connect underneath: Google, GitLab and Auth0 are presets of the
// issuer and scopes; Microsoft (Entra ID) adds its tenant rules.
const (
	ProviderOIDC      = "oidc"
	ProviderGitHub    = "github"
	ProviderGoogle    = "google"
	ProviderGitLab    = "gitlab"
	ProviderAuth0     = "auth0"
	ProviderMicrosoft = "microsoft"
)

// ProviderTypes lists the provider types in the order the admin console offers them.
var ProviderTypes = []string{ProviderOIDC, ProviderGoogle, ProviderMicrosoft, ProviderGitHub, ProviderGitLab, ProviderAuth0}

// MicrosoftAuthority is the Microsoft identity platform.
const MicrosoftAuthority = "https://login.microsoftonline.com"

type Provider struct {
	Meta
	OrgID        string   `msgpack:"o" json:"org_id"`
	Type         string   `msgpack:"t" json:"type"`
	Name         string   `msgpack:"n" json:"name"` // button label
	Issuer       string   `msgpack:"is" json:"issuer,omitempty"`
	ClientID     string   `msgpack:"ci" json:"client_id"`
	ClientSecret string   `msgpack:"cs" json:"-"` // sealed
	Scopes       []string `msgpack:"sc" json:"scopes"`
	// LinkByEmail links an existing user whose verified email matches a verified address from the provider on their
	// first sign-in (on for new providers).
	LinkByEmail    bool     `msgpack:"lbe" json:"link_by_email"`
	AutoProvision  bool     `msgpack:"ap" json:"auto_provision"`
	AllowedDomains []string `msgpack:"ad" json:"allowed_domains"`
	Enabled        bool     `msgpack:"en" json:"enabled"`
	// TrustMFA counts a sign-in through this provider as both factors for plain users: the provider is trusted to
	// have asked for a second factor itself, so Quisora asks them for none and the session satisfies every
	// second-factor requirement. Managers and above always give their own second factor. Only a super admin may set
	// it. Off by default: a provider sign-in is a first factor only.
	TrustMFA bool `msgpack:"tm" json:"trust_mfa"`
	// Microsoft: Tenant is the directory signed in against (a tenant ID, or "organizations" for work and school
	// accounts of any directory); AllowedTenants are the tenant IDs whose users may sign in (required with
	// "organizations"; with a tenant ID only that tenant is allowed).
	Tenant         string   `msgpack:"tn" json:"tenant,omitempty"`
	AllowedTenants []string `msgpack:"at" json:"allowed_tenants,omitempty"`
}

// OIDC reports whether the provider signs in with OpenID Connect (every type but GitHub).
func (p *Provider) OIDC() bool { return p.Type != ProviderGitHub }

func (p *Provider) Kind() Kind { return KindProvider }
func (p *Provider) Index() Index {
	return Index{
		Scope:     p.OrgID,
		Partition: p.OrgID,
		Unique:    []string{p.OrgID + "/n/" + Lower(p.Name)},
		Fields:    map[string]any{"name": p.Name, "type": p.Type, "enabled": p.Enabled, "created": p.Created},
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Passkeys

type Passkey struct {
	Meta
	// Epoch is the account's credential epoch it was made in (User.CredEpoch): it works only while that is current.
	Epoch          uint64    `msgpack:"ep,omitempty" json:"-"`
	UserID         string    `msgpack:"ui" json:"user_id"`
	OrgID          string    `msgpack:"o" json:"org_id"`
	Name           string    `msgpack:"n" json:"name"`
	CredentialID   []byte    `msgpack:"cid" json:"-"`
	PublicKey      []byte    `msgpack:"pk" json:"-"`
	AttestationFmt string    `msgpack:"af" json:"-"`
	AAGUID         []byte    `msgpack:"ag" json:"-"`
	SignCount      uint32    `msgpack:"sc" json:"-"`
	Transports     []string  `msgpack:"tr" json:"transports"`
	BackupEligible bool      `msgpack:"be" json:"backup_eligible"`
	BackupState    bool      `msgpack:"bs" json:"backup_state"`
	UserVerified   bool      `msgpack:"uv" json:"-"`
	LastUsed       time.Time `msgpack:"lu" json:"last_used"`
	// Disabled is set when a sign-in showed signs of a cloned authenticator; the passkey no longer signs in.
	Disabled bool `msgpack:"d" json:"disabled"`
}

// MaxPasskeys is how many passkeys one user may register.
const MaxPasskeys = 20

// Usable reports whether the passkey can sign in: every sign-in requires user verification, so a credential
// registered without it (before registration required it) cannot, and nor can a disabled one.
func (p *Passkey) Usable() bool { return p.UserVerified && !p.Disabled }

func (p *Passkey) Kind() Kind { return KindPasskey }
func (p *Passkey) Index() Index {
	return Index{
		Scope:     p.UserID,
		Partition: p.OrgID, // the credential id is unique across organizations: a reservation holds it (GlobalUnique)
		Unique:    []string{PasskeyCredentialKey(p.CredentialID)},
		Fields:    map[string]any{"name": p.Name, "created": p.Created, "last_used": p.LastUsed},
	}
}

// PasskeyCredentialKey is the unique key for a WebAuthn credential id.
func PasskeyCredentialKey(id []byte) string { return b64(id) }

// ---------------------------------------------------------------------------------------------------------------
// Upstream identities linked to users

type Identity struct {
	Meta
	// Epoch is the account's credential epoch it was made in (User.CredEpoch): it works only while that is current.
	Epoch      uint64 `msgpack:"ep,omitempty" json:"-"`
	UserID     string `msgpack:"ui" json:"user_id"`
	OrgID      string `msgpack:"o" json:"org_id"`
	ProviderID string `msgpack:"p" json:"provider_id"`
	Subject    string `msgpack:"s" json:"subject"`
	Email      string `msgpack:"e" json:"email,omitempty"`
	// Authority is the provider's type, issuer and directory when the identity was linked (ProviderAuthority): a
	// subject means something only at that authority, so a provider since pointed elsewhere no longer matches it.
	Authority string `msgpack:"au" json:"-"`
	// Via says how it was linked: "email" (linking by verified email), "provision" (an account created at first
	// sign-in), "connect" (the user connected it, signed in) or "admin".
	Via string `msgpack:"vi" json:"via,omitempty"`
	// Refresh is the provider's refresh token from the latest sign-in through it (sealed), when the provider gave
	// one. While the user has sessions signed in through the provider it is replayed on a schedule: a provider that
	// refuses it (invalid_grant: the account was removed or blocked there) ends the user's sessions here too.
	Refresh string `msgpack:"rt,omitempty" json:"-"`
	// RefreshChecked is when Refresh was stored or last replayed.
	RefreshChecked time.Time `msgpack:"rc,omitempty" json:"-"`
}

// ProviderAuthority names who issues a provider's subjects: its type, issuer and (Microsoft) directory, and when the
// provider was created, so one deleted and created again under the same id never matches the old links.
func ProviderAuthority(p *Provider) string {
	return p.Type + "|" + p.Issuer + "|" + p.Tenant + "|" + strconv.FormatInt(p.Created.UnixMilli(), 10)
}

// NewIdentity links subject at provider p to user u.
func NewIdentity(u *User, p *Provider, subject, email, via string) *Identity {
	return &Identity{UserID: u.ID, OrgID: u.OrgID, ProviderID: p.ID, Subject: subject, Email: email,
		Authority: ProviderAuthority(p), Via: via, Epoch: u.CredEpoch}
}

func (i *Identity) Kind() Kind { return KindIdentity }
func (i *Identity) Index() Index {
	return Index{
		Scope:     i.UserID,
		Partition: i.OrgID,
		Unique:    []string{IdentityKey(i.ProviderID, i.Subject)},
		Fields:    map[string]any{"provider_id": i.ProviderID, "created": i.Created},
	}
}

func IdentityKey(providerID, subject string) string { return providerID + "/" + subject }

// ---------------------------------------------------------------------------------------------------------------
// Browser sessions

type Session struct {
	Meta
	// Epoch is the account's session epoch it was made in (User.SessionEpoch): it works only while that is current.
	Epoch     uint64    `msgpack:"ep,omitempty" json:"-"`
	UserID    string    `msgpack:"ui" json:"user_id"`
	OrgID     string    `msgpack:"o" json:"org_id"`
	AMR       []string  `msgpack:"amr" json:"amr"`
	Provider  string    `msgpack:"pv" json:"provider_id,omitempty"` // upstream provider used to sign in, if any
	Passkey   string    `msgpack:"pk" json:"-"`                     // passkey used to sign in, if any (deleting it ends the session)
	AuthTime  time.Time `msgpack:"at" json:"auth_time"`
	Expires   time.Time `msgpack:"ex" json:"expires"`
	IdleTTL   int       `msgpack:"it" json:"-"` // seconds; 0 = no idle timeout
	LastSeen  time.Time `msgpack:"ls" json:"last_seen"`
	IP        string    `msgpack:"ip" json:"ip"`
	UserAgent string    `msgpack:"ua" json:"user_agent"`
	CSRF      string    `msgpack:"cs" json:"-"`
	// CookieHash is set once the session was re-authenticated (web.Sessions.Upgrade): the browser's cookie is then
	// "<id>.<secret>" and this is the hash of the secret, so the cookie value from before the upgrade no longer works
	// (no session fixation) while the id, which grants and tokens name as "sid", stays the same.
	CookieHash []byte `msgpack:"ck,omitempty" json:"-"`
	// Clients are the applications that were issued tokens for this session: they are told when it ends
	// (back-channel logout) even after their refresh grant was revoked.
	Clients []string `msgpack:"cl" json:"-"`
	// Stamp is the session sign-out counters it was made under (signout.go).
	Stamp SignOutStamp `msgpack:"st" json:"-"`
}

func (s *Session) Kind() Kind { return KindSession }
func (s *Session) Index() Index {
	return Index{
		Scope:     s.UserID,
		Partition: s.OrgID,
		Fields:    map[string]any{"ip": s.IP, "created": s.Created, "last_seen": s.LastSeen},
		Expires:   s.Expires,
	}
}

// Valid reports whether the session can still be used at now.
func (s *Session) Valid(now time.Time) bool {
	if now.After(s.Expires) {
		return false
	}
	if s.IdleTTL > 0 && now.Sub(s.LastSeen) > time.Duration(s.IdleTTL)*time.Second {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------------------------------------------
// Refresh-token grants

type Grant struct {
	Meta
	// Epoch is the session epoch of the sign-in it was granted in (User.SessionEpoch): it works only while that is
	// current.
	Epoch     uint64    `msgpack:"ep,omitempty" json:"-"`
	ClientID  string    `msgpack:"ci" json:"client_id"`
	UserID    string    `msgpack:"ui" json:"user_id"`
	OrgID     string    `msgpack:"o" json:"org_id"`
	SessionID string    `msgpack:"si" json:"session_id"`
	Scopes    []string  `msgpack:"sc" json:"scopes"`
	AMR       []string  `msgpack:"amr" json:"amr"`
	AuthTime  time.Time `msgpack:"at" json:"auth_time"`
	Counter   uint64    `msgpack:"n" json:"-"`
	// Rotated is when Counter last moved: the retry grace of the token before the current one runs from it, never
	// from Updated, which other changes (a re-seal of Key) move too.
	Rotated time.Time `msgpack:"rt,omitempty" json:"-"`
	// Key is the grant's refresh token key, random, sealed with the master key (service.GrantKeyBinding); the tokens
	// are made from it (oidc refreshToken).
	Key string `msgpack:"rk,omitempty" json:"-"`
	// Resources are the resource indicators (RFC 8707) the user authorized; a refresh may narrow them, never widen.
	Resources []string `msgpack:"rs" json:"resources,omitempty"`
	// ClaimsUI and ClaimsID are claims requested one by one (the claims request parameter) for userinfo and for
	// the ID token, beyond those of the scopes.
	ClaimsUI []string  `msgpack:"cu,omitempty" json:"claims_userinfo,omitempty"`
	ClaimsID []string  `msgpack:"cid,omitempty" json:"claims_id_token,omitempty"`
	Expires  time.Time `msgpack:"ex" json:"expires"`
	Revoked  bool      `msgpack:"rv" json:"revoked"`
	// Stamp is the session sign-out counters it was made under (signout.go).
	Stamp SignOutStamp `msgpack:"st" json:"-"`
	// DPoPJKT binds the refresh tokens of a public client's grant to a DPoP key (RFC 9449 §5): the thumbprint of
	// the key of the proof sent with the code exchange.
	DPoPJKT string `msgpack:"jkt,omitempty" json:"-"`
}

func (g *Grant) Kind() Kind { return KindGrant }
func (g *Grant) Index() Index {
	return Index{
		Scope:     g.UserID,
		Partition: g.OrgID,
		Fields:    map[string]any{"client_id": g.ClientID, "session_id": g.SessionID, "created": g.Created},
		Expires:   g.Expires,
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Personal API tokens

type APIToken struct {
	Meta
	// Epoch is the account's credential epoch it was made in (User.CredEpoch): it works only while that is current.
	Epoch      uint64   `msgpack:"ep,omitempty" json:"-"`
	UserID     string   `msgpack:"ui" json:"user_id"`
	OrgID      string   `msgpack:"o" json:"org_id"`
	Name       string   `msgpack:"n" json:"name"`
	SecretHash []byte   `msgpack:"h" json:"-"`
	Scopes     []string `msgpack:"sc" json:"scopes"`
	// Audience limits an "api" token to the listed clients (ids of the owner's organization): only they see it as
	// active through introspection. Empty: any confidential client of the organization.
	Audience []string `msgpack:"aud,omitempty" json:"audience"`
	// AppScopes (api scope only) narrows the token to some of its applications' own scopes (their "scopes for your
	// own APIs"): introspection reports them, and an application declaring none of them sees the token inactive.
	// Empty: the token acts with its owner's full access in every application it is for.
	AppScopes []string  `msgpack:"as,omitempty" json:"app_scopes"`
	Expires   time.Time `msgpack:"ex" json:"expires"`
	LastUsed  time.Time `msgpack:"lu" json:"last_used"`
	// Stamp is the API token sign-out counters it was made under (signout.go).
	Stamp SignOutStamp `msgpack:"st" json:"-"`
}

func (t *APIToken) Kind() Kind { return KindAPIToken }
func (t *APIToken) Index() Index {
	return Index{
		Scope:     t.UserID,
		Partition: t.OrgID,
		Fields:    map[string]any{"name": t.Name, "created": t.Created, "last_used": t.LastUsed},
		Expires:   t.Expires,
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Signing keys

type SigningKey struct {
	Meta
	Alg        string    `msgpack:"a" json:"alg"`
	PrivateKey string    `msgpack:"pk" json:"-"` // sealed PKCS#8 DER
	PublicJWK  []byte    `msgpack:"j" json:"-"`
	NotBefore  time.Time `msgpack:"nb" json:"not_before"` // published from Created, used for signing from NotBefore
	RetireAt   time.Time `msgpack:"ra" json:"retire_at"`  // stop signing; still published until Expires
	Expires    time.Time `msgpack:"ex" json:"expires"`
}

func (k *SigningKey) Kind() Kind { return KindKey }
func (k *SigningKey) Index() Index {
	return Index{Partition: "", Fields: map[string]any{"alg": k.Alg, "created": k.Created}, Expires: k.Expires}
}

// ---------------------------------------------------------------------------------------------------------------
// Audit log

type Audit struct {
	Meta
	OrgID   string            `msgpack:"o" json:"org_id"`
	ActorID string            `msgpack:"ai" json:"actor_id"`
	Actor   string            `msgpack:"an" json:"actor"`
	Action  string            `msgpack:"ac" json:"action"`
	Target  string            `msgpack:"t" json:"target"`
	IP      string            `msgpack:"ip" json:"ip"`
	Detail  map[string]string `msgpack:"d" json:"detail,omitempty"`
	Expires time.Time         `msgpack:"ex" json:"-"`
	// Outcome is "success" or "failure" (AuditOutcome of the action).
	Outcome string `msgpack:"oc,omitempty" json:"outcome,omitempty"`
	// The request the event was recorded for, when there was one: its id (the X-Request-ID response header, for
	// matching proxy and application logs), the browser or client software, and the session it was made in.
	RequestID string `msgpack:"rid,omitempty" json:"request_id,omitempty"`
	UserAgent string `msgpack:"ua,omitempty" json:"user_agent,omitempty"`
	SessionID string `msgpack:"sid,omitempty" json:"session_id,omitempty"`
}

// AuditOutcome says whether an audit action records something refused or failed ("failure") or done ("success"),
// from its name: actions for refusals end in .failure, .refused/_refused, .lockout, .limited, .replay, .reuse or .clone.
func AuditOutcome(action string) string {
	for _, s := range []string{".failure", ".refused", "_refused", ".lockout", ".limited", ".replay", ".reuse", ".clone"} {
		if strings.HasSuffix(action, s) {
			return "failure"
		}
	}
	return "success"
}

func (a *Audit) Kind() Kind { return KindAudit }
func (a *Audit) Index() Index {
	return Index{
		Scope:     a.OrgID,
		Partition: a.OrgID, // a server-level event with no organization is global
		Fields: map[string]any{"action": a.Action, "actor": a.Actor, "target": a.Target, "created": a.Created,
			"outcome": cmp.Or(a.Outcome, AuditOutcome(a.Action)), "ip": a.IP}, // older events may carry no outcome
		Expires: a.Expires,
	}
}

// Public reports whether the client cannot authenticate itself (token_endpoint_auth_method "none").
func (c *Client) Public() bool { return c.AuthMethod == AuthMethodNone }

// ---------------------------------------------------------------------------------------------------------------
// Emailed / shared links (invitation, password reset, email verification)

// LinkToken is a single-use link. Only the SHA-256 of the token is stored (as the id), so a database copy never
// yields a working link. Durable and replicated so a link survives restarts and works on every node.
type LinkToken struct {
	Meta
	UserID  string    `msgpack:"ui" json:"user_id"`
	OrgID   string    `msgpack:"o" json:"org_id"`
	Purpose string    `msgpack:"p" json:"purpose"`
	Email   string    `msgpack:"e" json:"email,omitempty"` // the address being verified, or an invitation or reset was mailed to
	Used    bool      `msgpack:"x" json:"used"`
	Expires time.Time `msgpack:"ex" json:"expires"`
	// UserCreated is the creation time of the user the link was issued for: the link works only for that very
	// account, not for another one that has (or later gets) the same id.
	UserCreated time.Time `msgpack:"uc" json:"-"`
	// For is the account's address when an invitation or reset link was issued: the link opens only while that is
	// still the address on file (service.PeekLink), so one sent to a mistyped address that was then corrected sets
	// nobody's credentials.
	For string `msgpack:"f,omitempty" json:"-"`
	// IssuedBy is the user who issued an invitation ("" for the system or a command): until it is used, nobody else
	// below a super admin may replace it (service.mayResetSignIn).
	IssuedBy string `msgpack:"ib,omitempty" json:"-"`
	// BreakGlass marks an invitation issued with "quisora invite --break-glass": it opens even for an account that is
	// disabled (locked out, or past its end date), and using it enables the account again.
	BreakGlass bool `msgpack:"bg,omitempty" json:"-"`
	// Gen is the user's security generation (User.SecurityGen) when the link was issued: an invitation or reset link
	// opens only while it is still the account's (service.PeekLink), so a password changed, a factor set up or an
	// account disabled after the link went out leaves it dead.
	Gen uint64 `msgpack:"g,omitempty" json:"-"`
	// TokenHash is the hash of the link's token, by which it is found (LinkTokenKey). An invitation or reset link's
	// id is its purpose and user (one of each per account: a new one replaces the record, and the token it held no
	// longer finds it); a verification link's id is its token hash.
	TokenHash string `msgpack:"th" json:"-"`
}

// LinkTokenKey is the unique value a link is found by: the hash of its token.
func LinkTokenKey(hash string) string { return "t/" + hash }

func (l *LinkToken) Kind() Kind { return KindLink }
func (l *LinkToken) Index() Index {
	return Index{Scope: l.UserID, Partition: l.OrgID, Unique: []string{LinkTokenKey(l.TokenHash)},
		Fields: map[string]any{"purpose": l.Purpose, "created": l.Created}, Expires: l.Expires}
}

// SignIn holds a user's sign-in stamps, kept apart from the user record (ID is the user's id). A sign-in writes
// only this record, so it can never overwrite (or be overwritten by) an administrator's change of the user; in a
// replicated cluster it is written with a cluster-wide compare-and-swap like the user itself (checked by its owner), which makes
// the TOTP step a replay guard on every node at once. Failed attempts and lockouts are counted in ephemeral state
// (login rate limits), not here.
type SignIn struct {
	Meta
	OrgID        string    `msgpack:"o" json:"org_id"`
	LastLogin    time.Time `msgpack:"ll" json:"last_login"`
	TOTPLastStep int64     `msgpack:"tl" json:"-"` // the last TOTP time step accepted: a code works once
	// RecoveryUsed are the hashes of the recovery codes used (User.RecoveryCodes): each works once, on every node.
	RecoveryUsed []string `msgpack:"ru,omitempty" json:"-"`
}

func (s *SignIn) Kind() Kind { return KindSignIn }
func (s *SignIn) Index() Index {
	return Index{Scope: s.OrgID, Partition: s.OrgID, Fields: map[string]any{"last_login": s.LastLogin}}
}

// Lock is a cluster-wide lock record (a compare-and-swap its owner decides): Holder holds it until Until. Used to serialise
// decisions that read more than one record (the super admins the server keeps).
type Lock struct {
	Meta
	Holder string    `msgpack:"h" json:"holder"`
	Until  time.Time `msgpack:"ut" json:"until"`
}

func (l *Lock) Kind() Kind   { return KindLock }
func (l *Lock) Index() Index { return Index{Partition: l.ID} }

// Replay records that a single-use value (a client assertion's or a DPoP proof's jti) was used, until it expires:
// creating it again is refused while it lives. It is written with a compare-and-swap its owner decides, so in a cluster it is committed on a majority
// before the value is accepted, and no node accepts the value again whichever node it reaches and whatever nodes come
// and go meanwhile. Its id is derived from the value (service.UseOnce).
type Replay struct {
	Meta
	Expires time.Time `msgpack:"ex" json:"expires"`
}

func (r *Replay) Kind() Kind   { return KindReplay }
func (r *Replay) Index() Index { return Index{Partition: r.ID, Expires: r.Expires} }

// Ephemeral is one item of short-lived state kept in a shared database (see KindEphemeral): a value, or a counter.
// Its id is derived from the namespace and key (ephemeral.Shared), never chosen by a client.
type Ephemeral struct {
	Meta
	Value   []byte    `msgpack:"b"`
	N       int64     `msgpack:"n"`
	Expires time.Time `msgpack:"ex"`
}

func (e *Ephemeral) Kind() Kind     { return KindEphemeral }
func (e *Ephemeral) Index() Index   { return Index{Expires: e.Expires} }
func (e *Ephemeral) GetMeta() *Meta { return &e.Meta }

// validUntilField is the indexed end date: the zero time when there is none (the "expiring" field tells them apart).
func validUntilField(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// Reservation claims a unique value that must hold across organizations (GlobalUnique) in a cluster that replicates by
// partition: the record with ID = the reserved key names the record that holds the value, by kind and id. Its
// partition key is the reserved key itself, so one node (the owner of that key's partition) decides every claim of a
// value, and the claims spread over the partitions. A reservation whose holder no longer exists, or no longer lists
// the value among its unique values, is free: the next claim takes it over when its copy of the holder shows that, and
// the housekeeping leader's sweep releases it when the holder is gone (cluster.Node.SweepReservations).
type Reservation struct {
	Meta
	// HolderKind and HolderID name the record that holds the reserved key.
	HolderKind Kind   `msgpack:"hk" json:"holder_kind"`
	HolderID   string `msgpack:"hi" json:"holder_id"`
}

func (r *Reservation) Kind() Kind { return KindReservation }
func (r *Reservation) Index() Index {
	return Index{Partition: r.ID}
}

// GlobalUnique reports whether key, a unique value of a record of kind, must be unique across organizations. Every
// other unique value is prefixed by the organization (or by an id of one organization's record) and so lives in one
// partition; these two are looked up with no organization at hand (a tenant's resource indicator in an authorization
// request, a discoverable passkey's credential id on the landing page) and are reserved (KindReservation).
func GlobalUnique(kind Kind, key string) bool {
	switch kind {
	case KindTenant:
		return strings.HasPrefix(key, tenantResourcePrefix)
	case KindPasskey:
		return true
	}
	return false
}
