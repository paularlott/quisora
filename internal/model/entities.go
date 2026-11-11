package model

import (
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	// APITokens is who may make personal API tokens with the api scope, the ones the organization's own applications
	// check through introspection: APITokensOff (or empty: nobody, so an organization saved before the setting
	// existed, and a new one, has none), APITokensGroups (the members of APITokenGroups) or APITokensEveryone. The
	// other scopes (scim, admin, backup, import) have no part in it: their owner's role alone decides.
	APITokens string `msgpack:"at,omitempty" json:"api_tokens,omitempty"`
	// APITokenGroups are the ids of the groups of the organization whose members may (APITokensGroups only).
	APITokenGroups []string `msgpack:"atg,omitempty" json:"api_token_groups,omitempty"`
	// The organization's own password, lockout, API token and privileged session policy; 0 keeps the server's
	// (limits.password_min_length, limits.lockout_attempts, limits.lockout_minutes, tokens.api_token_max_days,
	// session.privileged_ttl and session.privileged_idle). APITokenMaxDays may also be APITokensNoLimit.
	PasswordMinLength int `msgpack:"pml,omitempty" json:"password_min_length"`
	LockoutAttempts   int `msgpack:"loa,omitempty" json:"lockout_attempts"`
	LockoutMinutes    int `msgpack:"lom,omitempty" json:"lockout_minutes"`
	APITokenMaxDays   int `msgpack:"atm,omitempty" json:"api_token_max_days"`
	PrivilegedTTL     int `msgpack:"pttl,omitempty" json:"privileged_ttl"`  // seconds
	PrivilegedIdle    int `msgpack:"pidl,omitempty" json:"privileged_idle"` // seconds
	// GrantsPerUser is how many refresh grants one user may hold; 0 keeps the server's (limits.grants_per_user).
	GrantsPerUser int `msgpack:"gpu,omitempty" json:"grants_per_user"`
	// MCPServer serves the organization's own MCP server (internal/mcpapi), through which AI clients manage its users
	// and groups for its managers and administrators. Off by default (and for an organization saved before the setting
	// existed): while off, its address and metadata answer 404 and the console does not show it.
	MCPServer bool `msgpack:"mcp,omitempty" json:"mcp_server"`
	// PicturesByAdmins stops users setting their own profile picture: only those who manage users (managers and above)
	// and the directory (SCIM, sign-in providers) set pictures. Off by default (and for an organization saved before
	// the setting existed): users choose their own.
	PicturesByAdmins bool `msgpack:"pba,omitempty" json:"pictures_by_admins"`
}

// Equal reports whether two settings are the same (OrgSettings holds a slice, so == does not compile).
func (s OrgSettings) Equal(o OrgSettings) bool {
	g, og := s.APITokenGroups, o.APITokenGroups
	s.APITokenGroups, o.APITokenGroups = nil, nil
	return reflect.DeepEqual(s, o) && slices.Equal(g, og)
}

// APITokensNoLimit is OrgSettings.APITokenMaxDays for an organization whose personal API tokens may never expire.
const APITokensNoLimit = -1

// Who may make api-scope personal API tokens (OrgSettings.APITokens).
const (
	APITokensOff      = "off"
	APITokensGroups   = "groups"
	APITokensEveryone = "everyone"
)

// DefaultOrgSettings is applied to new organizations.
func DefaultOrgSettings() OrgSettings {
	return OrgSettings{PasswordLogin: true, PasswordReset: true, PasskeyLogin: true}
}

type Org struct {
	Meta
	Name        string      `msgpack:"n" json:"name"`
	DisplayName string      `msgpack:"dn" json:"display_name"`
	Settings    OrgSettings `msgpack:"s" json:"settings"`
	Branding    OrgBranding `msgpack:"b" json:"branding"`
	// Primary marks the server's own organization, the first one ("quisora bootstrap" makes it, with an id of its own
	// like any other): its super admins administer the server. It is set only there and never changes, and it claims
	// the unique value PrimaryOrgKey, so a data set has at most one. Being stored, the mark goes wherever the
	// organization's record goes: every node of a cluster, a backup and its restore.
	Primary bool `msgpack:"pri,omitempty" json:"-"`
	// SignOut are the organization's emergency sign-out counters (signout.go); LastSignOut the last pull.
	SignOut     SignOutCounters `msgpack:"so" json:"-"`
	LastSignOut *SignOutEvent   `msgpack:"lso,omitempty" json:"last_sign_out,omitempty"`
	// ServerSignOut and LastServerSignOut are the server's, kept on the primary organization (moved with the role).
	ServerSignOut     SignOutCounters `msgpack:"sso" json:"-"`
	LastServerSignOut *SignOutEvent   `msgpack:"lsso,omitempty" json:"-"`
	// CreatedBy is the service account (of the primary organization) that created the organization, which alone of
	// the service accounts may delete it again (orgs:delete). Empty for one a person created.
	CreatedBy string `msgpack:"cb,omitempty" json:"-"`
}

func (o *Org) Kind() Kind { return KindOrg }

// OrgBranding is how the organization's pages look (its sign-in pages, and the console for its users): its logo,
// kept in a record of its own (OrgLogo) because every page reads the organization, and its primary colour. Unset,
// the server's.
type OrgBranding struct {
	PrimaryColor string `msgpack:"pc,omitempty" json:"primary_color"` // #rrggbb, dark enough for white text on it
	// Logo is the version of the organization's OrgLogo (a hash of its images, for the pages' URLs); "" for none.
	Logo string `msgpack:"lg,omitempty" json:"-"`
	// LogoDark says whether the logo has a dark-theme image (OrgLogo.Dark).
	LogoDark bool `msgpack:"ld,omitempty" json:"-"`
	// Skin is the skin the organization's pages use: a built-in or custom skin's name, "default" for the built-in look
	// (no skin), or "" for the primary organization's (the primary organization's "" is the built-in look).
	Skin string `msgpack:"sk,omitempty" json:"skin"`
	// Footer is the footer line of the organization's pages (a little inline HTML, as ui.footer); "" inherits the
	// primary organization's, else ui.footer.
	Footer string `msgpack:"ft,omitempty" json:"footer"`
}

// OrgLogo is an organization's logo (OrgBranding): ID is the organization's. Dark, when set, is shown in the dark
// theme instead of Light.
type OrgLogo struct {
	Meta
	Light     []byte `msgpack:"l" json:"-"`
	LightType string `msgpack:"lt" json:"-"` // image/png, image/jpeg, image/webp or image/svg+xml
	Dark      []byte `msgpack:"d,omitempty" json:"-"`
	DarkType  string `msgpack:"dt,omitempty" json:"-"`
}

func (l *OrgLogo) Kind() Kind   { return KindOrgLogo }
func (l *OrgLogo) Index() Index { return Index{Partition: l.ID} } // read by the organization's id only

// EmailTemplates are an organization's own templates of the emails it sends (package mailtpl): ID is the
// organization's. A part left empty is the primary organization's, else the built-in one, so an organization may change
// only the layout, or only one email.
type EmailTemplates struct {
	Meta
	Set EmailTemplateSet `msgpack:"t" json:"-"`
}

func (t *EmailTemplates) Kind() Kind   { return KindEmailTemplates }
func (t *EmailTemplates) Index() Index { return Index{Partition: t.ID} } // read by the organization's id only

// EmailTemplateSet is a set of email templates: the layout, which holds every email's header and footer and places its
// body with {{template "body" .}}, and each email's subject and bodies, by its name (mailtpl.Names). "" is a part not
// set.
type EmailTemplateSet struct {
	LayoutHTML string                   `msgpack:"lh,omitempty" json:"layout_html"`
	LayoutText string                   `msgpack:"lt,omitempty" json:"layout_text"`
	Emails     map[string]EmailTemplate `msgpack:"e,omitempty" json:"emails"`
}

// Skin is a custom skin of the server (the built-in ones are in the binary, web/skins): a stylesheet loaded after the
// built-in one on the pages of the organizations that choose it (OrgBranding.Skin). Its id is its name (lowercase
// letters, digits and dashes), which never changes; super admins add, change and remove skins. It is global, as the
// organization records are: every organization's pages read it.
type Skin struct {
	Meta
	DisplayName string `msgpack:"dn" json:"display_name"`
	CSS         string `msgpack:"css" json:"-"`
	// CSSVersion is a hash of CSS, the ?v= of the stylesheet's address (so a changed skin is a new address).
	CSSVersion string `msgpack:"cv" json:"-"`
}

func (k *Skin) Kind() Kind   { return KindSkin }
func (k *Skin) Index() Index { return Index{} }

// EmailTemplate is one email's templates: its subject (text), and its body as HTML and as plain text.
type EmailTemplate struct {
	Subject string `msgpack:"s,omitempty" json:"subject"`
	HTML    string `msgpack:"h,omitempty" json:"html"`
	Text    string `msgpack:"x,omitempty" json:"text"`
}

func (o *Org) Index() Index {
	uq := []string{OrgNameKey(o.Name)}
	if o.Primary {
		uq = append(uq, PrimaryOrgKey)
	}
	return Index{
		Partition: "", // global: every organization's page and sign-in reads the organization list
		Unique:    uq,
		Fields:    map[string]any{"name": o.Name, "display_name": o.DisplayName, "created": o.Created},
	}
}

// OrgNameKey is the unique key for an organization name.
func OrgNameKey(name string) string { return Lower(name) }

// PrimaryOrgKey is the unique value the primary organization claims (Org.Primary): every node finds it by this value,
// and a second organization marked primary (a concurrent bootstrap, a restore over another data set) is refused as a
// clash. No organization name is spelled so (ValidOrgName).
const PrimaryOrgKey = "/primary"

// OrgPath is the path of an organization's page or endpoint: /o/<id> followed by rest ("" or starting with "/"). Every
// organization has its own address space, and the OAuth issuer is its root.
func OrgPath(orgID, rest string) string { return "/o/" + orgID + rest }

var orgNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ReservedOrgNames cannot be used because they collide with routes or would confuse users.
var ReservedOrgNames = map[string]bool{
	"admin": true, "api": true, "login": true, "logout": true, "scim": true, "oauth": true, "static": true,
	"assets": true, "account": true, "health": true, "healthz": true, "readyz": true, "well-known": true,
	"www": true, "auth": true, "signin": true, "signup": true, "register": true, "system": true, "root": true,
	"null": true, "undefined": true, "callback": true, "invite": true, "reset": true, "verify-email": true,
	"api-docs": true, "branding": true, "oauth2": true, "openid": true, "well-known-openid": true, "new": true, "settings": true, "help": true, "docs": true,
	"o": true,
}

// ValidOrgName reports whether name is a URL-safe, unreserved organization name that cannot be taken for an id
// (IsID): /o/<org> names an organization by either.
func ValidOrgName(name string) bool {
	return orgNameRe.MatchString(name) && !ReservedOrgNames[name] && !IsID(name)
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
	// Picture is the id of the user's profile picture (UserPicture), "" for none. Shown as its absolute URL
	// (service.Service.PictureURL): a new picture is a new record, so its URL never changes what it shows.
	Picture string `msgpack:"pic,omitempty" json:"-"`
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

// HasVerifiedEmail reports whether addr is a verified address of u: its primary address, verified, or a verified linked
// one.
func (u *User) HasVerifiedEmail(addr string) bool {
	if strings.EqualFold(u.Email, addr) && u.EmailVerified {
		return true
	}
	l, found := u.LinkedEmail(addr)
	return found && l.Verified
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
			"role": string(u.Role), "active": u.Active, "inactive": !u.Active, "created": u.Created,
			"tags": strings.Join(u.Tags, " "), "manager_id": u.Work.ManagerID,
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
		Fields: map[string]any{"display_name": g.DisplayName, "created": g.Created,
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
		return Index{Scope: m.OrgID, Partition: m.OrgID, Fields: map[string]any{"group_id": "", "user_id": ""},
			Expires: m.Removed.Add(RemovedMemberRetention)}
	}
	return Index{
		Scope:     m.OrgID,
		Partition: m.OrgID,
		Fields:    map[string]any{"group_id": m.GroupID, "user_id": m.UserID},
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
	// Resources are the APIs (resource indicators, RFC 8707: an MCP server's URL, say) the tenant owns: unique within
	// the organization (another organization may own the same URL). A self-registered application asking for one of
	// them is governed by this tenant.
	Resources []string `msgpack:"res,omitempty" json:"resources"`
	// SSH is the tenant's SSH certificate authority settings (docs/design/ssh-ca.md); nil: never enabled.
	SSH *TenantSSH `msgpack:"ssh,omitempty" json:"ssh,omitempty"`
}

func (t *Tenant) Kind() Kind { return KindTenant }
func (t *Tenant) Index() Index {
	uniq := []string{TenantNameKey(t.OrgID, t.Name)}
	for _, r := range t.Resources {
		uniq = append(uniq, TenantResourceKey(t.OrgID, r))
	}
	return Index{
		Scope:     t.OrgID,
		Partition: t.OrgID,
		Unique:    uniq,
		Fields: map[string]any{"name": t.Name, "display_name": t.DisplayName, "created": t.Created,
			"ssh_enabled": t.SSH != nil && t.SSH.Enabled},
	}
}

func TenantNameKey(orgID, name string) string { return orgID + "/n/" + Lower(name) }

// TenantResourceKey is the unique value claiming a resource for one tenant of an organization: its canonical form, so
// "https://MCP.example.com/mcp/" cannot be claimed by another tenant than "https://mcp.example.com/mcp". It starts with
// the organization's id like every unique value of the organization's records, so the same resource may belong to
// tenants of two organizations.
func TenantResourceKey(orgID, resource string) string {
	return orgID + "/res/" + CanonicalResource(resource)
}

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

// TenantSSH is a tenant's SSH certificate authority: whether it signs, for whom and for how long (docs/design/ssh-ca.md).
// Servers trust the tenant's CA key, and who may log in as which account is decided by the principals in the
// certificates, which come from the user's username, groups and application roles.
type TenantSSH struct {
	// Enabled off: signing is refused and the discovery document says so; the CA keys and the revocation list (which
	// then revokes every certificate) are still served, so that turning SSH off reaches the servers. The keys are kept.
	Enabled bool `msgpack:"en" json:"enabled"`
	// ClientID is the tenant's SSH application, made when SSH is first enabled (service.UpdateTenantSSH).
	ClientID string `msgpack:"ci,omitempty" json:"client_id,omitempty"`

	// User certificates.
	CertTTL    int `msgpack:"ttl" json:"cert_ttl"`     // seconds, 300..86400
	MaxAuthAge int `msgpack:"maa" json:"max_auth_age"` // seconds a sign-in may be old when it asks for a certificate, 60..86400
	// Where the principals come from.
	PrincipalUsername bool `msgpack:"pu" json:"principal_username"`
	PrincipalGroups   bool `msgpack:"pg" json:"principal_groups"`
	PrincipalRoles    bool `msgpack:"pr" json:"principal_roles"` // the application roles the tenant's access list gives the user
	// What the certificate lets the session do (OpenSSH extensions).
	PermitPTY             bool `msgpack:"pty" json:"permit_pty"`
	PermitUserRC          bool `msgpack:"prc" json:"permit_user_rc"`
	PermitPortForwarding  bool `msgpack:"ppf" json:"permit_port_forwarding"`
	PermitAgentForwarding bool `msgpack:"paf" json:"permit_agent_forwarding"`
	PermitX11Forwarding   bool `msgpack:"px" json:"permit_x11_forwarding"`
	// SourceAddresses are CIDRs or addresses the certificate works from (the critical option source-address); none:
	// anywhere.
	SourceAddresses []string `msgpack:"sa,omitempty" json:"source_addresses"`
	// AllowPrivileged lets managers and administrators get user certificates.
	AllowPrivileged bool `msgpack:"ap" json:"allow_privileged"`
	// RotationDays is the user CA's scheduled rotation; 0: by hand only.
	RotationDays int `msgpack:"rot" json:"rotation_days"`

	// Host certificates.
	HostCerts    bool     `msgpack:"hc" json:"host_certs"`
	HostTTLDays  int      `msgpack:"htd" json:"host_ttl_days"` // 1..365
	HostPatterns []string `msgpack:"hp,omitempty" json:"host_patterns"`
}

// DefaultTenantSSH is what enabling SSH starts from: eight-hour certificates for the user's username and groups, with
// a terminal and ~/.ssh/rc but no forwarding, and no host certificates.
func DefaultTenantSSH() TenantSSH {
	return TenantSSH{CertTTL: 28800, MaxAuthAge: 3600, PrincipalUsername: true, PrincipalGroups: true,
		PermitPTY: true, PermitUserRC: true, HostTTLDays: 90}
}

// Access subject types.
const (
	SubjectUser  = "user"
	SubjectGroup = "group"
)

// TenantAccess gives a user, or every member of a group, access to a tenant's applications: all of them or the
// listed clients, until Expires (zero: no end). Roles and Tags go into the tokens issued for those applications (the
// "roles" claim, and merged into "tags"), and AuthorizationDetails into the access tokens of those registered for
// their types (authdetails.go). ID is AccessID(tenantID, subjectID), so checking a user's access is a few
// direct reads (the user's own record and one per group) rather than a scan.
type TenantAccess struct {
	Meta
	OrgID       string   `msgpack:"o" json:"org_id"`
	TenantID    string   `msgpack:"t" json:"tenant_id"`
	SubjectType string   `msgpack:"st" json:"subject_type"` // SubjectUser or SubjectGroup
	SubjectID   string   `msgpack:"si" json:"subject_id"`
	Roles       []string `msgpack:"r" json:"roles"`
	Tags        []string `msgpack:"tg" json:"tags"`
	// AuthorizationDetails are RFC 9396 authorization details (NormAuthDetails: a JSON array; nil for none).
	AuthorizationDetails json.RawMessage `msgpack:"ad,omitempty" json:"authorization_details,omitempty"`
	AllClients           bool            `msgpack:"ac" json:"all_clients"`
	Clients              []string        `msgpack:"cl" json:"clients"` // client ids, when AllClients is false
	Expires              time.Time       `msgpack:"e" json:"expires,omitzero"`
}

func (a *TenantAccess) Kind() Kind { return KindAccess }
func (a *TenantAccess) Index() Index {
	return Index{
		Scope:     a.OrgID,
		Partition: a.OrgID,
		Fields:    map[string]any{"tenant_id": a.TenantID},
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
	// only proof, refresh tokens always rotate, and it can never use client_credentials or serve every org.
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
	FirstParty     bool     `msgpack:"fp" json:"first_party"` // skip consent
	// RememberConsent remembers each user's approval on the consent screen (Consent), signing out or not, until their
	// access to the application is removed. Off (the default), the application asks once per sign-in: again after the
	// user signs out. Confidential clients only (a public client's identity is not proven), and unused by a first-party
	// one, which never asks.
	RememberConsent bool `msgpack:"rmc,omitempty" json:"remember_consent"`
	// RememberGen is the client's consent generation: it moves on when the client begins remembering consent
	// (service.RemembersConsent turned true), and when where its codes go or who can redeem them changes (redirect
	// URIs, secret, keys, authentication method: service.credentialsChanged). A Consent, and a Grant standing in for
	// consent, is honoured only while its Gen is the client's: one left from before remembering was last turned off
	// (removing them is best effort), or given to the client as it was before an administrator pointed it elsewhere,
	// never comes back into effect.
	RememberGen   int64 `msgpack:"rmg,omitempty" json:"-"`
	RotateRefresh bool  `msgpack:"rr" json:"rotate_refresh_tokens"` // one-time-use refresh tokens (costs a write per refresh)
	// ServiceAccount marks a service account: a non-human principal of the organization (no tenant) that calls the
	// management API and SCIM with client_credentials tokens. Scopes are what it was granted (ServiceAccountScopes),
	// and GrantTypes only client_credentials. It is managed apart from the organization's applications.
	ServiceAccount bool `msgpack:"svc,omitempty" json:"-"`
	// IntrospectOrg lets the client introspect every access token of its organization (a resource server that serves
	// several applications); without it introspection answers active only for tokens issued for the client (aud).
	IntrospectOrg bool `msgpack:"io,omitempty" json:"introspect_org"`
	// AcceptsAPITokens lets the application see its users' personal API tokens (the api scope) through introspection,
	// and lets them be made for it. Off: they are inactive to it, and it is not offered among the applications to make
	// one for, so an application takes them only once its administrator has chosen to.
	AcceptsAPITokens bool `msgpack:"apt,omitempty" json:"accepts_api_tokens"`
	Enabled          bool `msgpack:"en" json:"enabled"`
	// Resources are the resource indicators (RFC 8707) the client may ask tokens for: absolute URIs of the APIs the
	// access tokens are meant for (their aud). A request may name only these; none listed: no resource parameter.
	Resources []string `msgpack:"res,omitempty" json:"resources"`
	// AuthorizationDetailsTypes are the RFC 9396 authorization details types the client uses (its
	// authorization_details_types metadata): the only ones its requests may name, and the only ones its access tokens
	// carry (authdetails.go).
	AuthorizationDetailsTypes []string `msgpack:"adt,omitempty" json:"authorization_details_types"`
	// AuthorizationDetails are the authorization details of the client's own client_credentials tokens
	// (NormAuthDetails: a JSON array; nil for none).
	AuthorizationDetails json.RawMessage `msgpack:"ad,omitempty" json:"authorization_details,omitempty"`
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
	// ProviderID is the organization provider (of another organization, Provider.SourceOrg) this client is the sign-in
	// application of: made and removed with it, never by hand. A client whose provider is gone or no longer uses it is
	// an orphan the sweep removes.
	ProviderID string `msgpack:"pv,omitempty" json:"-"`
	// SSHApp marks the SSH application Quisora made for its tenant (TenantSSH.ClientID names the current one): it goes
	// with the tenant, and one the tenant no longer names is removed by housekeeping.
	SSHApp bool `msgpack:"ssh,omitempty" json:"-"`

	// SelfRegistered marks an application that registered itself (RFC 7591), or whose client_id is the URL of its
	// metadata document (Client ID Metadata Document): an AI client connecting to an MCP server, say. It belongs to
	// the organization it registered or was first authorized in (OrgID), and no tenant (TenantID empty): each
	// authorization request names resources, and the tenant of that organization that owns them (Tenant.Resources), if
	// it allows self-registered apps, decides who may sign in and how. Always a public client with PKCE; consent is
	// always asked.
	SelfRegistered bool `msgpack:"sr,omitempty" json:"self_registered,omitempty"`
	// MetadataURL is the client_id of a metadata-document application: the URL of its document, which the application
	// sends as it is. The record's id is ClientRecordID of it, since the same document is the application of every
	// organization that lets it in, one record each. Empty for every other client, whose client_id is its id.
	MetadataURL string `msgpack:"mu,omitempty" json:"-"`
	// MetadataFetched is when a metadata-document client's document was last read (zero for RFC 7591 ones).
	MetadataFetched time.Time `msgpack:"mf,omitempty" json:"metadata_fetched,omitzero"`
	// LastUsed is when a self-registered app was last given an authorization code; one never used is removed a day
	// after it registered.
	LastUsed time.Time `msgpack:"lu,omitempty" json:"last_used,omitzero"`
}

// DynamicClientPrefix starts the id of a dynamically registered (RFC 7591) client.
const DynamicClientPrefix = "dyn-"

// metadataClientPrefix starts the record id of a metadata-document client (ClientRecordID).
const metadataClientPrefix = "md_"

// ClientRecordID is the id of the record of the client an application names in organization orgID by clientID, the
// client_id it sends. A client's record id is its client_id, except for a metadata-document application, whose
// client_id is the URL of its document and the same in every organization: its record id is a digest of the
// organization and the URL, so each organization has a record of its own, and a request names it with the URL alone.
func ClientRecordID(orgID, clientID string) string {
	if !strings.HasPrefix(clientID, "https://") {
		return clientID
	}
	sum := sha256.Sum256([]byte(orgID + "\n" + clientID))
	return metadataClientPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// ClientID is the client_id the application sends and finds in its tokens (aud, client_id, azp): its id, except for a
// metadata-document application, whose id is a record's (ClientRecordID) and whose client_id is the URL of its document.
func (c *Client) ClientID() string {
	if c.MetadataURL != "" {
		return c.MetadataURL
	}
	return c.ID
}

// IsMetadataClient reports whether the client is a metadata-document application (its client_id is the URL of its
// Client ID Metadata Document).
func (c *Client) IsMetadataClient() bool { return c.SelfRegistered && c.MetadataURL != "" }

// RequirePKCE reports whether authorization requests of the client must use PKCE (S256).
func (c *Client) RequirePKCE() bool { return !c.PKCEOptional || c.Public() }

func (c *Client) Kind() Kind { return KindClient }
func (c *Client) Index() Index {
	return Index{
		Scope:     c.OrgID,
		Partition: c.OrgID,
		Fields: map[string]any{"name": c.Name, "tenant_id": c.TenantID, "auth_method": c.AuthMethod,
			"created": c.Created, "self_registered": c.SelfRegistered, "service_account": c.ServiceAccount,
			"unused_self_registered": c.SelfRegistered && c.LastUsed.IsZero()},
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Upstream sign-in providers

// Provider types. Every type but GitHub is OpenID Connect underneath: Google, GitLab and Auth0 are presets of the
// issuer and scopes; Microsoft (Entra ID) adds its tenant rules; an organization provider is the issuer of another
// organization of this server (Provider.SourceOrg), whose users sign in to this one as guests.
const (
	ProviderOIDC         = "oidc"
	ProviderGitHub       = "github"
	ProviderGoogle       = "google"
	ProviderGitLab       = "gitlab"
	ProviderAuth0        = "auth0"
	ProviderMicrosoft    = "microsoft"
	ProviderOrganization = "organization"
)

// UpstreamAccount is the account at an upstream provider that a sign-in went through, as that provider names it: what
// the idp scope passes on to applications (the idp_sub, idp_tenant and idp_login claims), so one can tell which of the
// user's linked accounts was used and match it against the provider's own APIs. Quisora decides nothing on it.
type UpstreamAccount struct {
	// Subject is the provider's stable ID of the account: the object ID (oid) for Microsoft, whose sub differs for each
	// application; the sub for the other OpenID Connect providers (for an organization provider, the user's ID
	// there); the user ID for GitHub.
	Subject string `msgpack:"s" json:"s"`
	// Tenant is the Microsoft directory (tid) the account is in, or for an organization provider the organization
	// (Provider.SourceOrg); empty for the other providers.
	Tenant string `msgpack:"t,omitempty" json:"t,omitempty"`
	// Login is the name the person signs in to the provider with, a login_hint for it: the user principal name
	// (preferred_username) for Microsoft, the username for GitHub, the email address for the others - for an
	// organization provider only one that organization verified, else none. A hint only: it can change, and it is
	// never the account's identity (Subject is).
	Login string `msgpack:"l,omitempty" json:"l,omitempty"`
}

// ProviderTypes lists the provider types in the order the admin console offers them.
var ProviderTypes = []string{ProviderOIDC, ProviderGoogle, ProviderMicrosoft, ProviderGitHub, ProviderGitLab, ProviderAuth0,
	ProviderOrganization}

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
	// SourceOrg is the organization whose users sign in through an organization provider: the provider's issuer is
	// that organization's, and its client (ClientID) is an application of that organization, made and removed with
	// the provider (Client.ProviderID).
	SourceOrg string `msgpack:"so,omitempty" json:"source_org,omitempty"`
	// SourceGroups, when set, are groups of SourceOrg (ids): only their members sign in through the organization
	// provider, a first sign-in that creates a guest, one that links by email and every later one alike, so someone
	// taken out of the groups no longer signs in. Empty: every user of SourceOrg may. A group deleted since lets
	// nobody in; with all of them deleted, nobody signs in through the provider.
	SourceGroups []string `msgpack:"sg,omitempty" json:"source_groups,omitempty"`
}

// OIDC reports whether the provider signs in with OpenID Connect (every type but GitHub).
func (p *Provider) OIDC() bool { return p.Type != ProviderGitHub }

func (p *Provider) Kind() Kind { return KindProvider }

// ProviderNameKey is the unique value of a provider's name in its organization (names match without regard to case).
func ProviderNameKey(orgID, name string) string { return orgID + "/n/" + Lower(name) }

func (p *Provider) Index() Index {
	return Index{
		Scope:     p.OrgID,
		Partition: p.OrgID,
		Unique:    []string{ProviderNameKey(p.OrgID, p.Name)},
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
		Partition: p.OrgID,
		Unique:    []string{PasskeyCredentialKey(p.UserID, p.CredentialID)},
	}
}

// PasskeyCredentialKey is the unique key for a WebAuthn credential id: unique per user, not across the server. A
// passkey is bound to the site, not to an organization, so one person may register the same authenticator in several
// organizations; each such passkey lives in its own organization's partition, and a sign-in names the user first (the
// WebAuthn user handle), then finds the credential among that user's passkeys.
func PasskeyCredentialKey(userID string, id []byte) string { return userID + "/" + b64(id) }

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
	// Scopes are what the provider granted with Refresh (its token response's scope, else the scopes asked for, sorted):
	// what the token may be used for. Stored and cleared with it.
	Scopes []string `msgpack:"gs,omitempty" json:"granted_scopes,omitempty"`
}

// ProviderCallbackPath is the path of provider providerID's callback address in organization orgID's address space: where
// the upstream provider sends the browser back, and so the redirect URI registered with it. One function, so the
// address an organization provider registers in its source organization is the one the sign-in uses.
func ProviderCallbackPath(orgID, providerID string) string {
	return OrgPath(orgID, "/login/callback/"+url.PathEscape(providerID))
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
		Fields:    map[string]any{"provider_id": i.ProviderID},
	}
}

func IdentityKey(providerID, subject string) string { return providerID + "/" + subject }

// ---------------------------------------------------------------------------------------------------------------
// Browser sessions

type Session struct {
	Meta
	// Epoch is the account's session epoch it was made in (User.SessionEpoch): it works only while that is current.
	Epoch    uint64   `msgpack:"ep,omitempty" json:"-"`
	UserID   string   `msgpack:"ui" json:"user_id"`
	OrgID    string   `msgpack:"o" json:"org_id"`
	AMR      []string `msgpack:"amr" json:"amr"`
	Provider string   `msgpack:"pv" json:"provider_id,omitempty"` // upstream provider used to sign in, if any
	// UpstreamAMR is how that provider said the person signed in to it (its ID token's amr, model.CleanAMR). Tokens
	// pass it on (model.TokenAMR); Quisora's own decisions (MFA policies, acr) read only AMR, what Quisora verified,
	// or the provider's say-so when it is trusted for the second factor (Provider.TrustMFA: "mfa" in AMR).
	UpstreamAMR []string `msgpack:"uamr,omitempty" json:"upstream_amr,omitempty"`
	// Upstream is the account at that provider the person signed in with (the idp scope's claims).
	Upstream  *UpstreamAccount `msgpack:"upa,omitempty" json:"-"`
	Passkey   string           `msgpack:"pk" json:"-"` // passkey used to sign in, if any (deleting it ends the session)
	AuthTime  time.Time        `msgpack:"at" json:"auth_time"`
	Expires   time.Time        `msgpack:"ex" json:"expires"`
	IdleTTL   int              `msgpack:"it" json:"-"` // seconds; 0 = no idle timeout
	LastSeen  time.Time        `msgpack:"ls" json:"last_seen"`
	IP        string           `msgpack:"ip" json:"ip"`
	UserAgent string           `msgpack:"ua" json:"user_agent"`
	CSRF      string           `msgpack:"cs" json:"-"`
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
	Epoch uint64 `msgpack:"ep,omitempty" json:"-"`
	// ConsentGen is the client's consent generation (Client.RememberGen) when the grant was made: the grant spares
	// the user the consent screen only while it is still the client's.
	ConsentGen int64    `msgpack:"cg,omitempty" json:"-"`
	ClientID   string   `msgpack:"ci" json:"client_id"`
	UserID     string   `msgpack:"ui" json:"user_id"`
	OrgID      string   `msgpack:"o" json:"org_id"`
	SessionID  string   `msgpack:"si" json:"session_id"`
	Scopes     []string `msgpack:"sc" json:"scopes"`
	AMR        []string `msgpack:"amr" json:"amr"`
	// IdP is the type of the upstream provider the sign-in went through (Provider.Type, such as "microsoft"), empty
	// for a sign-in of Quisora's own: the idp claim of the tokens issued from the grant.
	IdP string `msgpack:"idp,omitempty" json:"idp,omitempty"`
	// UpstreamAMR is how that provider said the person signed in to it (Session.UpstreamAMR): the tokens' amr is AMR
	// and then these (model.TokenAMR), while acr and Quisora's own checks read AMR alone.
	UpstreamAMR []string `msgpack:"uamr,omitempty" json:"upstream_amr,omitempty"`
	// Upstream is the account at that provider the person signed in with (Session.Upstream): the idp_sub, idp_tenant
	// and idp_login claims of the idp scope.
	Upstream *UpstreamAccount `msgpack:"upa,omitempty" json:"-"`
	AuthTime time.Time        `msgpack:"at" json:"auth_time"`
	Counter  uint64           `msgpack:"n" json:"-"`
	// Rotated is when Counter last moved: the retry grace of the token before the current one runs from it, never
	// from Updated, which other changes (a re-seal of Key) move too.
	Rotated time.Time `msgpack:"rt,omitempty" json:"-"`
	// Key is the grant's refresh token key, random, sealed with the master key (service.GrantKeyBinding); the tokens
	// are made from it (oidc refreshToken).
	Key string `msgpack:"rk,omitempty" json:"-"`
	// Resources are the resource indicators (RFC 8707) the user authorized; a refresh may narrow them, never widen.
	Resources []string `msgpack:"rs" json:"resources,omitempty"`
	// AuthDetailTypes are the authorization details types (RFC 9396) the authorization request named; a token request
	// may narrow them, never widen. Empty: it named none, and the tokens carry every type the client is registered for.
	AuthDetailTypes []string `msgpack:"adt,omitempty" json:"authorization_details_types,omitempty"`
	// ClaimsUI and ClaimsID are claims requested one by one (the claims request parameter) for userinfo and for
	// the ID token, beyond those of the scopes.
	ClaimsUI []string  `msgpack:"cu,omitempty" json:"claims_userinfo,omitempty"`
	ClaimsID []string  `msgpack:"cid,omitempty" json:"claims_id_token,omitempty"`
	Expires  time.Time `msgpack:"ex" json:"expires"`
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
		Fields:    map[string]any{"client_id": g.ClientID},
		Expires:   g.Expires,
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Remembered consent

// Consent is what a user allowed one application on its consent screen, remembered until the user or an
// administrator removes the application's access (service.RevokeAppAccess), the application asks again
// (prompt=consent) or either is deleted (the sweep). Signing out keeps it, as other identity providers do: the
// application asks again only for what the user has not allowed yet. One record per user and application
// (ConsentID). Only confidential clients' consent is remembered: a public client's identity is not proven, so another
// app could claim it and inherit the consent (oidc hasConsent).
type Consent struct {
	Meta
	UserID   string `msgpack:"ui" json:"user_id"`
	OrgID    string `msgpack:"o" json:"org_id"`
	ClientID string `msgpack:"ci" json:"client_id"`
	// Allowed are the sets the user approved, each its scopes (with those of claims requested one by one: oidc
	// consentScopes) and resource indicators. A request is covered when one set holds all it asks for: scopes allowed
	// for one resource are not allowed for another. A new approval drops the sets it covers.
	Allowed []ConsentSet `msgpack:"al" json:"allowed"`
	// Gen is the client's RememberGen when the consent was recorded: another, and the consent is not honoured.
	Gen int64 `msgpack:"g,omitempty" json:"-"`
}

// ConsentSet is one approval of a Consent.
type ConsentSet struct {
	Scopes    []string `msgpack:"sc" json:"scopes"`
	Resources []string `msgpack:"rs,omitempty" json:"resources,omitempty"`
}

// ConsentID is the id of user userID's Consent for client clientID: derived from both, so there is at most one and
// it is read by id.
func ConsentID(userID, clientID string) string {
	sum := sha256.Sum256([]byte("consent\x00" + userID + "\x00" + clientID))
	var b [16]byte
	copy(b[:], sum[:16])
	return FormatID(b)
}

func (c *Consent) Kind() Kind { return KindConsent }
func (c *Consent) Index() Index {
	return Index{
		Scope:     c.UserID,
		Partition: c.OrgID,
		Fields:    map[string]any{"client_id": c.ClientID},
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
		Fields:    map[string]any{"created": t.Created},
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
	return Index{Partition: "", Expires: k.Expires}
}

// ---------------------------------------------------------------------------------------------------------------
// SSH certificate authority

// SSH CA key purposes (SSHKey.Purpose).
const (
	SSHPurposeUser = "user"
	SSHPurposeHost = "host"
)

// SSHAlgEd25519 is the algorithm of every SSH CA key made.
const SSHAlgEd25519 = "ssh-ed25519"

// SSHKey is a tenant's SSH CA key: it signs the tenant's user (or host) certificates, and servers trust its public
// half. Like a signing key it is published from Created, signs from NotBefore until RetireAt, and is published until
// Expires (zero: kept until removed by hand). A key removed by hand keeps its record, without its private half, as a
// tombstone (Removed set) until every certificate it could have signed has expired: the tenant's revocation list
// revokes the key itself meanwhile, for servers whose CA file still lists it.
type SSHKey struct {
	Meta
	OrgID     string `msgpack:"o" json:"org_id"`
	TenantID  string `msgpack:"t" json:"tenant_id"`
	Purpose   string `msgpack:"pu" json:"purpose"` // SSHPurposeUser or SSHPurposeHost
	Alg       string `msgpack:"a" json:"alg"`
	PublicKey string `msgpack:"pub" json:"public_key"` // authorized_keys form, no comment
	// PrivateKey is sealed (service.SSHKeyBinding): the key in OpenSSH PEM form.
	PrivateKey string    `msgpack:"pk" json:"-"`
	NotBefore  time.Time `msgpack:"nb" json:"not_before"`
	RetireAt   time.Time `msgpack:"ra" json:"retire_at,omitzero"` // stops signing (zero: until a successor starts)
	Expires    time.Time `msgpack:"ex" json:"expires,omitzero"`
	// Removed is when the key was removed (a tombstone: no longer published, never signs, revoked by the KRL).
	Removed time.Time `msgpack:"rm,omitempty" json:"removed,omitzero"`
}

func (k *SSHKey) Kind() Kind { return KindSSHKey }
func (k *SSHKey) Index() Index {
	return Index{
		Scope:     k.OrgID,
		Partition: k.OrgID,
		Fields:    map[string]any{"tenant_id": k.TenantID},
		Expires:   k.Expires,
	}
}

// SSHCert is a certificate issued, kept until it has expired: the KRL and the console's list are made from them.
type SSHCert struct {
	Meta
	OrgID       string    `msgpack:"o" json:"org_id"`
	TenantID    string    `msgpack:"t" json:"tenant_id"`
	UserID      string    `msgpack:"ui,omitempty" json:"user_id,omitempty"` // "" for a host certificate
	Host        bool      `msgpack:"h,omitempty" json:"host,omitempty"`
	Serial      uint64    `msgpack:"sn" json:"serial,string"` // random, non-zero
	KeyID       string    `msgpack:"k" json:"key_id"`         // the certificate's key id, as sshd logs it
	CAKeyID     string    `msgpack:"ca" json:"ca_key_id"`     // the SSHKey that signed it
	Principals  []string  `msgpack:"p" json:"principals"`
	Fingerprint string    `msgpack:"fp" json:"fingerprint"` // SHA256:… of the certified public key
	ValidAfter  time.Time `msgpack:"va" json:"valid_after"`
	ValidBefore time.Time `msgpack:"vb" json:"valid_before"`
	// Extensions and SourceAddresses are what a user certificate grants: the names of its OpenSSH extensions, sorted,
	// and the addresses of its critical option source-address (none: anywhere). A certificate that grants more than the
	// tenant's settings now would is revoked (SSHReasonSettingsChanged).
	Extensions      []string `msgpack:"ext,omitempty" json:"extensions,omitempty"`
	SourceAddresses []string `msgpack:"sa,omitempty" json:"source_addresses,omitempty"`
	// SessionEpoch and Stamp are the session epoch and sign-out counters the certificate was asked for under: those of
	// the access token's grant (the sign endpoint) or of the session (the account page), never the current ones. The
	// certificate counts only while they would (user certificates).
	SessionEpoch uint64       `msgpack:"se,omitempty" json:"-"`
	Stamp        SignOutStamp `msgpack:"st" json:"-"`
	// SignIn is the session (the account page) or grant (the sign endpoint) the certificate was issued under: ending
	// that sign-in revokes it (service.RevokeSSHCertsFrom). "" for a host certificate.
	SignIn    string    `msgpack:"sg,omitempty" json:"-"`
	Via       string    `msgpack:"via" json:"via"`                          // "cli", "account" or "api"
	IssuedBy  string    `msgpack:"ib,omitempty" json:"issued_by,omitempty"` // the actor, for host certificates
	Revoked   bool      `msgpack:"rv,omitempty" json:"revoked"`
	RevokedAt time.Time `msgpack:"rva,omitempty" json:"revoked_at,omitzero"`
	RevokedBy string    `msgpack:"rvb,omitempty" json:"revoked_by,omitempty"`
	// RevokedReason is why, when Quisora found it revoked (RevokedBy "system": the user lost access, a role or a
	// principal it carries, or the sign-in it was issued under was taken back); "" for one revoked by hand. Listed as the reason of the certificate (SSHCertView).
	RevokedReason string `msgpack:"rvr,omitempty" json:"-"`
}

func (c *SSHCert) Kind() Kind { return KindSSHCert }

// Index lists a user certificate by its tenant (tenant_id) and a host certificate by its tenant under another field
// (host_tenant_id), so the revocation list reads the user certificates of a tenant without its host certificates, of
// which it needs only those revoked by hand.
func (c *SSHCert) Index() Index {
	userTenant, hostTenant := c.TenantID, ""
	if c.Host {
		userTenant, hostTenant = "", c.TenantID
	}
	return Index{
		Scope:     c.OrgID,
		Partition: c.OrgID,
		Fields: map[string]any{"tenant_id": userTenant, "host_tenant_id": hostTenant, "user_id": c.UserID, "revoked": c.Revoked,
			"created": c.Created, "key_id": clipRunes(c.KeyID, 255), "fingerprint": c.Fingerprint, "serial": strconv.FormatUint(c.Serial, 10),
			"principals": clipRunes(strings.Join(c.Principals, " "), MaxTagsText)},
		Expires: c.ValidBefore.Add(time.Hour),
	}
}

// SSHRevokedSignIn records that a sign-in, a session or a refresh grant (SSHCert.SignIn: its id is the sign-in's), was
// taken back, which revokes the SSH certificates issued under it (service.RevokeSSHCertsFrom): the revocation lists
// revoke a certificate whose sign-in has one. The revocation also marks revoked the certificates it lists, but in a
// gossip cluster a certificate signed on another node at that moment may not have replicated to it, while its signer
// still read the sign-in as there: this record, replicated, revokes it all the same. Kept until every certificate that
// could have been signed under the sign-in has expired. A user's own sign-out writes none: its certificates last.
type SSHRevokedSignIn struct {
	Meta
	OrgID   string    `msgpack:"o" json:"org_id"`
	UserID  string    `msgpack:"ui" json:"user_id"`
	Expires time.Time `msgpack:"ex" json:"expires"`
}

func (r *SSHRevokedSignIn) Kind() Kind { return KindSSHRevokedSignIn }
func (r *SSHRevokedSignIn) Index() Index {
	return Index{Scope: r.OrgID, Partition: r.ID, Expires: r.Expires}
}

// UserPicture is a user's profile picture, made by package picture (a square JPEG or PNG). Its id is new for every
// picture and random (NewRandomID): it is the picture's public address (/o/<org id>/pictures/<id>), which anyone
// holding it may read, so it is never guessed from the user. The user names their current picture (User.Picture);
// any other is a leftover of a change and served by nobody, and the orphan sweep removes it.
type UserPicture struct {
	Meta
	OrgID  string `msgpack:"o" json:"org_id"`
	UserID string `msgpack:"ui" json:"user_id"`
	Type   string `msgpack:"t" json:"-"` // image/jpeg or image/png
	Data   []byte `msgpack:"d" json:"-"`
	// Source names what the picture was made from: the URL it was fetched from, or "sha256:" and the hash of the
	// image given. A directory that sends the same one again changes nothing.
	Source string `msgpack:"s,omitempty" json:"-"`
}

func (p *UserPicture) Kind() Kind { return KindUserPicture }
func (p *UserPicture) Index() Index {
	return Index{Scope: p.OrgID, Partition: p.ID} // read by its id only
}

// clipRunes cuts s to at most n characters: a queryable field longer than its column is refused with the record.
func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
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
	// TargetID is the id of the user the event targets, when its target is one (Target then holds their username at
	// the time): the username may change or be reused, the id names the account for good.
	TargetID string `msgpack:"ti,omitempty" json:"target_id,omitempty"`
	// SuperAdmin marks an event whose actor or target user was a super admin when it was recorded. Super admins are
	// invisible to everyone below them, so their events are left out of every other reader's audit log by this
	// indexed field (service.ListAudit): decided once, when the event is written, it holds whatever the users are
	// renamed or promoted to later, and lets a page and its total be read with one filter.
	SuperAdmin bool `msgpack:"sa,omitempty" json:"-"`
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
			"outcome": cmp.Or(a.Outcome, AuditOutcome(a.Action)), "ip": a.IP, // older events may carry no outcome
			"super_admin": a.SuperAdmin},
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
	// For is the account's address when an invitation or reset link was issued: the link opens only while that is
	// still the address on file (service.PeekLink), so one sent to a mistyped address that was then corrected sets
	// nobody's credentials.
	For string `msgpack:"f,omitempty" json:"-"`
	// IssuedBy is the user who issued an invitation ("" for the system or a command): until it is used, nobody else
	// below a super admin may replace it (service.mayResetSignIn).
	IssuedBy string `msgpack:"ib,omitempty" json:"-"`
	// IssuedByClient is the service account that issued an invitation (IssuedBy is then ""): judged again when the
	// invitation is used, as a user issuer is (service.PeekLink).
	IssuedByClient string `msgpack:"ic,omitempty" json:"-"`
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
	return Index{Scope: l.UserID, Partition: l.OrgID, Unique: []string{LinkTokenKey(l.TokenHash)}, Expires: l.Expires}
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
	return Index{Partition: s.OrgID} // read by user id only: never listed by organization, so it has no scope
}

// Lock is a lease record, replicated with a compare-and-swap its owner decides: Holder holds it until Until, and a
// holder that stops renewing it stops counting. Each node's report of its master keys is one (service.ReportMasterKey):
// Holder is the report, Until how long it counts. The housekeeping leader's report of its master key re-seal
// (service.ResealProgress) is another, with an Until that never comes. An organization's deletion guard is a third
// (service.DeleteOrg): its id is the organization's, so it is in the organization's partition, and Holder says whether
// a deletion holds it.
type Lock struct {
	Meta
	Holder string    `msgpack:"h" json:"holder"`
	Until  time.Time `msgpack:"ut" json:"until"`
}

// OrgDeleted is the Holder of an organization's deletion guard once its deletion has decided (service.DeleteOrg). Such
// guards are indexed (org_deleted), so housekeeping finds a deletion that decided and did not finish.
const OrgDeleted = "org.deleted"

func (l *Lock) Kind() Kind { return KindLock }
func (l *Lock) Index() Index {
	return Index{Partition: l.ID, Fields: map[string]any{"org_deleted": l.Holder == OrgDeleted}}
}

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

// QueueItem is an item of a node's retry queue (package queue): an email waiting for SMTP, a back-channel logout
// waiting for its application. Only the node that queued it reads, counts or delivers it (its scope names the node),
// so the nodes sharing a database never contend for one, and a node that is gone leaves its items to expire: Expires
// is the queue's discard horizon, past the point the item would have been given up anyway.
type QueueItem struct {
	Meta
	Queue string `msgpack:"q"`  // the queue's name ("mail", "logout")
	Node  string `msgpack:"nd"` // the id of the node that queued it
	// Key is the item's fairness key (an organization's id): its share of the queue and of the workers.
	Key     string    `msgpack:"k,omitempty"`
	Attempt int       `msgpack:"a,omitempty"` // failed deliveries so far
	Next    time.Time `msgpack:"n"`           // not to be delivered before
	// Sealed is the item itself, sealed with the master key (it carries single-use links and user identifiers).
	Sealed  string    `msgpack:"s"`
	Expires time.Time `msgpack:"ex"`
}

// QueueScope is the scope of node's items of queue: every listing and count of a queue is of one node's items.
func QueueScope(queue, node string) string { return queue + "/" + node }

// QueueSlot is the slot of an item of key next due at next: the key (hex, so no key is a prefix of another's slots)
// then the due time, so one key's items are a range of the slot index (QueueKeySlots) in the order they come due.
func QueueSlot(key string, next time.Time) string {
	return QueueKeySlots(key) + strconv.FormatInt(max(next.UnixMilli(), 0)+1e15, 10)[1:]
}

// QueueKeySlots is the prefix of the slots of key's items.
func QueueKeySlots(key string) string { return hex.EncodeToString([]byte(key)) + "/" }

func (q *QueueItem) Kind() Kind { return KindQueue }
func (q *QueueItem) Index() Index {
	return Index{Scope: QueueScope(q.Queue, q.Node), Fields: map[string]any{"due": q.Next, "slot": QueueSlot(q.Key, q.Next)},
		Expires: q.Expires}
}

// validUntilField is the indexed end date: the zero time when there is none (the "expiring" field tells them apart).
func validUntilField(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
