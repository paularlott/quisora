package model

import (
	"net/url"
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
	SessionTTL    int  `msgpack:"sttl" json:"session_ttl"`  // seconds
	SessionIdle   int  `msgpack:"sidl" json:"session_idle"` // seconds
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
}

func (o *Org) Kind() Kind { return KindOrg }
func (o *Org) Index() Index {
	return Index{
		Unique: []string{OrgNameKey(o.Name)},
		Fields: map[string]any{"name": o.Name, "display_name": o.DisplayName, "primary": o.Primary, "created": o.Created},
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
	// StatusChanged records the last time the account was disabled or enabled again (Active says which).
	StatusChanged *StatusChange `msgpack:"stc,omitempty" json:"status_changed"`
}

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
		Scope:  u.OrgID,
		Unique: uq,
		Fields: map[string]any{
			"username": u.Username, "email": u.Email, "name": u.FullName(), "external_id": u.ExternalID,
			"role": string(u.Role), "active": u.Active, "created": u.Created,
			"tags": strings.Join(u.Tags, " "), "user_type": u.UserType, "department": u.Work.Department,
			"manager_id": u.Work.ManagerID, "employee_number": u.Work.EmployeeNumber,
			"expiring": u.ValidUntil != nil, "valid_until": validUntilField(u.ValidUntil),
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

type Group struct {
	Meta
	OrgID       string   `msgpack:"o" json:"org_id"`
	DisplayName string   `msgpack:"dn" json:"display_name"`
	ExternalID  string   `msgpack:"x" json:"external_id,omitempty"`
	Tags        []string `msgpack:"tg" json:"tags"`
}

func (g *Group) Kind() Kind { return KindGroup }
func (g *Group) Index() Index {
	uq := []string{GroupNameKey(g.OrgID, g.DisplayName)}
	if g.ExternalID != "" {
		uq = append(uq, GroupExternalIDKey(g.OrgID, g.ExternalID))
	}
	return Index{
		Scope:  g.OrgID,
		Unique: uq,
		Fields: map[string]any{"display_name": g.DisplayName, "external_id": g.ExternalID, "created": g.Created,
			"tags": strings.Join(g.Tags, " ")},
	}
}

// Member is one user's membership of a group. Each membership is its own record so concurrent adds and removes on
// different nodes never overwrite each other. ID is MemberID(groupID, userID). Scoped by organization so both "members
// of a group" and "groups of a user" are org-bounded filters.
type Member struct {
	Meta
	GroupID string `msgpack:"g" json:"group_id"`
	UserID  string `msgpack:"ui" json:"user_id"`
	OrgID   string `msgpack:"o" json:"org_id"`
}

func (m *Member) Kind() Kind { return KindMember }
func (m *Member) Index() Index {
	return Index{
		Scope:  m.OrgID,
		Fields: map[string]any{"group_id": m.GroupID, "user_id": m.UserID, "created": m.Created},
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
		Scope:  t.OrgID,
		Unique: uniq,
		Fields: map[string]any{"name": t.Name, "display_name": t.DisplayName, "created": t.Created},
	}
}

func TenantNameKey(orgID, name string) string { return orgID + "/n/" + Lower(name) }

// TenantResourceKey is the unique value claiming a resource for one tenant (server-wide): its canonical form, so
// "https://MCP.example.com/mcp/" cannot be claimed by another tenant than "https://mcp.example.com/mcp".
func TenantResourceKey(resource string) string { return "res/" + CanonicalResource(resource) }

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
	Clients     []string  `msgpack:"c" json:"clients"` // client ids, when AllClients is false
	Expires     time.Time `msgpack:"e" json:"expires,omitzero"`
}

func (a *TenantAccess) Kind() Kind { return KindAccess }
func (a *TenantAccess) Index() Index {
	return Index{
		Scope: a.OrgID,
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

// IsMetadataClient reports whether the client's id is the URL of its Client ID Metadata Document.
func (c *Client) IsMetadataClient() bool {
	return c.SelfRegistered && strings.HasPrefix(c.ID, "https://")
}

// RequirePKCE reports whether authorization requests of the client must use PKCE (S256).
func (c *Client) RequirePKCE() bool { return !c.PKCEOptional || c.Public() }

func (c *Client) Kind() Kind { return KindClient }
func (c *Client) Index() Index {
	return Index{
		Scope: c.OrgID,
		Fields: map[string]any{"name": c.Name, "tenant_id": c.TenantID, "auth_method": c.AuthMethod,
			"created": c.Created, "self_registered": c.SelfRegistered},
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
		Scope:  p.OrgID,
		Unique: []string{p.OrgID + "/n/" + Lower(p.Name)},
		Fields: map[string]any{"name": p.Name, "type": p.Type, "enabled": p.Enabled, "created": p.Created},
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Passkeys

type Passkey struct {
	Meta
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
		Scope:  p.UserID,
		Unique: []string{PasskeyCredentialKey(p.CredentialID)},
		Fields: map[string]any{"name": p.Name, "created": p.Created, "last_used": p.LastUsed},
	}
}

// PasskeyCredentialKey is the unique key for a WebAuthn credential id.
func PasskeyCredentialKey(id []byte) string { return b64(id) }

// ---------------------------------------------------------------------------------------------------------------
// Upstream identities linked to users

type Identity struct {
	Meta
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
	Via string `msgpack:"v" json:"via,omitempty"`
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
		Authority: ProviderAuthority(p), Via: via}
}

func (i *Identity) Kind() Kind { return KindIdentity }
func (i *Identity) Index() Index {
	return Index{
		Scope:  i.UserID,
		Unique: []string{IdentityKey(i.ProviderID, i.Subject)},
		Fields: map[string]any{"provider_id": i.ProviderID, "created": i.Created},
	}
}

func IdentityKey(providerID, subject string) string { return providerID + "/" + subject }

// ---------------------------------------------------------------------------------------------------------------
// Browser sessions

type Session struct {
	Meta
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
}

func (s *Session) Kind() Kind { return KindSession }
func (s *Session) Index() Index {
	return Index{
		Scope:   s.UserID,
		Fields:  map[string]any{"ip": s.IP, "created": s.Created, "last_seen": s.LastSeen},
		Expires: s.Expires,
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
	ClientID  string    `msgpack:"ci" json:"client_id"`
	UserID    string    `msgpack:"ui" json:"user_id"`
	OrgID     string    `msgpack:"o" json:"org_id"`
	SessionID string    `msgpack:"si" json:"session_id"`
	Scopes    []string  `msgpack:"sc" json:"scopes"`
	AMR       []string  `msgpack:"amr" json:"amr"`
	AuthTime  time.Time `msgpack:"at" json:"auth_time"`
	Nonce     string    `msgpack:"nc" json:"-"`
	Counter   uint64    `msgpack:"n" json:"-"`
	// Key is the grant's refresh token key, random, sealed with the master key (service.GrantKeyBinding); the tokens
	// are made from it (oidc refreshToken). Grants from before it existed have Secret instead (see GrantRefreshKeys).
	Key    string `msgpack:"rk,omitempty" json:"-"`
	Secret []byte `msgpack:"k,omitempty" json:"-"` // legacy: seed of a key derived from the master key
	// Resources are the resource indicators (RFC 8707) the user authorized; a refresh may narrow them, never widen.
	Resources []string `msgpack:"rs" json:"resources,omitempty"`
	// ClaimsUI and ClaimsID are claims requested one by one (the claims request parameter) for userinfo and for
	// the ID token, beyond those of the scopes.
	ClaimsUI []string  `msgpack:"cu,omitempty" json:"claims_userinfo,omitempty"`
	ClaimsID []string  `msgpack:"cid,omitempty" json:"claims_id_token,omitempty"`
	Expires  time.Time `msgpack:"ex" json:"expires"`
	Revoked  bool      `msgpack:"rv" json:"revoked"`
}

func (g *Grant) Kind() Kind { return KindGrant }
func (g *Grant) Index() Index {
	return Index{
		Scope:   g.UserID,
		Fields:  map[string]any{"client_id": g.ClientID, "session_id": g.SessionID, "created": g.Created},
		Expires: g.Expires,
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Personal API tokens

type APIToken struct {
	Meta
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
}

func (t *APIToken) Kind() Kind { return KindAPIToken }
func (t *APIToken) Index() Index {
	return Index{
		Scope:   t.UserID,
		Fields:  map[string]any{"name": t.Name, "created": t.Created, "last_used": t.LastUsed},
		Expires: t.Expires,
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
	return Index{Fields: map[string]any{"alg": k.Alg, "created": k.Created}, Expires: k.Expires}
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
		Scope:   a.OrgID,
		Fields:  map[string]any{"action": a.Action, "actor": a.Actor, "target": a.Target, "created": a.Created},
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
	Email   string    `msgpack:"e" json:"email,omitempty"` // verification: the address being verified
	Used    bool      `msgpack:"x" json:"used"`
	Expires time.Time `msgpack:"ex" json:"expires"`
	// UserCreated is the creation time of the user the link was issued for: the link works only for that very
	// account, not for another one that has (or later gets) the same id.
	UserCreated time.Time `msgpack:"uc" json:"-"`
	// IssuedBy is the user who issued an invitation ("" for the system or a command): until it is used, nobody else
	// below a super admin may replace it (service.mayResetSignIn).
	IssuedBy string `msgpack:"ib,omitempty" json:"-"`
}

func (l *LinkToken) Kind() Kind { return KindLink }
func (l *LinkToken) Index() Index {
	return Index{Scope: l.UserID, Fields: map[string]any{"purpose": l.Purpose, "created": l.Created},
		Expires: l.Expires}
}

// SignIn holds a user's sign-in stamps, kept apart from the user record (ID is the user's id). A sign-in writes
// only this record, so it can never overwrite (or be overwritten by) an administrator's change of the user; in a
// replicated cluster it is written with a cluster-wide compare-and-swap like the user itself (QuorumCAS), which makes
// the TOTP step a replay guard on every node at once. Failed attempts and lockouts are counted in ephemeral state
// (login rate limits), not here.
type SignIn struct {
	Meta
	OrgID        string    `msgpack:"o" json:"org_id"`
	LastLogin    time.Time `msgpack:"ll" json:"last_login"`
	TOTPLastStep int64     `msgpack:"tl" json:"-"` // the last TOTP time step accepted: a code works once
}

func (s *SignIn) Kind() Kind { return KindSignIn }
func (s *SignIn) Index() Index {
	return Index{Scope: s.OrgID, Fields: map[string]any{"last_login": s.LastLogin}}
}

// Lock is a cluster-wide lock record (written with QuorumCAS): Holder holds it until Until. Used to serialise
// changes whose safety depends on more than one record (the last administrator of an organization).
type Lock struct {
	Meta
	Holder string    `msgpack:"h" json:"holder"`
	Until  time.Time `msgpack:"u" json:"until"`
}

func (l *Lock) Kind() Kind   { return KindLock }
func (l *Lock) Index() Index { return Index{} }

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
