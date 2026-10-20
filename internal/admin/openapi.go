package admin

import (
	"encoding/json"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/scim"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// The OpenAPI 3.1 description of the management API. It is written out here (not generated from the handlers) and a
// test checks that every registered /api route is described.

type opDoc struct {
	Method, Path, Tag, Summary string
	Req, Resp                  string // component schema names ("" = none)
	Status                     int    // success status (default 200)
	List                       bool   // Resp is the item schema of a {items,total} list taking q/sort/desc/offset/limit
	Sorts                      string // comma separated sortable fields for lists
	Extra                      []string
}

const (
	pOrg  = "/api/orgs/{org}"
	pUser = pOrg + "/users/{id}"
)

// paramDocs describe the Extra parameters that need more than their name.
var paramDocs = map[string]string{
	"plain":             "1: download the backup unencrypted (required unless X-Backup-Password is given)",
	"X-Backup-Password": "password to encrypt the backup with, at least 12 characters (required unless ?plain=1)",
}

var opDocs = []opDoc{
	{"GET", "/api/orgs", "Organizations", "List organizations (non-super callers see only their own)", "", "Org", 200, true, "name,display_name,created", nil},
	{"POST", "/api/orgs", "Organizations", "Create an organization (super admin)", "OrgInput", "Org", 201, false, "", nil},
	{"GET", pOrg, "Organizations", "Get an organization", "", "Org", 200, false, "", nil},
	{"PATCH", pOrg, "Organizations", "Rename or edit an organization", "OrgInput", "Org", 200, false, "", nil},
	{"DELETE", pOrg, "Organizations", "Delete an organization (super admin). ?cascade=1 also deletes its users, groups, clients and providers", "", "Ok", 200, false, "", []string{"cascade"}},

	{"GET", pOrg + "/users", "Users", "List users; ?tag=<tag> keeps only users carrying exactly that tag; q also matches tags", "", "User", 200, true, "username,email,name,role,active,created,last_login", []string{"role", "active", "tag"}},
	{"POST", pOrg + "/users", "Users", "Create a user without a password; optionally issue (and email) an invitation link", "UserCreate", "UserCreated", 201, false, "", nil},
	{"GET", pUser, "Users", "Get a user with their groups", "", "User", 200, false, "", nil},
	{"PATCH", pUser, "Users", "Update a user (role, active, profile)", "UserInput", "User", 200, false, "", nil},
	{"DELETE", pUser, "Users", "Delete a user and everything that belongs to them", "", "Ok", 200, false, "", nil},
	{"DELETE", pUser + "/password", "Users", "Remove the user's password and end their sessions; they can sign in with a password again only after accepting a new invitation", "", "", 204, false, "", nil},
	{"POST", pUser + "/invite", "Users", "Issue a new single-use invitation link (valid 7 days; earlier links stop working) through which the user sets a password, if their organization allows passwords, or creates a passkey; optionally email it", "InviteRequest", "Invite", 200, false, "", nil},
	{"POST", pUser + "/emails", "Users", "Link another email address to the user (managers and up, for users they manage and themselves; for yourself it needs a recent re-authentication: 403, field reauth). With email set up it starts unverified and the user is mailed a link to verify it; without email it counts as verified at once (your own: always unverified). 409 when the address is already anyone's primary or linked address, 422 beyond 10 addresses", "EmailInput", "User", 201, false, "", nil},
	{"DELETE", pUser + "/emails/{address}", "Users", "Unlink an email address; the primary address cannot be removed (make another address primary first)", "", "User", 200, false, "", nil},
	{"POST", pUser + "/emails/{address}/primary", "Users", "Make a verified linked address the primary one; the old primary becomes a linked address", "", "User", 200, false, "", nil},
	{"POST", pUser + "/emails/{address}/verify", "Users", "Mail the user a new verification link for one of their unverified addresses; 503 when email is not set up", "", "Ok", 200, false, "", nil},
	{"GET", pUser + "/apps", "Users", "The applications the user granted access to (managers and up, for users they manage, and yourself)", "", "ConnectedApp", 200, true, "", nil},
	{"DELETE", pUser + "/apps/{client}", "Users", "End the user's access to one application: it is sent a back-channel logout and its refresh tokens stop working; 404 when the user granted it nothing", "", "Ok", 200, false, "", nil},
	{"GET", pUser + "/sessions", "Users", "The user's signed-in sessions, the current one first (managers and up, for users they manage, and yourself)", "", "UserSession", 200, true, "", nil},
	{"DELETE", pUser + "/sessions/{session}", "Users", "Sign the user out of one session (its applications are sent back-channel logouts); 409 for the session making the request", "", "Ok", 200, false, "", nil},
	{"GET", pUser + "/providers", "Users", "The sign-in providers linked to the user (managers and up, for users they manage, and yourself)", "", "LinkedProvider", 200, true, "", nil},
	{"DELETE", pUser + "/providers/{provider}", "Users", "Unlink the user's account at one sign-in provider; for someone else it may be their last way to sign in (send an invitation afterwards), for yourself it may not (409) and needs a recent re-authentication (403, field reauth); 404 when none is linked", "", "Ok", 200, false, "", nil},
	{"GET", pUser + "/passkeys", "Users", "The user's passkeys, oldest first (managers and up, for users they manage, and yourself)", "", "UserPasskey", 200, true, "", nil},
	{"DELETE", pUser + "/passkeys/{passkey}", "Users", "Remove one of the user's passkeys and end the sessions that signed in with it; for someone else it may be their last way to sign in (send an invitation afterwards), for yourself it may not (409) and needs a recent re-authentication (403, field reauth)", "", "Ok", 200, false, "", nil},
	{"DELETE", pUser + "/sessions", "Users", "Sign the user out everywhere (revoke sessions and refresh grants)", "", "Ok", 200, false, "", nil},
	{"GET", pUser + "/tokens", "Users", "List the user's personal API tokens, newest first (offset/limit only; secrets are never shown again)", "", "APIToken", 200, true, "", nil},
	{"DELETE", pUser + "/tokens/{token}", "Users", "Revoke one of the user's personal API tokens at once", "", "Ok", 200, false, "", nil},

	{"GET", pOrg + "/groups", "Groups", "List groups", "", "Group", 200, true, "display_name,created", nil},
	{"POST", pOrg + "/groups", "Groups", "Create a group", "GroupInput", "Group", 201, false, "", nil},
	{"GET", pOrg + "/groups/{id}", "Groups", "Get a group", "", "Group", 200, false, "", nil},
	{"PATCH", pOrg + "/groups/{id}", "Groups", "Update a group", "GroupInput", "Group", 200, false, "", nil},
	{"DELETE", pOrg + "/groups/{id}", "Groups", "Delete a group", "", "Ok", 200, false, "", nil},
	{"GET", pOrg + "/groups/{id}/members", "Groups", "List the members of a group (offset/limit only)", "", "Member", 200, true, "", nil},
	{"PUT", pOrg + "/groups/{id}/members/{user}", "Groups", "Add a user to a group (idempotent)", "", "Ok", 200, false, "", nil},
	{"DELETE", pOrg + "/groups/{id}/members/{user}", "Groups", "Remove a user from a group", "", "Ok", 200, false, "", nil},

	{"GET", pOrg + "/tenants", "Tenants", "List tenants (groups of applications sharing sign-in rules); each carries its client count", "", "Tenant", 200, true, "name,display_name,created", nil},
	{"POST", pOrg + "/tenants", "Tenants", "Create a tenant", "TenantInput", "Tenant", 201, false, "", nil},
	{"GET", pOrg + "/tenants/{id}", "Tenants", "Get a tenant", "", "Tenant", 200, false, "", nil},
	{"PATCH", pOrg + "/tenants/{id}", "Tenants", "Update a tenant (name, display name, description, sign-in settings, resources)", "TenantInput", "Tenant", 200, false, "", nil},
	{"GET", pOrg + "/tenants/{id}/self-registered", "Tenants", "The self-registered applications users of this tenant have authorized, with how many users they hold access for", "", "SelfRegisteredApp", 200, true, "", nil},
	{"DELETE", pOrg + "/tenants/{id}/self-registered/{client}", "Tenants", "End a self-registered application's access in the organization: every user's grants to it go; it can come back only by asking users again", "", "Ok", 200, false, "", nil},
	{"DELETE", pOrg + "/tenants/{id}", "Tenants", "Delete a tenant; 409 while it still has clients", "", "Ok", 200, false, "", nil},
	{"GET", pOrg + "/tenants/{id}/access", "Tenant access", "List the users and groups with access to the tenant's applications (q searches name and email)", "", "Access", 200, true, "name,type,expires,created", nil},
	{"POST", pOrg + "/tenants/{id}/access", "Tenant access", "Give a user or group access; 409 when they already have it", "AccessInput", "Access", 201, false, "", nil},
	{"GET", pOrg + "/tenants/{id}/access/{aid}", "Tenant access", "Get one access entry", "", "Access", 200, false, "", nil},
	{"PATCH", pOrg + "/tenants/{id}/access/{aid}", "Tenant access", "Change roles, tags, applications or the end date (subject_type and subject_id are ignored)", "AccessInput", "Access", 200, false, "", nil},
	{"DELETE", pOrg + "/tenants/{id}/access/{aid}", "Tenant access", "Remove an access entry", "", "Ok", 200, false, "", nil},

	{"GET", pOrg + "/clients", "Clients", "List OAuth clients; ?tenant=<tenant id> keeps only that tenant's clients", "", "Client", 200, true, "name,auth_method,created", []string{"tenant"}},
	{"POST", pOrg + "/clients", "Clients", "Create an OAuth client; the response carries its secret, shown once", "ClientInput", "ClientWithSecret", 201, false, "", nil},
	{"GET", pOrg + "/clients/{id}", "Clients", "Get an OAuth client", "", "Client", 200, false, "", nil},
	{"PATCH", pOrg + "/clients/{id}", "Clients", "Update an OAuth client", "ClientInput", "Client", 200, false, "", nil},
	{"DELETE", pOrg + "/clients/{id}", "Clients", "Delete an OAuth client", "", "Ok", 200, false, "", nil},
	{"POST", pOrg + "/clients/{id}/secret", "Clients", "Rotate the client secret; the old one stops working at once", "", "SecretResult", 200, false, "", nil},

	{"GET", pOrg + "/providers", "Providers", "List upstream sign-in providers", "", "Provider", 200, true, "name,type,created", nil},
	{"POST", pOrg + "/providers", "Providers", "Create a provider (client_secret is write-only)", "ProviderInput", "Provider", 201, false, "", nil},
	{"GET", pOrg + "/providers/{id}", "Providers", "Get a provider", "", "Provider", 200, false, "", nil},
	{"PATCH", pOrg + "/providers/{id}", "Providers", "Update a provider (omit client_secret to keep it)", "ProviderInput", "Provider", 200, false, "", nil},
	{"DELETE", pOrg + "/providers/{id}", "Providers", "Delete a provider", "", "Ok", 200, false, "", nil},

	{"GET", pOrg + "/settings", "Settings", "Get organization settings", "", "Settings", 200, false, "", nil},
	{"PUT", pOrg + "/settings", "Settings", "Update organization settings", "OrgInput", "Settings", 200, false, "", nil},
	{"GET", pOrg + "/audit", "Audit", "List audit events, newest first by default. Also: source (store, cluster or victorialogs) and, in a gossip cluster, nodes and nodes_answered (a node that did not answer in time is missing from the page)", "", "Audit", 200, true, "action,created", nil},
	{"GET", "/api/audit", "Audit", "List the audit events of every organization (super admins), newest first by default; ?org=<name> for one. Items carry org_name; source, nodes and nodes_answered as for an organization's audit log", "", "Audit", 200, true, "action,created", []string{"org"}},

	{"GET", "/api/keys", "Keys", "List signing keys, newest first, with their state (super admin)", "", "Key", 200, true, "", nil},
	{"POST", "/api/keys/rotate", "Keys", "Rotate the signing key now (super admin): a new key signs from now on; the old one stays published until the tokens it signed have expired", "", "KeyRotated", 200, false, "", nil},
	{"GET", "/api/backup", "Backup", "Download a backup of the whole store (super admin, with an API token: the backup scope): every record, secrets still sealed with the master key. It is encrypted (AES-256-GCM, the key derived from the X-Backup-Password header by argon2id; application/octet-stream) unless ?plain=1 asks for it unencrypted (a gzip stream); one or the other is required (400 otherwise). \"quisora backup --server\" downloads it with ?plain=1 over TLS and encrypts it on the operator's machine, so the password never reaches the server. A point-in-time snapshot where the backend has one; taken while the server runs; one at a time per server (409 otherwise). Restore it with \"quisora restore\" or \"quisora serve --restore-from\"", "", "Backup", 200, false, "", []string{"plain", "header:X-Backup-Password"}},
	{"GET", "/api/master-key", "Keys", "Where a master key rotation stands (super admin): the keys this node and every live node use, how many stored secrets are still sealed with a previous key or open with none, and whether the previous keys can be removed now (previous_keys_removable, state, detail). Reads every sealed value: a few seconds on a large directory", "", "MasterKey", 200, false, "", nil},
	{"GET", "/api/cluster", "Cluster", "This node's cluster status (super admin): size, quorum, every node with its address, state and role, readiness, and the counts of writes a majority did not confirm, refused writes and clock skew", "", "Cluster", 200, false, "", nil},
}

type obj = map[string]any

func prop(typ string) obj { return obj{"type": typ} }
func strArr() obj         { return obj{"type": "array", "items": prop("string")} }
func ref(n string) obj    { return obj{"$ref": "#/components/schemas/" + n} }
func schema(required []string, props obj) obj {
	o := obj{"type": "object", "properties": props}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

func nullable(typ string) obj { return obj{"type": []string{typ, "null"}} }

// tagsSchema describes the tags of a user or group.
func tagsSchema() obj {
	return obj{"type": "array", "maxItems": 50, "uniqueItems": true, "description": "identifiers (letters, digits and . _ : / -, 1-64 characters, starting and ending with a letter or digit; a colon separates a namespace, e.g. dept:finance); stored sorted; sent to applications in the tags claim together with the tags of the user's groups",
		"items": obj{"type": "string", "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,62}[A-Za-z0-9])?$"}}
}

// rolesSchema describes the application roles of a tenant access entry.
func rolesSchema() obj {
	return obj{"type": "array", "maxItems": 50, "uniqueItems": true, "description": "application role names (same characters as tags); sent in the roles claim of tokens for the tenant's applications",
		"items": obj{"type": "string", "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,62}[A-Za-z0-9])?$"}}
}

func dateTime() obj { return obj{"type": "string", "format": "date-time"} }

func components() obj {
	meta := func(p obj) obj {
		p["id"] = prop("string")
		p["created"] = dateTime()
		p["updated"] = dateTime()
		return p
	}
	orgSettings := schema(nil, obj{"password_login": prop("boolean"), "passkey_login": prop("boolean"),
		"require_mfa": prop("boolean"), "session_ttl": obj{"type": "integer", "description": "seconds; 0 = server default"},
		"session_idle": obj{"type": "integer", "description": "seconds; 0 = server default"}})
	userProps := meta(obj{"org_id": prop("string"), "username": prop("string"), "email": prop("string"),
		"email_verified": prop("boolean"), "name": obj{"type": "string", "description": "read-only full name: given and family name"},
		"given_name": prop("string"), "family_name": prop("string"),
		"linked_emails": obj{"type": "array", "items": ref("LinkedEmail"), "description": "further addresses of the user; they let upstream providers find the user and never sign in by themselves"},
		"role":          obj{"type": "string", "enum": []string{"super_admin", "admin", "manager", "user"}},
		"active":        prop("boolean"), "external_id": prop("string"),
		"locale":                obj{"type": "string", "description": "BCP 47 language tag such as en-GB (the locale claim); en_GB is accepted and stored as en-GB"},
		"zoneinfo":              obj{"type": "string", "description": "IANA time zone such as Europe/London (the zoneinfo claim)"},
		"user_type":             obj{"type": "string", "description": "employee, contractor, guest, service, or another short value from provisioning"},
		"valid_until":           obj{"type": "string", "format": "date-time", "description": "null for no end; otherwise the end of the account: from then it cannot sign in or use tokens, and within a minute it is disabled with its sessions ended (back-channel logout)"},
		"work":                  ref("Work"),
		"phone_number":          obj{"type": "string", "description": "contact number in E.164 form (the phone_number claim); never used to sign in"},
		"phone_number_verified": prop("boolean"),
		"password_changed_at":   obj{"type": "string", "format": "date-time", "description": "when the password was last set or removed; null if never"},
		"mfa_enrolled_at":       obj{"type": "string", "format": "date-time", "description": "when the authenticator app was last set up; null without one"},
		"status_changed": obj{"type": "object", "description": "the last time the account was disabled or enabled again (active says which); null if never",
			"properties": obj{"at": dateTime(), "by": obj{"type": "string", "description": "a username, client:<name> or system"},
				"by_id": prop("string"), "reason": prop("string")}},
		"manager": obj{"type": "object", "properties": obj{"id": prop("string"), "name": prop("string")}, "description": "the manager's name; present on GET of one user"},
		"tags":    tagsSchema(), "has_password": obj{"type": "boolean", "description": "whether a password is set; the password itself is never returned"},
		"passkeys": obj{"type": "integer", "description": "number of registered passkeys; present on GET of one user"}, "last_login": dateTime(),
		"can_reset_sign_in": obj{"type": "boolean", "description": "whether the caller may issue this user an invitation or remove their password: for a manager or administrator who has a way to sign in, only a super admin may; present on GET of one user"},
		"groups":            obj{"type": "array", "items": schema(nil, obj{"id": prop("string"), "display_name": prop("string")}), "description": "present on GET of one user"}})
	userIn := obj{"username": prop("string"), "email": prop("string"), "given_name": obj{"type": "string", "description": "first name; required on create and never empty"},
		"family_name": obj{"type": "string", "description": "last name; optional"}, "role": prop("string"), "active": prop("boolean"), "external_id": prop("string"),
		"locale":                obj{"type": "string", "description": "BCP 47 language tag (en_GB accepted); \"\" clears"},
		"zoneinfo":              obj{"type": "string", "description": "IANA time zone; \"\" clears"},
		"user_type":             prop("string"),
		"valid_until":           obj{"type": "string", "description": "RFC 3339 time or a date (YYYY-MM-DD, ends at the start of that day UTC); \"\" = no end"},
		"work":                  obj{"$ref": "#/components/schemas/Work", "description": "fields left out are unchanged; \"\" clears one"},
		"email_verified":        prop("boolean"),
		"phone_number":          obj{"type": "string", "description": "international form (+ and the country code; spaces, dots, dashes and brackets are dropped); \"\" clears; a new number is unverified unless phone_number_verified is sent"},
		"phone_number_verified": prop("boolean"),
		"status_reason":         obj{"type": "string", "description": "recorded when this change sets active to a new value (at most 500 characters)"},
		"tags":                  tagsSchema()}
	userIn["email"] = obj{"type": "string", "description": "required on create, unique in the organization; the sign-in name (email address + password)"}
	userIn["username"] = obj{"type": "string", "description": "optional; shown to applications as preferred_username, defaults to the email; never used to sign in"}
	userCreate := schema([]string{"email", "given_name"}, obj{})
	for k, v := range userIn {
		userCreate["properties"].(obj)[k] = v
	}
	userCreate["properties"].(obj)["invite"] = obj{"type": "object", "description": "issue an invitation link and return it in the response",
		"properties": obj{"email": obj{"type": "boolean", "description": "also email it (needs an email address)"}}}
	userCreated := schema(nil, obj{"invite": ref("Invite")})
	for k, v := range userProps {
		userCreated["properties"].(obj)[k] = v
	}
	tenantResources := obj{"type": "array", "items": prop("string"), "description": "the APIs the tenant owns (resource indicators, RFC 8707: an MCP server's URL, say), unique across the server; a self-registered application asking for one is governed by this tenant"}
	tenantSettings := schema(nil, obj{"members_only": obj{"type": "boolean", "description": "only users and groups with access (see Tenant access) may sign in to the tenant's applications; otherwise everyone in the organization may"},
		"password_login": prop("boolean"), "passkey_login": prop("boolean"),
		"all_providers":     obj{"type": "boolean", "description": "allow every enabled provider of the organization, including future ones"},
		"providers":         obj{"type": "array", "items": prop("string"), "description": "provider ids allowed when all_providers is false"},
		"require_mfa":       obj{"type": "boolean", "description": "in addition to the organization setting"},
		"self_registration": obj{"type": "boolean", "description": "applications that registered themselves (RFC 7591, or a Client ID Metadata Document) may sign users in for the tenant's resources; off by default"}})
	clientProps := meta(obj{"org_id": prop("string"), "tenant_id": obj{"type": "string", "description": "tenant of this organization; defaults to the organization's default tenant"}, "name": prop("string"), "description": prop("string"),
		"redirect_uris": strArr(), "post_logout_redirect_uris": strArr(), "backchannel_logout_uri": prop("string"),
		"grant_types": strArr(), "scopes": strArr(),
		"resources":                    obj{"type": "array", "items": prop("string"), "description": "resource indicators (RFC 8707) the client may ask tokens for: absolute URIs without a fragment, at most 20; a request naming any other is refused with invalid_target"},
		"token_endpoint_auth_method":   obj{"type": "string", "enum": []string{"client_secret_post", "client_secret_basic", "private_key_jwt", "none"}, "description": "none = public client (SPA, mobile, CLI): PKCE only, no secret, refresh tokens always rotate"},
		"id_token_signed_response_alg": prop("string"), "jwks": prop("string"), "jwks_uri": prop("string"),
		"first_party": prop("boolean"), "scim": prop("boolean"),
		"rotate_refresh_tokens": prop("boolean"), "introspect_org": prop("boolean"), "enabled": prop("boolean"),
		"require_pkce": obj{"type": "boolean", "description": "default true; false lets a confidential client send authorization requests without PKCE (public clients always need it)"}})
	clientIn := obj{}
	for k, v := range clientProps {
		if k != "id" && k != "created" && k != "updated" && k != "org_id" {
			clientIn[k] = v
		}
	}
	clientSecret := schema(nil, obj{})
	for k, v := range clientProps {
		clientSecret["properties"].(obj)[k] = v
	}
	clientSecret["properties"].(obj)["secret"] = obj{"type": "string", "description": "shown once"}
	provProps := meta(obj{"org_id": prop("string"), "type": obj{"type": "string", "enum": model.ProviderTypes},
		"name": prop("string"), "issuer": prop("string"), "client_id": prop("string"), "scopes": strArr(),
		"auto_provision": prop("boolean"), "trust_mfa": prop("boolean"), "link_by_email": prop("boolean"), "allowed_domains": strArr(), "enabled": prop("boolean"),
		"tenant": prop("string"), "allowed_tenants": strArr(),
		"has_secret": prop("boolean"), "callback_url": obj{"type": "string", "description": "this provider's redirect URI, to register with the provider"}})
	provIn := obj{"id": obj{"type": "string", "format": "uuid", "description": "create only, optional: choose the id (and so the callback URL) before the provider is set up"}, "type": obj{"type": "string", "enum": model.ProviderTypes},
		"name":            obj{"type": "string", "description": "button label; on create, empty means the type's name (Google, Microsoft…)"},
		"issuer":          obj{"type": "string", "description": "oidc: the https issuer; gitlab: the server address (empty: gitlab.com); auth0: the domain; ignored for google, github and microsoft"},
		"tenant":          obj{"type": "string", "description": "microsoft: a tenant ID, or organizations (then allowed_tenants is required)"},
		"allowed_tenants": obj{"type": "array", "items": prop("string"), "description": "microsoft with organizations: the tenant IDs whose users may sign in"},
		"client_id":       prop("string"),
		"client_secret":   obj{"type": "string", "writeOnly": true}, "scopes": strArr(), "auto_provision": prop("boolean"), "trust_mfa": prop("boolean"), "link_by_email": prop("boolean"),
		"allowed_domains": strArr(), "enabled": prop("boolean")}
	orgProps := meta(obj{"name": obj{"type": "string", "description": "URL name"}, "display_name": prop("string"),
		"primary": prop("boolean"), "settings": ref("OrgSettings"),
		"users": obj{"type": "integer", "description": "user count, super admins only"}})

	return obj{
		"Error": schema([]string{"error"}, obj{"error": prop("string"), "field": obj{"type": "string", "description": "the input field the error is about, when there is one"}}),
		"Ok":    schema(nil, obj{"ok": prop("boolean")}),
		"UserSession": schema(nil, obj{"id": obj{"type": "string", "description": "an opaque handle, not the session's id"},
			"current": obj{"type": "boolean", "description": "the session making this request"}, "created": dateTime(), "last_seen": dateTime(),
			"expires": dateTime(), "ip": prop("string"), "user_agent": prop("string"), "amr": strArr()}),
		"ConnectedApp": schema(nil, obj{"client_id": prop("string"), "name": prop("string"), "scopes": strArr(),
			"since": dateTime(), "last_used": dateTime(), "grants": obj{"type": "integer", "description": "live refresh grants (one per signed-in session)"}}),
		"UserPasskey": schema(nil, obj{"id": prop("string"), "name": prop("string"), "created": dateTime(), "last_used": dateTime(),
			"transports": strArr(), "backup_eligible": prop("boolean"), "backup_state": prop("boolean"),
			"problem": obj{"type": "string", "enum": []string{"disabled", "unverified"}, "description": "why it cannot sign in; absent when it works"}}),
		"LinkedProvider": schema(nil, obj{"provider_id": prop("string"), "name": prop("string"), "type": prop("string"),
			"enabled": prop("boolean"), "email": prop("string"), "linked": dateTime(),
			"via": obj{"type": "string", "enum": []string{"email", "provision", "connect", "admin"}, "description": "how it was linked"}}),
		"Cluster": schema(nil, obj{"node_id": prop("string"), "standalone": prop("boolean"), "replicating": prop("boolean"),
			"size": prop("integer"), "quorum": prop("integer"), "members": prop("integer"), "alive": prop("integer"),
			"leader": prop("boolean"), "ready": prop("boolean"), "writable": prop("boolean"), "behind": prop("boolean"),
			"catching_up": prop("boolean"), "last_sync": dateTime(), "sync_point": dateTime(), "forced_start": prop("string"),
			"refused": prop("integer"), "unconfirmed": prop("integer"), "clock_skewed": prop("integer"),
			"skew_refused": prop("integer"),
			"nodes": obj{"type": "array", "description": "every member, as this node sees it (replicated clusters only)",
				"items": schema(nil, obj{"id": prop("string"), "address": prop("string"),
					"state": obj{"type": "string", "enum": []string{"alive", "suspect", "dead", "leaving"}},
					"ready": prop("boolean"), "leader": prop("boolean"), "self": prop("boolean"), "version": prop("string")})}}),
		"MasterKey": schema(nil, obj{"active_key": prop("string"),
			"previous_keys": obj{"type": "array", "items": prop("string"), "description": "this node's server.previous_master_keys, by key id"},
			"nodes": obj{"type": "object", "description": "the keys every live node reported, by node id",
				"additionalProperties": schema(nil, obj{"active_key": prop("string"),
					"previous_keys": obj{"type": "array", "items": prop("string")}})},
			"nodes_agree":             obj{"type": "boolean", "description": "every live node seals with active_key"},
			"stale_secrets":           obj{"type": "integer", "description": "stored secrets sealed with a previous key (being re-sealed)"},
			"unopenable_secrets":      obj{"type": "integer", "description": "stored secrets no configured key opens"},
			"legacy_grants":           obj{"type": "integer", "description": "refresh grants from an earlier version still bound to a previous key"},
			"previous_keys_removable": obj{"type": "boolean", "description": "the previous keys can be removed now"},
			"state":                   obj{"type": "string", "enum": []string{"none", "waiting_for_nodes", "resealing", "unopenable", "legacy_grants", "complete"}},
			"detail":                  prop("string")}),
		"Work": schema(nil, obj{"title": prop("string"), "department": prop("string"), "organization": prop("string"),
			"division": prop("string"), "cost_center": prop("string"), "employee_number": prop("string"),
			"manager_id": obj{"type": "string", "description": "id of another user of the organization (no reporting loops)"}}),
		"OrgSettings": orgSettings,
		"Org":         schema(nil, orgProps),
		"OrgInput":    schema(nil, obj{"name": prop("string"), "display_name": prop("string"), "settings": ref("OrgSettings")}),
		"Settings": schema(nil, func() obj {
			p := meta(obj{"name": prop("string"), "display_name": prop("string"), "primary": prop("boolean"),
				"settings": ref("OrgSettings"), "default_session_ttl": prop("integer"), "default_session_idle": prop("integer")})
			return p
		}()),
		"User":          schema(nil, userProps),
		"UserInput":     schema(nil, userIn),
		"UserCreate":    userCreate,
		"UserCreated":   userCreated,
		"LinkedEmail":   schema([]string{"address", "verified"}, obj{"address": prop("string"), "verified": prop("boolean"), "added": dateTime()}),
		"EmailInput":    schema([]string{"address"}, obj{"address": prop("string")}),
		"InviteRequest": schema(nil, obj{"email": obj{"type": "boolean", "description": "also email the link (needs an email address)"}}),
		"Invite": schema([]string{"url", "expires"}, obj{"url": obj{"type": "string", "description": "single-use link; shown only now"}, "expires": dateTime(),
			"emailed": prop("boolean"), "email_warning": obj{"type": "string", "description": "why the email was not sent; the link still works"}}),
		"Group": schema(nil, meta(obj{"org_id": prop("string"), "display_name": prop("string"), "external_id": prop("string"), "tags": tagsSchema(),
			"members": obj{"type": "integer", "description": "number of users in the group"}})),
		"GroupInput": schema(nil, obj{"display_name": prop("string"), "external_id": prop("string"), "tags": tagsSchema()}),
		"Member": schema(nil, obj{"id": prop("string"), "username": prop("string"), "name": obj{"type": "string", "description": "the user's full name"},
			"email": prop("string"), "role": prop("string")}),
		"APIToken": schema(nil, obj{"id": prop("string"), "name": prop("string"), "scopes": strArr(),
			"audience":   obj{"type": "array", "items": prop("string"), "description": "api tokens: the client ids that may introspect the token; empty: any confidential client of the organization"},
			"app_scopes": obj{"type": "array", "items": prop("string"), "description": "api tokens: the application scopes the token is narrowed to; empty: its owner's full access"},
			"created":    dateTime(), "expires": obj{"type": "string", "format": "date-time", "description": "absent: never"},
			"last_used": obj{"type": "string", "format": "date-time", "description": "absent: never used"}}),
		"TenantSettings": tenantSettings,
		"Tenant": schema(nil, meta(obj{"org_id": prop("string"), "name": obj{"type": "string", "description": "URL-safe, unique in the organization"},
			"display_name": prop("string"), "description": prop("string"), "settings": ref("TenantSettings"),
			"resources": tenantResources,
			"clients":   obj{"type": "integer", "description": "number of clients in the tenant"}})),
		"TenantInput": schema(nil, obj{"name": prop("string"), "display_name": prop("string"), "description": prop("string"),
			"settings": ref("TenantSettings"), "resources": tenantResources}),
		"SelfRegisteredApp": schema(nil, obj{"client_id": prop("string"), "name": obj{"type": "string", "description": "the name the application gave itself"},
			"metadata_document": obj{"type": "boolean", "description": "client_id is the URL of its Client ID Metadata Document"},
			"redirect_uris":     strArr(), "created": dateTime(), "last_used": dateTime(),
			"users": obj{"type": "integer", "description": "users of the organization it holds access for"}}),
		"Access": schema(nil, meta(obj{"org_id": prop("string"), "tenant_id": prop("string"),
			"subject_type": obj{"type": "string", "enum": []string{"user", "group"}}, "subject_id": prop("string"),
			"name": obj{"type": "string", "description": "the user's full name or the group's name"}, "detail": obj{"type": "string", "description": "the user's email address"},
			"roles": rolesSchema(), "tags": tagsSchema(), "all_clients": prop("boolean"),
			"clients": obj{"type": "array", "items": prop("string"), "description": "client ids, when all_clients is false"},
			"expires": obj{"type": "string", "format": "date-time", "description": "absent: no end"}, "expired": prop("boolean")})),
		"AccessInput": schema(nil, obj{"subject_type": obj{"type": "string", "enum": []string{"user", "group"}, "description": "required on create"},
			"subject_id": obj{"type": "string", "description": "user or group id; required on create"}, "roles": rolesSchema(), "tags": tagsSchema(),
			"all_clients": obj{"type": "boolean", "description": "default true"}, "clients": obj{"type": "array", "items": prop("string"), "description": "client ids of this tenant, when all_clients is false"},
			"expires": obj{"type": "string", "description": "RFC 3339 time, or a date (YYYY-MM-DD: access ends at the start of that day, UTC); empty: no end; omitted on update: unchanged"}}),
		"Client":           schema(nil, clientProps),
		"ClientInput":      schema(nil, clientIn),
		"ClientWithSecret": clientSecret,
		"SecretResult":     schema(nil, obj{"client_id": prop("string"), "secret": prop("string")}),
		"Provider":         schema(nil, provProps),
		"ProviderInput":    schema(nil, provIn),
		"Audit": schema(nil, meta(obj{"org_id": prop("string"), "actor_id": prop("string"), "actor": prop("string"),
			"action": prop("string"), "target": prop("string"), "ip": prop("string"),
			"detail": obj{"type": "object", "additionalProperties": prop("string")}})),
		"Key": schema(nil, meta(obj{"alg": prop("string"), "not_before": dateTime(), "retire_at": dateTime(), "expires": dateTime(),
			"state": obj{"type": "string", "enum": []string{"signing", "next", "previous"},
				"description": "signing: signs new tokens now; next: published, signs from not_before; previous: no longer signs, published until expires so its tokens still verify"}})),
		"KeyRotated": schema([]string{"rotated"}, obj{"rotated": prop("boolean")}),
	}
}

var (
	specOnce sync.Once
	specJSON []byte
)

func buildSpec() []byte {
	comps := components()
	for _, d := range opDocs {
		if d.List {
			comps[d.Resp+"List"] = schema([]string{"items", "total"}, obj{
				"items": obj{"type": "array", "items": ref(d.Resp)}, "total": prop("integer")})
		}
	}
	paths := obj{}
	for _, d := range opDocs {
		item, _ := paths[d.Path].(obj)
		if item == nil {
			item = obj{}
			paths[d.Path] = item
		}
		var params []any
		for _, seg := range strings.Split(d.Path, "/") {
			if strings.HasPrefix(seg, "{") {
				n := strings.Trim(seg, "{}")
				desc := "id"
				if n == "org" {
					desc = "organization URL name"
				} else if n == "id" && strings.Contains(d.Path, "/tenants/{id}") {
					desc = "tenant id or name"
				}
				params = append(params, obj{"name": n, "in": "path", "required": true, "description": desc, "schema": prop("string")})
			}
		}
		params = append(params, obj{"$ref": "#/components/parameters/ApiVersion"})
		if d.List {
			for _, q := range []struct{ n, t, d string }{{"q", "string", "case-insensitive substring search"},
				{"sort", "string", "sort field: " + d.Sorts}, {"desc", "boolean", "descending order (1)"},
				{"offset", "integer", "items to skip"}, {"limit", "integer", "page size, default 25, max 100"}} {
				params = append(params, obj{"name": q.n, "in": "query", "description": q.d, "schema": prop(q.t)})
			}
		}
		for _, e := range d.Extra {
			p := obj{"name": e, "in": "query", "schema": prop("string")}
			if h, ok := strings.CutPrefix(e, "header:"); ok { // a request header rather than a query parameter
				p["name"], p["in"] = h, "header"
			}
			if desc, ok := paramDocs[p["name"].(string)]; ok {
				p["description"] = desc
			}
			params = append(params, p)
		}
		status := d.Status
		if status == 0 {
			status = 200
		}
		respSchema := ref(d.Resp)
		if d.List {
			respSchema = ref(d.Resp + "List")
		}
		sc := http_status(status)
		success := obj{"description": "Success", "headers": obj{"Api-Version": obj{"schema": prop("string")}}}
		switch {
		case d.Resp == "Backup": // a file, not JSON
			success["content"] = obj{"application/gzip": obj{"schema": obj{"type": "string", "format": "binary"}}}
		case d.Resp != "":
			success["content"] = obj{"application/json": obj{"schema": respSchema}}
		}
		// The backup download takes its own scope; admin is not enough for it (and it is the only route backup opens).
		scope := "admin"
		if d.Resp == "Backup" {
			scope = "backup"
		}
		op := obj{"tags": []string{d.Tag}, "summary": d.Summary, "operationId": opID(d), "parameters": params,
			"security": []obj{{"session": []string{}}, {"bearer": []string{scope}}},
			"responses": obj{
				sc:    success,
				"400": errResp("Unsupported Api-Version or unreadable body"), "401": errResp("Not signed in or invalid token"),
				"403": errResp("Not permitted (or CSRF check failed, or the token lacks the " + scope + " scope)"), "404": errResp("Not found"),
				"409": errResp("Conflict"), "422": errResp("Validation failed; `field` names the input"),
				"503": errResp("This server cannot make the change now (catching up with its cluster, or cut off from its majority), or a majority has not confirmed it yet; Retry-After says when to try again"),
			}}
		if d.Req != "" {
			op["requestBody"] = obj{"required": true, "content": obj{"application/json": obj{"schema": ref(d.Req)}}}
		}
		item[strings.ToLower(d.Method)] = op
	}
	scimPaths(paths, comps)
	doc := obj{
		"openapi": "3.1.0",
		"info": obj{"title": "quisora management API", "version": "1",
			"description": "Everything an administrator can do. The path prefix /api never changes; select the API version with the Api-Version header (currently 1). Without the header the oldest supported version is served.\n\n" +
				"With a browser session, managers and above must have signed in with a second factor; otherwise every call answers 403 with field \"mfa\".\n\n" +
				"SCIM 2.0 (RFC 7643, RFC 7644) is described too, under the SCIM tag: a provisioning client's base URL is /scim/v2/{org}. It answers application/scim+json and takes a personal API token with the scim scope, or an OAuth access token of a client with SCIM provisioning turned on (client credentials, scim scope).\n\n" +
				"Not described here: the OAuth 2 / OpenID Connect endpoints (see /.well-known/openid-configuration), the account page's own API under /api-internal/account (the signed-in user, session only) and the live-update stream at /api/events (server-sent events: a browser session, or a token with the admin scope)."},
		"paths": paths,
		"components": obj{
			"schemas": comps,
			"parameters": obj{"ApiVersion": obj{"name": "Api-Version", "in": "header", "required": false,
				"schema": obj{"type": "string", "enum": []string{"1"}}, "description": "API version; responses echo it"}},
			"securitySchemes": obj{
				"session": obj{"type": "apiKey", "in": "cookie", "name": "__Host-quisora_session",
					"description": "Browser session. Unsafe methods must also send the X-CSRF-Token header (from the page's csrf-token meta tag)."},
				"bearer": obj{"type": "http", "scheme": "bearer", "bearerFormat": "qsr_<id>_<secret>",
					"description": "Personal API token with the admin scope (the backup download: the backup scope; SCIM: the scim scope). The owning user's role still limits every call."},
				"scimClient": obj{"type": "oauth2", "description": "A confidential client with SCIM provisioning turned on; it acts as an administrator of its own organization (never granting administrator roles).",
					"flows": obj{"clientCredentials": obj{"tokenUrl": "/oauth/token", "scopes": obj{"scim": "SCIM provisioning"}}}},
			},
		},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return b
}

func errResp(desc string) obj {
	return obj{"description": desc, "content": obj{"application/json": obj{"schema": ref("Error")}}}
}

func http_status(n int) string { return strconv.Itoa(n) }

func opID(d opDoc) string {
	r := strings.NewReplacer("/api/", "", "/", "_", "{", "", "}", "")
	return strings.ToLower(d.Method) + "_" + r.Replace(d.Path)
}

func serveOpenAPI(w http.ResponseWriter, r *http.Request) {
	specOnce.Do(func() { specJSON = buildSpec() })
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(specJSON)
}

// scimPaths adds the SCIM 2.0 operations (scim.Routes) to the document: their bodies are SCIM resources
// (application/scim+json), described loosely here; the server's own /Schemas endpoint has every attribute.
func scimPaths(paths obj, comps obj) {
	const scimJSON = "application/scim+json"
	res := func(urn, desc string, props obj) obj {
		o := schema(nil, props)
		o["description"] = desc + " Every attribute: the server's Schemas endpoint, " + urn + "."
		o["additionalProperties"] = true
		return o
	}
	comps["ScimUser"] = res("urn:ietf:params:scim:schemas:core:2.0:User", "A SCIM User (RFC 7643 §4.1) with Quisora's extension.",
		obj{"schemas": strArr(), "id": prop("string"), "externalId": prop("string"), "userName": prop("string"),
			"name":        obj{"type": "object", "properties": obj{"givenName": prop("string"), "familyName": prop("string")}},
			"displayName": prop("string"), "active": prop("boolean"),
			"emails": obj{"type": "array", "items": obj{"type": "object", "properties": obj{"value": prop("string"), "primary": prop("boolean"), "type": prop("string")}}},
			"groups": obj{"type": "array", "items": obj{"type": "object"}}, "meta": obj{"type": "object"}})
	comps["ScimGroup"] = res("urn:ietf:params:scim:schemas:core:2.0:Group", "A SCIM Group (RFC 7643 §4.2).",
		obj{"schemas": strArr(), "id": prop("string"), "externalId": prop("string"), "displayName": prop("string"),
			"members": obj{"type": "array", "items": obj{"type": "object", "properties": obj{"value": prop("string"), "display": prop("string")}}},
			"meta":    obj{"type": "object"}})
	comps["ScimOrganization"] = res("urn:paularlott:quisora:scim:schemas:2.0:Organization", "A Quisora organization as a SCIM resource (super admins).",
		obj{"schemas": strArr(), "id": prop("string"), "name": prop("string"), "displayName": prop("string"), "meta": obj{"type": "object"}})
	comps["ScimDiscovery"] = obj{"type": "object", "additionalProperties": true,
		"description": "ServiceProviderConfig, or a ListResponse of ResourceTypes or Schemas (RFC 7644 §4)."}
	comps["ScimListResponse"] = schema([]string{"schemas", "totalResults", "Resources"}, obj{"schemas": strArr(),
		"totalResults": prop("integer"), "startIndex": prop("integer"), "itemsPerPage": prop("integer"),
		"Resources": obj{"type": "array", "items": obj{"type": "object"}}})
	comps["ScimPatchOp"] = schema([]string{"schemas", "Operations"}, obj{"schemas": strArr(),
		"Operations": obj{"type": "array", "items": schema([]string{"op"}, obj{
			"op": obj{"type": "string", "enum": []string{"add", "remove", "replace"}}, "path": prop("string"), "value": obj{}})}})
	comps["ScimError"] = schema([]string{"schemas", "status"}, obj{"schemas": strArr(), "status": prop("string"),
		"scimType": prop("string"), "detail": prop("string")})
	scimErr := func(desc string) obj {
		return obj{"description": desc, "content": obj{scimJSON: obj{"schema": ref("ScimError")}}}
	}
	for _, rt := range scim.Routes {
		item, _ := paths[rt.Path].(obj)
		if item == nil {
			item = obj{}
			paths[rt.Path] = item
		}
		var params []any
		for _, seg := range strings.Split(rt.Path, "/") {
			if strings.HasPrefix(seg, "{") {
				n := strings.Trim(seg, "{}")
				desc := "resource id"
				if n == "org" {
					desc = "organization URL name"
				}
				params = append(params, obj{"name": n, "in": "path", "required": true, "description": desc, "schema": prop("string")})
			}
		}
		schemaName := "Scim" + rt.Resource
		list := rt.Method == "GET" && !strings.HasSuffix(rt.Path, "{id}") && !rt.Public
		if list {
			for _, q := range []struct{ n, t, d string }{{"filter", "string", `SCIM filter, for example userName eq "alan"`},
				{"sortBy", "string", "attribute to sort by"}, {"sortOrder", "string", "ascending or descending"},
				{"startIndex", "integer", "1-based index of the first result"}, {"count", "integer", "page size"},
				{"attributes", "string", "attributes to return, comma separated"}, {"excludedAttributes", "string", "attributes to leave out"}} {
				params = append(params, obj{"name": q.n, "in": "query", "description": q.d, "schema": prop(q.t)})
			}
		}
		respSchema := ref(schemaName)
		switch {
		case rt.Public:
			respSchema = ref("ScimDiscovery")
		case list:
			respSchema = ref("ScimListResponse")
		}
		status, success := "200", obj{"description": "Success", "content": obj{scimJSON: obj{"schema": respSchema}}}
		switch rt.Method {
		case "POST":
			status = "201"
		case "DELETE":
			status, success = "204", obj{"description": "Deleted"}
		}
		op := obj{"tags": []string{"SCIM"}, "summary": rt.Summary,
			"operationId": strings.ToLower(rt.Method) + "_" + strings.NewReplacer("/scim/v2/", "scim_", "/", "_", "{", "", "}", "").Replace(rt.Path),
			"parameters":  params, "responses": obj{status: success}}
		if rt.Public {
			op["security"] = []obj{}
		} else {
			op["security"] = []obj{{"bearer": []string{"scim"}}, {"scimClient": []string{"scim"}}}
			r := op["responses"].(obj)
			r["400"], r["401"], r["403"], r["404"], r["409"] = scimErr("Invalid request (scimType says which)"),
				scimErr("No token, or an invalid one"), scimErr("Not permitted, or the token lacks the scim scope"),
				scimErr("No such organization or resource"), scimErr("Conflict (uniqueness, or a stale ETag)")
		}
		switch rt.Method {
		case "POST", "PUT":
			op["requestBody"] = obj{"required": true, "content": obj{scimJSON: obj{"schema": ref(schemaName)}}}
		case "PATCH":
			op["requestBody"] = obj{"required": true, "content": obj{scimJSON: obj{"schema": ref("ScimPatchOp")}}}
		}
		item[strings.ToLower(rt.Method)] = op
	}
}
