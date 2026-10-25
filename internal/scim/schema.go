package scim

import (
	"strings"
)

// Schema URNs. The quisora ones live under a namespace of this project.
const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	// schemaEnterprise is the enterprise extension of RFC 7643 §4.3 (work details).
	schemaEnterprise   = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	schemaIdpUser      = "urn:paularlott:quisora:scim:schemas:2.0:User"
	schemaIdpGroup     = "urn:paularlott:quisora:scim:schemas:2.0:Group"
	schemaOrg          = "urn:paularlott:quisora:scim:schemas:2.0:Organization"
	schemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaPatchOp      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaError        = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaSPC          = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	schemaResourceType = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	schemaSchema       = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

func init() {
	knownURNs = []string{schemaUser, schemaGroup, schemaEnterprise, schemaIdpUser, schemaIdpGroup, schemaOrg}
}

// attrDef is a SCIM attribute definition as served by /Schemas.
type attrDef struct {
	Name            string    `json:"name"`
	Type            string    `json:"type"`
	MultiValued     bool      `json:"multiValued"`
	Description     string    `json:"description,omitempty"`
	Required        bool      `json:"required"`
	CaseExact       bool      `json:"caseExact"`
	CanonicalValues []string  `json:"canonicalValues,omitempty"`
	Mutability      string    `json:"mutability"`
	Returned        string    `json:"returned"`
	Uniqueness      string    `json:"uniqueness"`
	SubAttributes   []attrDef `json:"subAttributes,omitempty"`
	ReferenceTypes  []string  `json:"referenceTypes,omitempty"`
}

func attr(name, typ, desc string, opts ...func(*attrDef)) attrDef {
	a := attrDef{Name: name, Type: typ, Description: desc, Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
	for _, o := range opts {
		o(&a)
	}
	return a
}

func required(a *attrDef)  { a.Required = true }
func exact(a *attrDef)     { a.CaseExact = true }
func multi(a *attrDef)     { a.MultiValued = true }
func readOnly(a *attrDef)  { a.Mutability = "readOnly" }
func immutable(a *attrDef) { a.Mutability = "immutable" }
func never(a *attrDef)     { a.Returned = "never" }
func server(a *attrDef)    { a.Uniqueness = "server" }
func always(a *attrDef)    { a.Returned = "always" }
func subs(s ...attrDef) func(*attrDef) {
	return func(a *attrDef) { a.SubAttributes = s }
}
func canon(v ...string) func(*attrDef) { return func(a *attrDef) { a.CanonicalValues = v } }
func refs(v ...string) func(*attrDef)  { return func(a *attrDef) { a.ReferenceTypes = v } }

// commonAttrs are defined on every resource but not listed in /Schemas.
var commonAttrs = []attrDef{
	attr("id", "string", "Unique identifier", readOnly, exact, always, server),
	attr("externalId", "string", "Identifier assigned by the provisioning client", exact),
	attr("meta", "complex", "Resource metadata", readOnly, subs(
		attr("resourceType", "string", "", readOnly, exact),
		attr("created", "dateTime", "", readOnly),
		attr("lastModified", "dateTime", "", readOnly),
		attr("location", "reference", "", readOnly, exact),
		attr("version", "string", "", readOnly, exact),
	)),
}

var userAttrs = []attrDef{
	attr("userName", "string", "Username, unique within the organization (the preferred_username claim); sign-in is by email address", required, server),
	attr("name", "complex", "The components of the user's name", subs(
		attr("formatted", "string", "Full name (given and family name)", readOnly),
		attr("familyName", "string", "Family name"),
		attr("givenName", "string", "Given name"),
	)),
	attr("displayName", "string", "Name shown in user interfaces: the given and family name. What a client sends is "+
		"ignored, except as the given name when name.givenName is absent", readOnly),
	attr("title", "string", "Job title"),
	attr("userType", "string", "Kind of user, for example employee, contractor, guest or service"),
	attr("preferredLanguage", "string", "Preferred language (Accept-Language form); the first one is kept as the locale when no locale is sent"),
	attr("locale", "string", "Language and region as a BCP 47 tag, for example en-GB (en_GB is accepted)"),
	attr("timezone", "string", "IANA time zone, for example Europe/London"),
	attr("active", "boolean", "Whether the user can sign in"),
	attr("password", "string", "Not supported: users set their own password through an invitation", readOnly, never),
	attr("emails", "complex", "Email address (required; userName is used when it is an email address and none is sent); the primary (else first) one is the user's email and sign-in name", multi, subs(
		attr("value", "string", "Email address"),
		attr("type", "string", "Label", canon("work", "home", "other")),
		attr("primary", "boolean", "Primary email"),
	)),
	attr("phoneNumbers", "complex", "Contact phone number; the primary (else first) one is kept, in international form (+ and the country code; one that is not is ignored)", multi, subs(
		attr("value", "string", "Phone number"),
		attr("type", "string", "Label", canon("work", "home", "mobile", "fax", "pager", "other")),
		attr("primary", "boolean", "Primary phone number"),
	)),
	attr("groups", "complex", "Groups the user belongs to", multi, readOnly, subs(
		attr("value", "string", "Group id", readOnly, exact),
		attr("$ref", "reference", "Group location", readOnly, exact, refs("Group")),
		attr("display", "string", "Group name", readOnly),
		attr("type", "string", "direct", readOnly),
	)),
}

var quisoraUserAttrs = []attrDef{
	attr("role", "string", "Role in the organization", canon("user", "manager", "admin", "super_admin")),
	attr("tags", "string", tagsDesc, multi, exact),
	attr("validUntil", "dateTime", "End of the account: from then it cannot sign in or use tokens, and it is disabled with its sessions ended"),
}

var enterpriseUserAttrs = []attrDef{
	attr("employeeNumber", "string", "Employee number"),
	attr("costCenter", "string", "Cost center"),
	attr("organization", "string", "Organization"),
	attr("division", "string", "Division"),
	attr("department", "string", "Department"),
	attr("manager", "complex", "The user's manager: another user of the organization", subs(
		attr("value", "string", "The manager's id", exact),
		attr("$ref", "reference", "The manager's location", readOnly, exact, refs("User")),
		attr("displayName", "string", "The manager's name", readOnly),
	)),
}

const tagsDesc = "Tags: identifiers of letters, digits and . _ : / - (1-64 characters, starting and ending with a letter or digit; a colon separates a namespace, e.g. dept:finance), at most 50, stored sorted. Applications receive them in the tags claim, merged with the tags of the user's groups"

var quisoraGroupAttrs = []attrDef{
	attr("tags", "string", "Tags: identifiers as for users; every member receives them in the tags claim", multi, exact),
}

var groupAttrs = []attrDef{
	attr("displayName", "string", "Group name, unique within the organization", required, server),
	attr("members", "complex", "Members of the group (users only)", multi, subs(
		attr("value", "string", "User id", exact, immutable),
		attr("$ref", "reference", "User location", readOnly, exact, refs("User")),
		attr("display", "string", "User name", readOnly),
		attr("type", "string", "User", readOnly, canon("User")),
	)),
}

var orgAttrs = []attrDef{
	attr("name", "string", "URL name of the organization", required, server),
	attr("displayName", "string", "Name shown in user interfaces"),
	attr("primary", "boolean", "Whether this is the primary organization", readOnly),
	attr("settings", "complex", "Sign-in and session policy", subs(
		attr("passwordLogin", "boolean", "Allow password sign-in"),
		attr("passwordReset", "boolean", "Allow resetting a forgotten password by email"),
		attr("passkeyLogin", "boolean", "Allow passkey sign-in"),
		attr("requireMfa", "boolean", "Require a second factor"),
		attr("sessionTtl", "integer", "Session lifetime in seconds (0 = server default)"),
		attr("sessionIdle", "integer", "Idle timeout in seconds (0 = server default)"),
	)),
}

// attrInfo is what the evaluator needs to know about an attribute.
type attrInfo struct {
	typ       string
	caseExact bool
	multi     bool
}

// schemaSet describes the attributes of one resource type, for case rules and attribute name canonicalization.
type schemaSet struct {
	core  string
	exts  []string
	infos map[string]attrInfo
	canon map[string]string
}

func newSchemaSet(core string, coreAttrs []attrDef, exts map[string][]attrDef, extOrder []string) *schemaSet {
	s := &schemaSet{core: core, exts: extOrder, infos: map[string]attrInfo{}, canon: map[string]string{}}
	add := func(prefix string, defs []attrDef) {
		for _, a := range defs {
			k := prefix + strings.ToLower(a.Name)
			s.infos[k] = attrInfo{typ: a.Type, caseExact: a.CaseExact, multi: a.MultiValued}
			s.canon[k] = a.Name
			for _, sa := range a.SubAttributes {
				sk := k + "." + strings.ToLower(sa.Name)
				s.infos[sk] = attrInfo{typ: sa.Type, caseExact: sa.CaseExact}
				s.canon[sk] = sa.Name
			}
		}
	}
	add("", commonAttrs)
	add("", coreAttrs)
	for urn, defs := range exts {
		add(strings.ToLower(urn)+":", defs)
	}
	return s
}

func (s *schemaSet) key(urn, name, sub string) string {
	k := strings.ToLower(name)
	if urn != "" && !strings.EqualFold(urn, s.core) {
		k = strings.ToLower(urn) + ":" + k
	}
	if sub != "" {
		k += "." + strings.ToLower(sub)
	}
	return k
}

func (s *schemaSet) info(p attrPath) attrInfo {
	k := s.key(p.URN, p.Name, p.Sub)
	if i, ok := s.infos[k]; ok {
		return i
	}
	if p.Sub != "" { // unknown sub-attribute of a complex attribute: compare like a plain string
		return attrInfo{}
	}
	return attrInfo{}
}

// canonName returns the declared spelling of an attribute name (or sub-attribute), else name unchanged.
func (s *schemaSet) canonName(urn, name, sub string) string {
	k := s.key(urn, name, "")
	if sub != "" {
		k2 := s.key(urn, name, sub)
		if c, ok := s.canon[k2]; ok {
			return c
		}
		return sub
	}
	if c, ok := s.canon[k]; ok {
		return c
	}
	return name
}

// extURN returns the canonical spelling of an extension URN of this resource type.
func (s *schemaSet) extURN(urn string) (string, bool) {
	for _, e := range s.exts {
		if strings.EqualFold(e, urn) {
			return e, true
		}
	}
	return "", false
}

var (
	userSchemas = newSchemaSet(schemaUser, userAttrs,
		map[string][]attrDef{schemaEnterprise: enterpriseUserAttrs, schemaIdpUser: quisoraUserAttrs},
		[]string{schemaEnterprise, schemaIdpUser})
	groupSchemas = newSchemaSet(schemaGroup, groupAttrs, map[string][]attrDef{schemaIdpGroup: quisoraGroupAttrs}, []string{schemaIdpGroup})
	orgSchemas   = newSchemaSet(schemaOrg, orgAttrs, nil, nil)
)
