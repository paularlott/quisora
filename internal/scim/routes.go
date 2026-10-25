package scim

// Route is one SCIM operation, for the OpenAPI document (admin/openapi.go). Paths use {org} for the organization's
// URL name and {id} for a resource id; a test checks that the handler serves each of them.
type Route struct {
	Method, Path, Resource, Summary string
	Public                          bool // discovery: no token needed
}

// Routes lists every operation the SCIM server answers. Users and Groups always sit under their organization; a
// provisioning client's base URL is /scim/v2/{org}.
var Routes = []Route{
	{"GET", "/scim/v2/{org}/Users", "User", "List or filter users (filter, sortBy, startIndex, count, attributes)", false},
	{"POST", "/scim/v2/{org}/Users", "User", "Create a user", false},
	{"GET", "/scim/v2/{org}/Users/{id}", "User", "Get a user", false},
	{"PUT", "/scim/v2/{org}/Users/{id}", "User", "Replace a user", false},
	{"PATCH", "/scim/v2/{org}/Users/{id}", "User", "Change a user (PatchOp)", false},
	{"DELETE", "/scim/v2/{org}/Users/{id}", "User", "Delete a user", false},
	{"GET", "/scim/v2/{org}/Groups", "Group", "List or filter groups", false},
	{"POST", "/scim/v2/{org}/Groups", "Group", "Create a group (administrator's token)", false},
	{"GET", "/scim/v2/{org}/Groups/{id}", "Group", "Get a group", false},
	{"PUT", "/scim/v2/{org}/Groups/{id}", "Group", "Replace a group", false},
	{"PATCH", "/scim/v2/{org}/Groups/{id}", "Group", "Change a group, members included (PatchOp; atomic, at most 1,000 members per request)", false},
	{"DELETE", "/scim/v2/{org}/Groups/{id}", "Group", "Delete a group", false},
	{"GET", "/scim/v2/Organizations", "Organization", "List organizations (super admins)", false},
	{"POST", "/scim/v2/Organizations", "Organization", "Create an organization (super admins)", false},
	{"GET", "/scim/v2/Organizations/{id}", "Organization", "Get an organization (super admins)", false},
	{"PUT", "/scim/v2/Organizations/{id}", "Organization", "Replace an organization (super admins)", false},
	{"PATCH", "/scim/v2/Organizations/{id}", "Organization", "Change an organization (super admins)", false},
	{"DELETE", "/scim/v2/Organizations/{id}", "Organization", "Refused: deleting an organization needs the console (re-authentication)", false},
	{"GET", "/scim/v2/{org}/ServiceProviderConfig", "Discovery", "What this server supports (RFC 7644 §4)", true},
	{"GET", "/scim/v2/{org}/ResourceTypes", "Discovery", "The resource types", true},
	{"GET", "/scim/v2/{org}/Schemas", "Discovery", "The schemas, Quisora's extensions included", true},
	{"GET", "/scim/v2/ServiceProviderConfig", "Discovery", "What this server supports, at the root (for Organizations)", true},
	{"GET", "/scim/v2/ResourceTypes", "Discovery", "The resource types, at the root", true},
	{"GET", "/scim/v2/Schemas", "Discovery", "The schemas, at the root", true},
}
