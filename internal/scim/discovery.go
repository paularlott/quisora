package scim

import (
	"net/http"
	"strings"
)

// Discovery documents (RFC 7644 §4). They describe the shape of the API only, so they are served without
// authentication.

type resourceType struct {
	Schemas          []string       `json:"schemas"`
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Endpoint         string         `json:"endpoint"`
	Description      string         `json:"description"`
	Schema           string         `json:"schema"`
	SchemaExtensions []schemaExt    `json:"schemaExtensions,omitempty"`
	Meta             map[string]any `json:"meta"`
}

type schemaExt struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

func (rq *request) resourceTypes(orgScoped bool) []resourceType {
	mk := func(id, endpoint, desc, schema string, exts ...schemaExt) resourceType {
		return resourceType{Schemas: []string{schemaResourceType}, ID: id, Name: id, Endpoint: endpoint, Description: desc,
			Schema: schema, SchemaExtensions: exts,
			Meta: map[string]any{"resourceType": "ResourceType", "location": rq.base + "/ResourceTypes/" + id}}
	}
	out := []resourceType{
		mk("User", "/Users", "User account", schemaUser, schemaExt{schemaEnterprise, false}, schemaExt{schemaIdpUser, false}),
		mk("Group", "/Groups", "Group of users", schemaGroup, schemaExt{schemaIdpGroup, false}),
	}
	if !orgScoped {
		out = append(out, mk("Organization", "/Organizations", "Organization (super admins only)", schemaOrg))
	}
	return out
}

type schemaDoc struct {
	Schemas     []string       `json:"schemas"`
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Attributes  []attrDef      `json:"attributes"`
	Meta        map[string]any `json:"meta"`
}

func (rq *request) schemaDocs(orgScoped bool) []schemaDoc {
	mk := func(id, name, desc string, attrs []attrDef) schemaDoc {
		return schemaDoc{Schemas: []string{schemaSchema}, ID: id, Name: name, Description: desc, Attributes: attrs,
			Meta: map[string]any{"resourceType": "Schema", "location": rq.base + "/Schemas/" + id}}
	}
	out := []schemaDoc{
		mk(schemaUser, "User", "User account", userAttrs),
		mk(schemaEnterprise, "EnterpriseUser", "Enterprise user (work details)", enterpriseUserAttrs),
		mk(schemaIdpUser, "IdpUser", "quisora user attributes", quisoraUserAttrs),
		mk(schemaGroup, "Group", "Group of users", groupAttrs),
		mk(schemaIdpGroup, "IdpGroup", "quisora group attributes", quisoraGroupAttrs),
	}
	if !orgScoped {
		out = append(out, mk(schemaOrg, "Organization", "Organization (super admins only)", orgAttrs))
	}
	return out
}

func (rq *request) serviceProviderConfig() map[string]any {
	return map[string]any{
		"schemas":          []string{schemaSPC},
		"documentationUri": rq.base + "/ServiceProviderConfig",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": maxCount},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": true},
		"etag":             map[string]any{"supported": true},
		"authenticationSchemes": []any{map[string]any{
			"type": "oauthbearertoken", "name": "OAuth Bearer Token",
			"description": "Personal API token with the scim scope, or an OAuth client_credentials access token of a client with SCIM enabled",
			"specUri":     "https://www.rfc-editor.org/info/rfc6750", "primary": true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": rq.base + "/ServiceProviderConfig"},
	}
}

// discovery serves ServiceProviderConfig, ResourceTypes and Schemas. root is true for /scim/v2/<name>.
func (rq *request) discovery(segs []string, root bool) {
	if !rq.allow(http.MethodGet) {
		return
	}
	scoped := !root
	switch segs[0] {
	case "ServiceProviderConfig":
		if len(segs) != 1 {
			writeError(rq.w, notFound("Resource"))
			return
		}
		write(rq.w, http.StatusOK, rq.serviceProviderConfig())
	case "ResourceTypes":
		list := rq.resourceTypes(scoped)
		if len(segs) == 2 {
			for _, t := range list {
				if strings.EqualFold(t.ID, segs[1]) {
					write(rq.w, http.StatusOK, t)
					return
				}
			}
			writeError(rq.w, notFound("Resource type"))
			return
		}
		rq.discoveryList(list)
	case "Schemas":
		list := rq.schemaDocs(scoped)
		if len(segs) == 2 {
			for _, d := range list {
				if strings.EqualFold(d.ID, segs[1]) {
					write(rq.w, http.StatusOK, d)
					return
				}
			}
			writeError(rq.w, notFound("Schema"))
			return
		}
		rq.discoveryList(list)
	}
}

func (rq *request) discoveryList(list any) {
	n := 0
	switch l := list.(type) {
	case []resourceType:
		n = len(l)
	case []schemaDoc:
		n = len(l)
	}
	write(rq.w, http.StatusOK, map[string]any{"schemas": []string{schemaListResponse}, "totalResults": n,
		"startIndex": 1, "itemsPerPage": n, "Resources": list})
}
