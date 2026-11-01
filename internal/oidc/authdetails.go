package oidc

import (
	"slices"

	"github.com/paularlott/quisora/internal/model"
)

// Rich authorization requests (RFC 9396).
//
// What a token may do is decided by its administrators, not by the request: a user's access entries for the
// application (service.AppAccess.Details) and, for a client_credentials token, the client's own details
// (model.Client.AuthorizationDetails). An access token carries those whose type the client is registered for
// (authorization_details_types) and whose locations, when they name any, include one of the token's audiences: the
// details of an API go only into tokens for it (§9.1: "filtered to the specific audience").
//
// A request may send authorization_details (at the authorization, pushed authorization, device authorization and
// token endpoints) to ask for fewer: Quisora reads the types it names, each of which must be one the client is
// registered for (invalid_authorization_details otherwise, §5), and the token then carries only the granted details of
// those types. The types an authorization request named are kept with the grant; a token request may narrow them,
// never widen. The token response states the details issued (§7) whenever the token carries any or the request
// asked, and introspection reports them as the token holds them (§9.2).

// parseAuthDetailsParam reads a request's authorization_details for client c: the types it names, nil when it sent
// none.
func parseAuthDetailsParam(raw string, c *model.Client) ([]string, *oauthError) {
	if raw == "" {
		return nil, nil
	}
	list, err := model.ParseAuthDetails([]byte(raw))
	if err != nil {
		return nil, oerr("invalid_authorization_details", err.Error())
	}
	if len(list) == 0 {
		return nil, oerr("invalid_authorization_details", "authorization_details must name at least one authorization detail")
	}
	types := make([]string, 0, len(list))
	for _, d := range list {
		t := d["type"].(string)
		if !slices.Contains(c.AuthorizationDetailsTypes, t) {
			return nil, oerr("invalid_authorization_details", "the authorization details type "+t+" is not one this client is registered for")
		}
		if !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	return types, nil
}

// narrowAuthDetails is the types a token request gets: those it asked for, which must be among the grant's (granted
// nil: the authorization request named none, so any of the client's), or the grant's when it asked for none.
func narrowAuthDetails(asked, granted []string) ([]string, *oauthError) {
	if asked == nil {
		return granted, nil
	}
	if granted != nil && !subset(asked, granted) {
		return nil, oerr("invalid_authorization_details", "authorization_details names a type the authorization did not")
	}
	return asked, nil
}

// authDetails is the authorization_details of the access token of is, as a JSON array; nil when it carries none.
func (p *Provider) authDetails(is *issue) []byte {
	c := is.client
	if len(c.AuthorizationDetailsTypes) == 0 {
		return nil
	}
	var all []model.AuthDetail
	switch {
	case is.user != nil && is.app != nil:
		all = is.app.Details
	case is.user == nil:
		// Validated when saved, so details that no longer read are left out rather than failing the request.
		all, _ = model.ExpandAuthDetails(c.AuthorizationDetails, model.AuthDetailVars{Sub: c.ClientID(), Org: c.OrgID, Tenant: c.TenantID})
	}
	aud := is.audience()
	var b []byte
	for _, d := range all {
		if !slices.Contains(c.AuthorizationDetailsTypes, d.Type) || is.adTypes != nil && !slices.Contains(is.adTypes, d.Type) {
			continue
		}
		if len(d.Locations) > 0 && !slices.ContainsFunc(d.Locations, func(l string) bool { return slices.Contains(aud, l) }) {
			continue
		}
		if b == nil {
			b = append(b, '[')
		} else {
			b = append(b, ',')
		}
		b = append(b, d.JSON...)
	}
	if b != nil {
		b = append(b, ']')
	}
	return b
}
