package oidc

import (
	"encoding/json"
	"errors"
	"slices"
)

// The claims request parameter (OpenID Connect Core §5.5) and acr_values (§3.1.2.1).
//
// A client may ask for individual claims, for the ID token or for userinfo, instead of (or as well as) whole
// scopes. Quisora answers for the claims it has, each only when the client may use the scope that holds it (a client
// limited to "openid email" cannot read the name through the claims parameter) and the user has a value; the
// consent screen shows those scopes. "essential" changes nothing for these: a claim the user has no value for is
// left out either way.
//
// acr: Quisora's two values are urn:quisora:acr:basic and urn:quisora:acr:mfa (see tokens.go). The values a request
// names (an acr claim request for the ID token first, then acr_values) are in order of preference, and the first one
// Quisora knows decides: urn:quisora:acr:mfa makes a second factor a condition of this sign-in, as if the tenant
// required one. Unknown values are ignored (acr_values is voluntary), except that an acr claim requested as essential
// whose values Quisora knows none of fails the request (unmet_authentication_requirements) rather than signing the
// user in at a level the client said it cannot accept. The ID token always states how the user actually signed in.

// claimScopes maps each claim that can be requested individually to the scope that holds it.
var claimScopes = map[string]string{
	"name": "profile", "given_name": "profile", "family_name": "profile", "preferred_username": "profile",
	"locale": "profile", "zoneinfo": "profile", "updated_at": "profile",
	"email": "email", "email_verified": "email",
	"phone_number": "phone", "phone_number_verified": "phone",
	"groups":     "groups",
	"enterprise": "enterprise",
}

// maxClaimsParam bounds the claims parameter (it rides in the authorization URL).
const maxClaimsParam = 4096

type claimRequest struct {
	Essential bool              `json:"essential"`
	Value     json.RawMessage   `json:"value"`
	Values    []json.RawMessage `json:"values"`
}

// claimsParam is the parsed claims parameter: the claim names granted for each target, and the acr values asked for.
type claimsParam struct {
	UserInfo []string
	IDToken  []string
	ACR      []string
	// ACREssential: the acr claim was requested as essential.
	ACREssential bool
}

var errClaimsParam = errors.New("claims must be a JSON object with userinfo and/or id_token members")

// parseClaimsParam reads the claims parameter, keeping the claims the client's scopes allow.
func parseClaimsParam(raw string, clientScopes []string) (claimsParam, error) {
	var out claimsParam
	if raw == "" {
		return out, nil
	}
	if len(raw) > maxClaimsParam {
		return out, errors.New("claims is too long")
	}
	var req struct {
		UserInfo map[string]*claimRequest `json:"userinfo"`
		IDToken  map[string]*claimRequest `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return out, errClaimsParam
	}
	keep := func(m map[string]*claimRequest) []string {
		var names []string
		for name := range m {
			if s, ok := claimScopes[name]; ok && slices.Contains(clientScopes, s) {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		return names
	}
	out.UserInfo, out.IDToken = keep(req.UserInfo), keep(req.IDToken)
	if a := req.IDToken["acr"]; a != nil {
		out.ACREssential = a.Essential
		var v string
		if json.Unmarshal(a.Value, &v) == nil && v != "" {
			out.ACR = append(out.ACR, v)
		}
		for _, raw := range a.Values {
			if json.Unmarshal(raw, &v) == nil && v != "" {
				out.ACR = append(out.ACR, v)
			}
		}
	}
	return out, nil
}

// demandsMFA reports whether acr values, in order of preference, ask for a second factor: the first one Quisora
// knows is urn:quisora:acr:mfa (unknown values are skipped).
func demandsMFA(acr []string) bool {
	for _, v := range acr {
		switch v {
		case acrMFA:
			return true
		case acrBasic:
			return false
		}
	}
	return false
}

// knowsACR reports whether any of the acr values is one Quisora issues.
func knowsACR(acr []string) bool {
	return slices.Contains(acr, acrMFA) || slices.Contains(acr, acrBasic)
}

// consentScopes are the scopes a request asks the user for: its scopes and those holding its individually
// requested claims.
func consentScopes(scopes []string, claims ...[]string) []string {
	out := slices.Clone(scopes)
	for _, names := range claims {
		for _, n := range names {
			if s := claimScopes[n]; s != "" && !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}
