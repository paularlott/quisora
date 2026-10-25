package oidc

import (
	"net/url"
	"testing"
)

// RFC 7523 §3 / RFC 9126 §2: a client assertion may name the endpoint it is presented at as its audience, besides
// the issuer and the token endpoint; an assertion made for another endpoint is not taken at this one.
func TestAssertionAudienceMayBeTheEndpointCalled(t *testing.T) {
	h := setup(t, nil)
	k := newAssertionKeys(t)[0]
	c := h.jwtClient(k, nil)
	introspect := func(aud string) tokResp {
		tok := h.assertion(k, h.assertionClaims(c, func(m map[string]any) { m["aud"] = aud }))
		return h.post("/oauth/introspect", url.Values{"token": {"x"}, "client_assertion_type": {assertionType},
			"client_assertion": {tok}}, "", "")
	}
	if r := introspect(h.env.URL + "/oauth/introspect"); r.status != 200 {
		t.Fatalf("aud = the introspection endpoint: %d %v", r.status, r.m)
	}
	if r := introspect(h.env.URL + "/oauth/revoke"); r.status != 401 {
		t.Fatalf("aud = another endpoint: %d %v", r.status, r.m)
	}
}
