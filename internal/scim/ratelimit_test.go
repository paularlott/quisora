package scim_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/web"
)

// Failed bearer authentications count against the address (shared with the management API): past the limit every
// SCIM request from it is refused before its token is looked at, the right one too.
func TestSCIMBearerFailuresLimited(t *testing.T) {
	e := newEnv(t)
	for i := range web.BearerFailuresPerIPMin {
		if r := e.do("GET", "/scim/v2/acme/Users", "qsr_nosuch_secret", nil); r.Status != 401 {
			t.Fatalf("failure %d: %d %s", i+1, r.Status, r.Raw)
		}
	}
	r := e.do("GET", "/scim/v2/acme/Users", e.admA, nil)
	if r.Status != 429 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("valid token after the limit: %d %s", r.Status, r.Raw)
	}
}
