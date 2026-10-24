package scim_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// A provisioning client's access token that cannot be checked (the store failed, not the token) is answered 503, as
// a personal API token is: 401 would make the client treat its token as revoked, and the failure would count against
// its address.
func TestAccessTokenStoreFailureIsUnavailable(t *testing.T) {
	e := newEnv(t)
	e.verify = func(r *http.Request, scheme, tok string) (*service.Actor, error) {
		return nil, fmt.Errorf("%w: the client could not be read", service.ErrUnavailable)
	}
	if r := e.do("GET", "/scim/v2/Users", "jwt-for-entra", nil); r.Status != http.StatusServiceUnavailable {
		t.Fatalf("store failure while checking an access token: %d %s", r.Status, r.Raw)
	}
	e.verify = func(r *http.Request, scheme, tok string) (*service.Actor, error) { return nil, service.ErrBadToken }
	if r := e.do("GET", "/scim/v2/Users", "jwt-for-entra", nil); r.Status != http.StatusUnauthorized {
		t.Fatalf("control: a bad token: %d %s", r.Status, r.Raw)
	}
}
