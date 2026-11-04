package oidc

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	logtesting "github.com/paularlott/logger/testing"
	"github.com/paularlott/quisora/internal/metrics"
)

// An authorization request sent back with an error before anyone signed in - here an application asking for a scope
// its settings do not allow - is counted and logged with the application, so its administrator can find out why its
// sign-ins fail.
func TestAuthorizeRefusalIsCountedAndLogged(t *testing.T) {
	t.Parallel()
	log := logtesting.New()
	h := setupLogged(t, nil, nil, log)
	cl, _ := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()
	before := metrics.AuthorizeRefused.Value("invalid_scope")

	u := h.authorize(c, authzQuery(cl, ch, url.Values{"scope": {"openid admin"}}))
	if u.Query().Get("error") != "invalid_scope" {
		t.Fatal(u)
	}
	if metrics.AuthorizeRefused.Value("invalid_scope") <= before {
		t.Error("not counted")
	}
	if n := refusals(log); n != 1 {
		t.Fatalf("%d refusals logged: %v", n, log.GetEntries())
	}
	for _, en := range log.GetEntries() {
		if en.Message == refusedMessage {
			if en.Level != "warn" {
				t.Errorf("logged at %s", en.Level)
			}
			kv := fmt.Sprint(en.KeysAndValues)
			if !strings.Contains(kv, cl.ClientID()) || !strings.Contains(kv, "invalid_scope") {
				t.Errorf("the entry names no client or error: %v", en.KeysAndValues)
			}
		}
	}

	// A request that goes on to sign-in is not logged.
	if u := h.authorize(c, authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
		t.Fatal(u)
	}
	if n := refusals(log); n != 1 {
		t.Errorf("%d refusals logged after a good request", n)
	}
}

const refusedMessage = "oidc: authorization request refused"

func refusals(log *logtesting.MockLogger) int {
	n := 0
	for _, en := range log.GetEntries() {
		if en.Message == refusedMessage {
			n++
		}
	}
	return n
}
