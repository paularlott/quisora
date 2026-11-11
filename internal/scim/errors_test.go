package scim

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// A store that cannot answer now, as a read of a cluster that lost quorum, is a 503 the client retries, not a 500:
// reads reach SCIM as the store's own errors, not the service's.
func TestStoreUnavailableIsRetryable(t *testing.T) {
	m := &Module{}
	for _, err := range []error{store.ErrUnavailable, fmt.Errorf("list: %w", store.ErrUnavailable), store.ErrUnconfirmed,
		service.ErrUnavailable, service.ErrOutcomeUnknown} {
		if got := m.fromService(err); got.Status != 503 {
			t.Errorf("%v: %d, want 503", err, got.Status)
		}
	}
}

// A picture this server has no turn for now is a 503 the client retries in a few seconds.
func TestPictureBusyIsRetryable(t *testing.T) {
	got := (&Module{}).fromService(service.ErrPictureBusy)
	if got.Status != 503 || got.Detail != "This server is busy: it is making other pictures; try again in a few seconds" {
		t.Fatalf("%d %q", got.Status, got.Detail)
	}
	rec := httptest.NewRecorder()
	writeError(rec, got)
	if rec.Code != 503 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
}
