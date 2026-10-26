package app

import (
	"errors"
	"fmt"
	"testing"

	logtest "github.com/paularlott/logger/testing"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// A housekeeping task that fails because the cluster cannot take writes (it is forming, or has no majority) is logged
// once at warn level, then retried quietly until it succeeds (logged once at info); any other failure is an error each
// time.
func TestHousekeepingWaitsQuietlyForAWritableCluster(t *testing.T) {
	log := logtest.New()
	hk := housekeepingLog{log: log}
	unwritable := fmt.Errorf("%w: partition 0 has no owner", store.ErrNotWritable)
	for range 5 {
		if hk.ok("signing key rotation", unwritable) {
			t.Fatal("a failure reported as done")
		}
	}
	hk.ok("user end dates", fmt.Errorf("%w: no quorum", service.ErrUnavailable))
	if n, e := log.CountEntries("warn"), log.CountEntries("error"); n != 2 || e != 0 {
		t.Fatalf("waiting for a writable cluster: %d warnings, %d errors (want one warning per task)", n, e)
	}
	if !hk.ok("signing key rotation", nil) || log.CountEntries("info") != 1 {
		t.Fatal("the task's recovery was not logged once")
	}
	hk.ok("signing key rotation", nil)
	hk.ok("signing key rotation", unwritable)
	if log.CountEntries("warn") != 3 || log.CountEntries("info") != 1 {
		t.Fatalf("a new wait after a success: %s", log.String())
	}
	for range 2 {
		hk.ok("orphan sweep", errors.New("disk full"))
	}
	if log.CountEntries("error") != 2 {
		t.Fatalf("other failures are errors every time: %s", log.String())
	}
}
