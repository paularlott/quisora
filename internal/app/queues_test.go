package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// The daily sweep gives up, while the node runs, the queued items no configured key opens that are older than
// lostItemAge; it leaves younger ones (their key may be put back) and every item a configured key opens, and records
// in the audit log only a sweep that removed something.
func TestPurgeLostQueueItems(t *testing.T) {
	a, _, _ := startAppWith(t, "badgerdb", nil)
	ctx := context.Background()
	c := a.Cfg
	foreign, _ := secure.NewKeyring(secure.RandomBytes(32))
	named := func(at time.Time) string { return fmt.Sprintf("%020d-ab", at.UnixNano()) }
	put := func(dir string, at time.Time, s *secure.Sealer) string {
		d := c.DataPath(dir)
		_ = os.MkdirAll(d, 0o700)
		p := filepath.Join(d, named(at)+".item")
		if err := os.WriteFile(p, []byte(s.SealFor("", []byte("x"))), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sweeps := func() int {
		evs, _, _ := a.Svc.Audits.List(ctx, store.ListQuery{})
		n := 0
		for _, e := range evs {
			if e.Action == "queue.purge_lost" {
				n++
			}
		}
		return n
	}
	old := time.Now().Add(-lostItemAge - time.Hour)
	// No SMTP server here: no worker on the mail queue, so an item the active key opens stays there untouched.
	oldMail := put(config.DirMailQueue, old, foreign)
	keptMail := put(config.DirMailQueue, old.Add(time.Second), a.Svc.Sealer)
	oldLogout := put(config.DirLogoutQueue, old, foreign)
	youngLogout := put(config.DirLogoutQueue, time.Now().Add(-time.Hour), foreign)
	before := time.Now().Add(-lostItemAge)
	if m, l, err := a.purgeLostQueueItems(ctx, before); err != nil || m != 1 || l != 1 {
		t.Fatalf("sweep: %d mail, %d logout: %v", m, l, err)
	}
	for _, p := range []string{oldMail, oldLogout} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s not given up", filepath.Base(p))
		}
	}
	for _, p := range []string{keptMail, youngLogout} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s given up", filepath.Base(p))
		}
	}
	if q := a.logoutQueue.Load(); q == nil || q.Queued() != 1 {
		t.Fatal("the logout queue does not count what is left")
	}
	evs, _, _ := a.Svc.Audits.List(ctx, store.ListQuery{})
	found := false
	for _, e := range evs {
		found = found || e.Action == "queue.purge_lost" && e.Detail["emails"] == "1" && e.Detail["logouts"] == "1" &&
			e.Detail["queued_before"] != ""
	}
	if !found {
		t.Fatalf("not audited: %+v", evs)
	}
	if _, _, err := a.purgeLostQueueItems(ctx, before); err != nil || sweeps() != 1 {
		t.Fatalf("a sweep that removed nothing is audited: %v", err)
	}
	// The young lost item does not hold the rotation back: it is a warning only.
	st, err := a.Svc.RotationStatus(ctx)
	if err != nil || st.QueueLost != 1 || st.QueueStale != 0 || !strings.Contains(st.Detail, "given up once") {
		t.Fatalf("status: %+v %v", st, err)
	}
}
