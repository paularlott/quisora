package mail

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
)

// The running mailer gives up the messages no configured master key opens, and only those.
func TestMailerPurgeLost(t *testing.T) {
	m := newMailer(t, nil, TransportFunc(func(context.Context, Message) error { return nil }))
	foreign, _ := secure.NewKeyring(secure.RandomBytes(32))
	p := filepath.Join(m.Cfg.DataPath(config.DirMailQueue), "00000000000000000001-aa.item") // queued long ago
	if err := os.WriteFile(p, []byte(foreign.SealFor("", []byte("x"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := m.PurgeLost(time.Now()); err != nil || n != 1 {
		t.Fatalf("purged %d: %v", n, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("the lost message is still queued")
	}
	if m.Queued() != 0 {
		t.Fatalf("queued %d", m.Queued())
	}
}
