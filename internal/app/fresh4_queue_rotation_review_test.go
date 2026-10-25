package app

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/secure"
)

func TestFreshReviewReloadMustKeepKeyNeededByFailedQueueReseal(t *testing.T) {
	ctx := context.Background()
	b64 := base64.StdEncoding.EncodeToString
	oldKey, newKey := b64(secure.RandomBytes(32)), b64(secure.RandomBytes(32))
	a, _, _ := startAppWith(t, "badgerdb", func(c *config.Config) { c.Server.MasterKey = oldKey })
	m, err := mail.New(a.Cfg, logger.NewNullLogger(), a.Svc.Sealer, mail.TransportFunc(func(context.Context, mail.Message) error { return errors.New("SMTP offline") }))
	if err != nil {
		t.Fatal(err)
	}
	a.mailer = m
	if err := m.Send(ctx, mail.Message{To: "user@example.test", Subject: "invitation", Text: "single-use link"}); err != nil {
		m.Close()
		t.Fatal(err)
	}
	m.Close() // accepted message remains on disk, without a racing delivery worker
	dir := a.Cfg.DataPath(config.DirMailQueue)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var name string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".item") {
			name = e.Name()
		}
	}
	if name == "" {
		t.Fatal("missing accepted queue item")
	}
	path := filepath.Join(dir, name)
	if err := os.Mkdir(filepath.Join(dir, "."+name+".tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	// A full/failing disk can likewise prevent atomic replacement of the old item.
	if err := a.ReloadMasterKeys(ctx, newKey, []string{oldKey}); err != nil {
		t.Logf("safely refused failed reseal: %v", err)
		return
	}
	if _, err := a.Svc.ResealSecrets(ctx, 10000); err != nil {
		t.Fatal(err)
	}
	if err := a.ReloadMasterKeys(ctx, newKey, nil); err != nil {
		return
	} // refusing to drop the needed key is safe
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, openErr := a.Svc.Sealer.OpenFor("mail/queue", string(ciphertext))
	nodes, err := a.Svc.MasterKeyNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if openErr != nil {
		t.Fatalf("reload removed previous key and reported keys=%+v despite failed queue reseal; accepted item open error=%v", nodes, openErr)
	}
}
