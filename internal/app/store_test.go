package app

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
)

func TestOpenStoreErrors(t *testing.T) {
	ctx := context.Background()
	c := config.Default()
	c.Server.DataDir = t.TempDir()
	c.Storage.Backend = "nonesuch"
	if _, err := OpenStore(ctx, c); err == nil || !strings.Contains(err.Error(), "unknown storage backend") {
		t.Fatalf("unknown: %v", err)
	}
	c.Storage.Backend = "badgerdb"
	c.Storage.BadgerDB.EncryptionKey = "not base64!"
	if _, err := OpenStore(ctx, c); err == nil || !strings.Contains(err.Error(), "encryption_key") {
		t.Fatalf("badger key: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	for _, b := range []string{"postgres", "mysql", "mariadb"} {
		c.Storage.Backend = b
		c.Storage.Postgres.CAFile, c.Storage.MySQL.CAFile, c.Storage.MariaDB.CAFile = missing, missing, missing
		if _, err := OpenStore(ctx, c); err == nil || !strings.Contains(err.Error(), "ca_file") {
			t.Fatalf("%s CA: %v", b, err)
		}
	}
	// an encrypted badger store opens with a valid key
	c.Storage.Backend = "badgerdb"
	c.Storage.BadgerDB.EncryptionKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	st, err := OpenStore(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
}
