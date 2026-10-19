package kvstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// An encrypted store opens again with its key only; its files do not hold the data in the clear.
func TestBadgerEncryption(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, 32)
	s, err := OpenBadger(ctx, dir, BadgerOptions{EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("very-recognisable-plaintext-marker")
	rec := &store.Record{Kind: model.KindClient, ID: "c1", Version: store.Clock.Now(), Origin: "n", Scope: "o", Data: secret}
	if err := s.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	s.Close()

	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil && bytes.Contains(b, secret) {
			t.Fatalf("%s holds the data in the clear", filepath.Base(f))
		}
	}
	if s, err := OpenBadger(ctx, dir, BadgerOptions{}); err == nil {
		s.Close()
		t.Fatal("opened without its key")
	}
	if s, err := OpenBadger(ctx, dir, BadgerOptions{EncryptionKey: bytes.Repeat([]byte{8}, 32)}); err == nil {
		s.Close()
		t.Fatal("opened with another key")
	}
	s, err = OpenBadger(ctx, dir, BadgerOptions{EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Get(ctx, model.KindClient, "c1")
	if err != nil || !bytes.Equal(got.Data, secret) {
		t.Fatalf("read back: %v", err)
	}
}
