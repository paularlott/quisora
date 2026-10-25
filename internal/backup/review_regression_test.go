package backup_test

// Regression tests from the external code reviews, one per finding: each states the failure it guards against.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

func TestDeepVerifyRejectsDamagedGzipFooter(t *testing.T) {
	f := setup(t, 1)
	var buf bytes.Buffer
	if _, err := backup.Write(f.ctx, f.src, f.sealer, &buf); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	for _, cut := range []int{1, 8} {
		t.Run(string(rune('0'+cut)), func(t *testing.T) {
			if _, err := backup.Verify(bytes.NewReader(data[:len(data)-cut]), f.sealer, ""); err == nil {
				t.Fatalf("Verify accepted backup missing %d gzip footer bytes", cut)
			}
		})
	}
}

// The unauthenticated trailer must not let a damaged backup conceal required old keys.
func TestDeepBackupTrailerKeyRequirementsAuthenticated(t *testing.T) {
	f := setup(t, 1)
	u := f.user
	k1 := secure.RandomBytes(32)
	old, _ := secure.NewSealer(k1)
	u.TOTPSecret = old.SealFor(service.TOTPBinding(u.ID), []byte("old-key-secret"))
	if err := f.svc.Users.Update(f.ctx, u); err != nil {
		t.Fatal(err)
	}
	// The backup itself is MACed by the new key, while records still need the old one.
	k2 := secure.RandomBytes(32)
	ring, _ := secure.NewKeyring(k2, k1)
	only2, _ := secure.NewSealer(k2)
	var buf bytes.Buffer
	if _, err := backup.Write(f.ctx, f.src, ring, &buf); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Verify(bytes.NewReader(buf.Bytes()), only2, ""); !errors.Is(err, backup.ErrKeyMissing) {
		t.Fatalf("setup should require missing old key: %v", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	zr.Close()
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	var trailer map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &trailer); err != nil {
		t.Fatal(err)
	}
	delete(trailer, "sealed")
	lines[len(lines)-1], _ = json.Marshal(trailer)
	var altered bytes.Buffer
	zw := gzip.NewWriter(&altered)
	zw.Write(append(bytes.Join(lines, []byte("\n")), '\n'))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Verify(bytes.NewReader(altered.Bytes()), only2, ""); err == nil {
		t.Fatal("altering only the un-MACed trailer bypassed required-key verification")
	}
}

func TestDeepVerifyRejectsEncryptedTrailingData(t *testing.T) {
	f := setup(t, 1)
	var buf bytes.Buffer
	const password = "deep-review-password"
	if _, err := backup.WriteWith(f.ctx, f.src, f.sealer, &buf, backup.Options{Password: password}); err != nil {
		t.Fatal(err)
	}
	data := append(bytes.Clone(buf.Bytes()), []byte("unexpected bytes after final encrypted chunk")...)
	if _, err := backup.Verify(bytes.NewReader(data), f.sealer, password); err == nil {
		t.Fatal("Verify accepted data after the authenticated final encrypted chunk")
	}
}
