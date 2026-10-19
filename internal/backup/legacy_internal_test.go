package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// legacyEncrypt seals a backup stream as earlier builds did ("QSRBKEN1": the key derived from the master key).
func legacyEncrypt(t *testing.T, plain []byte, s *secure.Sealer) []byte {
	t.Helper()
	aead, err := encKey(s)
	if err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, prefixLen)
	_, _ = rand.Read(prefix)
	out := append([]byte(encMagic), prefix...)
	for i := 0; ; i++ {
		n := min(chunkSize, len(plain))
		last := n == len(plain) && n < chunkSize
		ct := aead.Seal(nil, chunkNonce(prefix, uint32(i), last), plain[:n], nil)
		out = binary.BigEndian.AppendUint32(out, uint32(len(ct)))
		out = append(out, ct...)
		plain = plain[n:]
		if last {
			return out
		}
	}
}

// A backup encrypted by an earlier build with the master key still verifies and restores, needing no password, with
// that key in the keyring (active or previous).
func TestLegacyEncryptedBackupRestores(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	k1, k2 := secure.RandomBytes(32), secure.RandomBytes(32)
	old, _ := secure.NewSealer(k1)
	src := memstore.New()
	if _, _, err := service.New(cfg, src, old).Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if _, err := Write(ctx, src, old, &plain); err != nil {
		t.Fatal(err)
	}
	data := legacyEncrypt(t, plain.Bytes(), old)
	if PasswordProtected(data) {
		t.Fatal("a master-key backup reported as password protected")
	}
	ring, _ := secure.NewKeyring(k2, k1)
	if st, err := Restore(ctx, memstore.New(), ring, bytes.NewReader(data), false, ""); err != nil || st.Total() == 0 {
		t.Fatalf("restore with the ring: %v", err)
	}
}
