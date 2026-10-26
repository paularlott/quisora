package secure

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

func TestPassword(t *testing.T) {
	h := NewHasher(2)
	ctx := context.Background()
	if _, err := NewHasher(0).Hash(ctx, "", "x"); err != nil { // zero workers means the default
		t.Fatalf("default workers: %v", err)
	}
	enc, err := h.Hash(ctx, "", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, _ := h.Verify(ctx, "", "correct horse", enc); !ok || rehash {
		t.Fatalf("verify: ok %v, rehash %v", ok, rehash)
	}
	if ok, _, _ := h.Verify(ctx, "", "wrong", enc); ok {
		t.Fatal("wrong password verified")
	}
	if ok, _, _ := h.Verify(ctx, "", "x", ""); ok {
		t.Fatal("empty hash verified")
	}
}

// A hash made with other settings verifies and asks to be replaced; one naming settings out of bounds (or damaged) is
// refused before any hashing.
func TestPasswordSettings(t *testing.T) {
	h := NewHasher(2)
	ctx := context.Background()
	salt := RandomBytes(16)
	mk := func(m, tm uint32, p uint8, salt []byte, keyLen uint32) string {
		key := argon2.IDKey([]byte("pw"), salt, tm, m, p, keyLen)
		return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, tm, p,
			base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	}
	weaker := mk(12*1024, 1, 1, salt, 32)
	if ok, rehash, err := h.Verify(ctx, "", "pw", weaker); !ok || !rehash || err != nil {
		t.Errorf("weaker settings: ok %v, rehash %v, %v", ok, rehash, err)
	}
	for name, enc := range map[string]string{
		"too much memory": "$argon2id$v=19$m=4194304,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(salt[:16]),
		"too many passes": "$argon2id$v=19$m=19456,t=1000,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(salt),
		"too little":      mk(1024, 1, 1, salt, 32),
		"short salt":      mk(19456, 2, 1, salt[:4], 32),
		"damaged":         "$argon2id$v=19$m=x$y$z",
		"old version":     "$argon2id$v=18$m=65536,t=1,p=1$c2FsdA$AAAA",
		"garbage params":  "$argon2id$v=19$garbage$c2FsdHNhbHRzYWx0$" + strings.Repeat("A", 22),
		"bad salt":        "$argon2id$v=19$m=65536,t=1,p=1$!!!$" + strings.Repeat("A", 22),
		"bad hash":        "$argon2id$v=19$m=65536,t=1,p=1$c2FsdHNhbHRzYWx0$!!!",
		"memory of 1":     "$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHRzYWx0$" + strings.Repeat("A", 22),
	} {
		start := time.Now()
		if ok, _, err := h.Verify(ctx, "", "pw", enc); ok || !errors.Is(err, ErrHashParams) {
			t.Errorf("%s: ok %v, %v", name, ok, err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: refused only after %v", name, d)
		}
	}
}

// An imported bcrypt hash verifies (and always asks to be replaced); costs outside 4..14 and malformed hashes are
// refused, at import and at sign-in.
func TestPasswordBcrypt(t *testing.T) {
	h := NewHasher(2)
	ctx := context.Background()
	enc, err := bcrypt.GenerateFromPassword([]byte("correct horse"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if kind, err := CheckImport(string(enc)); kind != "bcrypt" || err != nil {
		t.Fatalf("import check: %q %v", kind, err)
	}
	if ok, rehash, err := h.Verify(ctx, "", "correct horse", string(enc)); !ok || !rehash || err != nil {
		t.Errorf("verify: ok %v, rehash %v, %v", ok, rehash, err)
	}
	if ok, _, _ := h.Verify(ctx, "", "wrong", string(enc)); ok {
		t.Error("wrong password verified")
	}
	// PHP's $2y$ is the same algorithm
	y := "$2y$" + string(enc)[4:]
	if ok, _, err := h.Verify(ctx, "", "correct horse", y); !ok || err != nil {
		t.Errorf("$2y$: %v %v", ok, err)
	}
	high, _ := bcrypt.GenerateFromPassword([]byte("x"), 4)
	tooHigh := "$2b$31$" + string(high)[7:]
	for name, bad := range map[string]string{"cost 31": tooHigh, "short": "$2b$10$abc", "garbage": "$2b$xx$" + string(enc)[7:]} {
		if _, err := CheckImport(bad); !errors.Is(err, ErrHashParams) {
			t.Errorf("import %s: %v", name, err)
		}
		if ok, _, err := h.Verify(ctx, "", "x", bad); ok || !errors.Is(err, ErrHashParams) {
			t.Errorf("verify %s: %v %v", name, ok, err)
		}
	}
	if kind, err := CheckImport("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"); kind != "argon2id" || err != nil {
		t.Errorf("argon2id import: %q %v", kind, err)
	}
	for _, bad := range []string{"", "plaintext", "$1$md5$x", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"} {
		if _, err := CheckImport(bad); !errors.Is(err, ErrHashParams) {
			t.Errorf("import %q accepted: %v", bad, err)
		}
	}
}

// A password is hashed as NFKC: the same password typed with a decomposed accent, or in full-width forms, matches.
func TestPasswordNormalized(t *testing.T) {
	h := NewHasher(1)
	ctx := context.Background()
	enc, err := h.Hash(ctx, "o", "café ｐａｓｓ")
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, _ := h.Verify(ctx, "o", "café pass", enc); !ok || rehash {
		t.Fatalf("another typing of the same password: ok %v rehash %v", ok, rehash)
	}
	// an argon2id hash imported from a system that hashed the password as typed matches once, and asks to be replaced
	salt := RandomBytes(16)
	raw := "café"
	sum := argon2.IDKey([]byte(raw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	imported := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
	if ok, rehash, _ := h.Verify(ctx, "o", raw, imported); !ok || !rehash {
		t.Fatalf("imported hash of the typed form: ok %v rehash %v", ok, rehash)
	}
}

// With every worker busy, callers wait in their organization's line and the lines are served in turn: a flood at one
// organization does not keep another waiting behind it.
func TestHasherServesLinesInTurn(t *testing.T) {
	h := NewHasher(1)
	ctx := context.Background()
	if err := h.acquire(ctx, "busy"); err != nil { // the one worker is taken
		t.Fatal(err)
	}
	flood, other := "flood", ""
	for i := 0; other == ""; i++ { // a key in another line
		if k := fmt.Sprint("org", i); lineOf(k) != lineOf(flood) {
			other = k
		}
	}
	order := make(chan string, 10)
	wait := func(key string) {
		go func() {
			if h.acquire(ctx, key) == nil {
				order <- key
				h.release()
			}
		}()
	}
	for range 5 {
		wait(flood)
	}
	waitFor(t, func() bool { h.mu.Lock(); defer h.mu.Unlock(); return len(h.waiting[lineOf(flood)]) == 5 })
	wait(other)
	waitFor(t, func() bool { h.mu.Lock(); defer h.mu.Unlock(); return len(h.waiting[lineOf(other)]) == 1 })
	h.release()
	served := 0
	for got := range order {
		served++
		if got == other {
			break
		}
	}
	if served > 2 {
		t.Fatalf("the other organization was served after %d of the flood's", served-1)
	}
	// a caller whose context ends while waiting leaves its line and takes no worker
	if err := h.acquire(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := h.acquire(cctx, "y"); err != ErrBusy {
		t.Fatalf("a caller that gave up: %v", err)
	}
	h.release()
	waitFor(t, func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.free == 1 })
}

func TestHasherBusy(t *testing.T) {
	h := NewHasher(1)
	h.free = 0 // every worker busy
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "", "x"); err != ErrBusy {
		t.Fatalf("want ErrBusy, got %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("timed out")
}
