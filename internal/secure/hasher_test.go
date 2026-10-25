package secure

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

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

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("timed out")
}
