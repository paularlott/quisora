package secure

import (
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func key32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestCoverageTOTP(t *testing.T) {
	sec := NewTOTPSecret()
	if len(sec) != 32 {
		t.Fatalf("secret length %d", len(sec))
	}
	u, err := url.Parse(TOTPURI("Quisora", "a@example.com", sec))
	if err != nil || u.Scheme != "otpauth" || u.Query().Get("secret") != sec || u.Query().Get("issuer") != "Quisora" {
		t.Fatalf("uri %v %v", u, err)
	}
	now := time.Unix(1_700_000_000, 0)
	code := TOTPCode(sec, now)
	if len(code) != 6 {
		t.Fatalf("code %q", code)
	}
	step, ok := VerifyTOTP(sec, code[:3]+" "+code[3:], now, 0)
	if !ok {
		t.Fatal("valid code refused")
	}
	// replay of the same step, and anything older, is refused
	if _, ok := VerifyTOTP(sec, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	// one step of drift is allowed, two are not
	if _, ok := VerifyTOTP(sec, code, now.Add(30*time.Second), 0); !ok {
		t.Fatal("drift of one step refused")
	}
	if _, ok := VerifyTOTP(sec, code, now.Add(90*time.Second), 0); ok {
		t.Fatal("expired code accepted")
	}
	if _, ok := VerifyTOTP(sec, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
	if _, ok := VerifyTOTP("!!not base32!!", code, now, 0); ok {
		t.Fatal("malformed secret verified")
	}
	if TOTPCode("!!not base32!!", now) != "" {
		t.Fatal("malformed secret produced a code")
	}
}

func TestCoverageKeyring(t *testing.T) {
	k1, k2 := key32(1), key32(2)
	old, err := NewSealer(k1)
	if err != nil {
		t.Fatal(err)
	}
	sealed := old.SealFor("user/1/totp", []byte("secret"))
	if kid := SealedKeyID(sealed); kid != KeyID(k1) {
		t.Fatalf("kid %q", kid)
	}
	if kid := SealedKeyID(""); kid != "" {
		t.Fatal("empty value names a key")
	}
	if kid := SealedKeyID("v2:abc"); kid != "" {
		t.Fatal("a value in another format names a key")
	}

	ring, err := NewKeyring(k2, k1)
	if err != nil {
		t.Fatal(err)
	}
	if !ring.Previous() || ring.ActiveKeyID() != KeyID(k2) {
		t.Fatal("ring metadata")
	}
	ids := ring.KeyIDs()
	if len(ids) != 2 || ids[0] != KeyID(k2) || ids[1] != KeyID(k1) {
		t.Fatalf("ids %v", ids)
	}
	if len(ring.MACs("x")) != 2 {
		t.Fatal("MACs")
	}
	if got, err := ring.OpenFor("user/1/totp", sealed); err != nil || string(got) != "secret" {
		t.Fatalf("previous key did not open: %v", err)
	}
	if !ring.Stale(sealed) {
		t.Fatal("old-key value not stale")
	}
	// wrong binding refused
	if _, err := ring.OpenFor("user/2/totp", sealed); err == nil {
		t.Fatal("opened under another binding")
	}
	re, err := ring.Reseal("user/1/totp", sealed)
	if err != nil || ring.Stale(re) {
		t.Fatalf("reseal: %v", err)
	}
	if same, _ := ring.Reseal("user/1/totp", re); same != re {
		t.Fatal("fresh value was re-sealed")
	}
	if _, err := ring.Reseal("user/2/totp", sealed); err == nil {
		t.Fatal("reseal under wrong binding succeeded")
	}
	// a ring without the old key reports it unknown, and cannot reseal
	only, _ := NewSealer(k2)
	if _, err := only.OpenFor("user/1/totp", sealed); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err %v", err)
	}
	if _, err := only.Reseal("user/1/totp", sealed); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("reseal err %v", err)
	}
	if only.Previous() {
		t.Fatal("single key has previous")
	}
	// Keys: one sealer per key, only opening what its key sealed
	ks := ring.Keys()
	if len(ks) != 2 || ks[0].ActiveKeyID() != KeyID(k2) {
		t.Fatal("Keys")
	}
	if _, err := ks[1].OpenFor("user/1/totp", sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := ks[0].OpenFor("user/1/totp", sealed); err == nil {
		t.Fatal("wrong single key opened")
	}
	// Replace swaps keys in place
	holder, _ := NewSealer(k1)
	holder.Replace(only)
	if holder.ActiveKeyID() != KeyID(k2) {
		t.Fatal("Replace")
	}
	// duplicate / short keys
	if _, err := NewKeyring(k1, k1); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := NewKeyring(k1[:16]); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := NewKeyring(k1, k2[:5]); err == nil {
		t.Fatal("short previous key accepted")
	}
}

func TestCoverageSealedFormats(t *testing.T) {
	s, _ := NewSealer(key32(7))
	if s.Seal(nil) != "" || s.SealFor("b", nil) != "" {
		t.Fatal("empty seals to non-empty")
	}
	if b, err := s.Open(""); b != nil || err != nil {
		t.Fatal("empty open")
	}
	if b, err := s.OpenFor("b", ""); b != nil || err != nil {
		t.Fatal("empty openfor")
	}
	if got, err := s.Open(s.Seal([]byte("x"))); err != nil || string(got) != "x" {
		t.Fatal("roundtrip")
	}
	for _, bad := range []string{"v9:abc", "plain", "v3:nocolon", "v3:" + s.ActiveKeyID() + ":!!!", "v3:" + s.ActiveKeyID() + ":QQ", "v2:!!!", "v2:QQ"} {
		if _, err := s.OpenFor("b", bad); err == nil {
			t.Errorf("OpenFor(%q) succeeded", bad)
		}
	}
	for _, bad := range []string{"v3:x", "bogus", "v1:!!!", "v1:QQ"} {
		if _, err := s.Open(bad); err == nil {
			t.Errorf("Open(%q) succeeded", bad)
		}
	}
	// a bound value is not an unbound one
	if _, err := s.Open(s.SealFor("b", []byte("x"))); err == nil {
		t.Fatal("bound value opened unbound")
	}
}

func TestCoverageHasherAndErrors(t *testing.T) {
	if cap(NewHasher(0).sem) < 1 {
		t.Fatal("default workers")
	}
	h := NewHasher(1)
	for _, bad := range []string{
		"$argon2id$v=18$m=65536,t=1,p=1$c2FsdA$AAAA",
		"$argon2id$v=19$garbage$c2FsdHNhbHRzYWx0$" + strings.Repeat("A", 22),
		"$argon2id$v=19$m=65536,t=1,p=1$!!!$" + strings.Repeat("A", 22),
		"$argon2id$v=19$m=65536,t=1,p=1$c2FsdHNhbHRzYWx0$!!!",
		"$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHRzYWx0$" + strings.Repeat("A", 22),
	} {
		if ok, _, err := h.Verify(t.Context(), "pw", bad); ok || !errors.Is(err, ErrHashParams) {
			t.Errorf("Verify(%q): ok %v err %v", bad, ok, err)
		}
	}
	e := &DestinationError{Addr: mustAddr("10.0.0.1"), Private: true}
	if !strings.Contains(e.Error(), "allow_private_networks") {
		t.Fatal(e.Error())
	}
	e.Private = false
	if !strings.Contains(e.Error(), "link-local") || !errors.Is(e, ErrDestination) {
		t.Fatal(e.Error())
	}
}

func TestCoverageRootPool(t *testing.T) {
	if p, err := RootPool(""); p != nil || err != nil {
		t.Fatal("empty file")
	}
	if _, err := RootPool(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("missing file accepted")
	}
	f := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(f, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RootPool(f); err == nil {
		t.Fatal("garbage PEM accepted")
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
