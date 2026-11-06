package secure

import (
	"net/url"
	"testing"
	"time"
)

func TestTOTP(t *testing.T) {
	t.Run("rfc vector", func(t *testing.T) {
		// RFC 6238 test vector (SHA1, secret "12345678901234567890").
		secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
		now := time.Unix(59, 0)
		step, ok := VerifyTOTP(secret, "287082", now, 0)
		if !ok || step != 1 {
			t.Fatalf("rfc vector: ok=%v step=%d", ok, step)
		}
		if _, ok := VerifyTOTP(secret, "287082", now, step); ok {
			t.Fatal("replay accepted")
		}
		if _, ok := VerifyTOTP(secret, "000000", now, 0); ok {
			t.Fatal("wrong code accepted")
		}
	})
	t.Run("generated secret", func(t *testing.T) {
		sec := NewTOTPSecret()
		if len(sec) != 32 {
			t.Fatalf("secret length %d", len(sec))
		}
		u, err := url.Parse(TOTPURI("Quisora", "a@example.com", sec))
		if err != nil || u.Scheme != "otpauth" || u.Query().Get("secret") != sec || u.Query().Get("issuer") != "Quisora" {
			t.Fatalf("uri %v %v", u, err)
		}
		// a colon in the issuer would split the label in the wrong place
		if u, _ := url.Parse(TOTPURI("Acme: Sales", "a@example.com", sec)); u.Path != "/Acme Sales:a@example.com" ||
			u.Query().Get("issuer") != "Acme Sales" {
			t.Fatalf("issuer with a colon: %v", u)
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
	})
}
