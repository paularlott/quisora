package secure

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The test vectors of the specification (Drepper, "Unix crypt using SHA-256 and SHA-512"), in the form a hash is
// stored (a salt longer than 16 characters, or fewer rounds than 1000, is written as it was used); then hashes in the
// form PHP's crypt() makes (default 5,000 rounds, a 16-character salt), made with `openssl passwd -6 -salt`, which
// agrees with the specification's vectors.
var sha512CryptVectors = []struct{ password, hash string }{
	{"Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
	{"Hello world!", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
	{"This is just a test", "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"},
	{"a very much longer text to encrypt.  This one even stretches over morethan one line.", "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"},
	{"we have a short salt string but not a short password", "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"},
	{"a short string", "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"},
	{"the minimum number is still observed", "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."},
	// the specification's "rounds=10" is raised to the minimum of 1000, and gives the same hash
	{"the minimum number is still observed", "$6$rounds=10$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."},
	// PHP's format
	{"correct horse battery", "$6$aZ09./aZ09./aZ09$JNpuOzbJHWS6aFNixpRZk4jTQsizfyAu/UAR2aRai8mCqPKjtRvYsUsCOajeqcNfK.UM.Qc9hpmXeM8kHaatU0"},
	{"pässwörd 密码 é", "$6$Qm3xT8vLk0RzP.1/$moLMrhzl2DLM5.J7nPv5lt0Xnh97auWYUoiQwEQ.qA8cDnUA4r640XG5x2Bz3jjFT1MCpMmlinpYWq1ODjPn90"},
	{"correct horse battery", "$6$rounds=5000$aZ09./aZ09./aZ09$JNpuOzbJHWS6aFNixpRZk4jTQsizfyAu/UAR2aRai8mCqPKjtRvYsUsCOajeqcNfK.UM.Qc9hpmXeM8kHaatU0"},
	// the most rounds accepted
	{"x", "$6$rounds=1000000$maxroundssalt$aB5mM1MoyOVXaYjda30FvFrqviTPaOplBCgMtWcZJI4i1r9sAsl5StKDKSxGv0jdEcWQVNtP2fBo06BBNW//K0"},
}

// An imported SHA-512 crypt hash verifies (and asks to be replaced, as bcrypt does); another password does not. The
// password is tried as typed first, then normalized.
func TestPasswordSHA512Crypt(t *testing.T) {
	h := NewHasher(2)
	ctx := context.Background()
	for _, v := range sha512CryptVectors {
		if kind, err := CheckImport(v.hash); kind != "sha512-crypt" || err != nil {
			t.Errorf("import check of %q: %q %v", v.hash, kind, err)
		}
		if ok, rehash, err := h.Verify(ctx, "", v.password, v.hash); !ok || !rehash || err != nil {
			t.Errorf("verify %q: ok %v, rehash %v, %v", v.hash, ok, rehash, err)
		}
		if ok, rehash, err := h.Verify(ctx, "", v.password+" ", v.hash); ok || rehash || err != nil {
			t.Errorf("a wrong password for %q: ok %v, rehash %v, %v", v.hash, ok, rehash, err)
		}
	}

	// "café" typed with a decomposed accent: a hash of that typing matches as typed, a hash of the composed form (what
	// NFKC makes of it) matches once normalized
	typed := "café"
	ofTyped := "$6$abc$fvBb0t53VoGn8l8CoyPyKnFz9v3scTcMofJE.Uu9SUMBbVqFnsQ8TfJFakzCO.xYhk8v2fW35jrvtUd9wAGkc0"
	ofNormalized := "$6$abc$VNxO7C/6fCDIBTmYnzKFyNvrWTSjyB.C.Qx4C7zX8OJs3jtLNQtmbgUTGzFUD0HTNZaIYNUkTQZdFKCz1q3kW0"
	for _, enc := range []string{ofTyped, ofNormalized} {
		if ok, rehash, err := h.Verify(ctx, "", typed, enc); !ok || !rehash || err != nil {
			t.Errorf("%q typed decomposed: ok %v, rehash %v, %v", enc, ok, rehash, err)
		}
	}
	if ok, _, _ := h.Verify(ctx, "", "cafe", ofNormalized); ok {
		t.Error("a password without the accent verified")
	}

	// crypt accepts an empty password
	empty := sha512Crypt(nil, []byte("salt"), 5000)
	if ok, _, err := h.Verify(ctx, "", "", "$6$salt$"+empty); !ok || err != nil {
		t.Errorf("empty password: %v %v", ok, err)
	}
}

// Hashes that are not well-formed SHA-512 crypt, or name more rounds than the cap, are refused at import and at
// sign-in, before any hashing, and the error does not carry the hash.
func TestCheckImportSHA512Crypt(t *testing.T) {
	h := NewHasher(1)
	ctx := context.Background()
	body := strings.Repeat("a", sha512CryptHashLen)
	for name, bad := range map[string]string{
		"rounds over the cap":   "$6$rounds=1000001$salt$" + body,
		"rounds out of range":   "$6$rounds=99999999999$salt$" + body,
		"rounds not a number":   "$6$rounds=x$salt$" + body,
		"rounds signed":         "$6$rounds=+5000$salt$" + body,
		"rounds empty":          "$6$rounds=$salt$" + body,
		"rounds without salt":   "$6$rounds=5000$" + body,
		"rounds in the salt":    "$6$rounds=5000$salt",
		"salt of 17":            "$6$" + strings.Repeat("s", 17) + "$" + body,
		"salt of 17, rounds":    "$6$rounds=5000$" + strings.Repeat("s", 17) + "$" + body,
		"no salt":               "$6$" + body,
		"short hash":            "$6$salt$" + body[1:],
		"long hash":             "$6$salt$" + body + "a",
		"hash outside alphabet": "$6$salt$" + body[1:] + "+",
		"extra part":            "$6$salt$" + body + "$x",
		"sha-256":               "$5$salt$" + body[:43],
		"md5":                   "$1$salt$" + body[:22],
		"no prefix":             "salt$" + body,
		"prefix only":           "$6$",
	} {
		_, err := CheckImport(bad)
		if !errors.Is(err, ErrHashParams) || strings.Contains(err.Error(), body) {
			t.Errorf("import %s: %v", name, err)
		}
		if strings.HasPrefix(bad, "$6$") {
			if ok, _, err := h.Verify(ctx, "", "x", bad); ok || !errors.Is(err, ErrHashParams) {
				t.Errorf("verify %s: %v %v", name, ok, err)
			}
		}
	}
	for name, good := range map[string]string{
		"no rounds":            "$6$salt$" + body,
		"16-character salt":    "$6$" + strings.Repeat("s", 16) + "$" + body,
		"empty salt":           "$6$$" + body,
		"rounds at cap":        "$6$rounds=1000000$salt$" + body,
		"rounds below minimum": "$6$rounds=1$salt$" + body,
		"rounds with zeros":    "$6$rounds=005000$salt$" + body,
	} {
		if kind, err := CheckImport(good); kind != "sha512-crypt" || err != nil {
			t.Errorf("import %s: %q %v", name, kind, err)
		}
	}
}

// Quisora never makes a SHA-512 crypt hash: what it makes is argon2id, and a sign-in that matches an imported one is
// asked to replace it.
func TestHashIsNeverSHA512Crypt(t *testing.T) {
	enc, err := NewHasher(1).Hash(context.Background(), "", "x")
	if err != nil || isSHA512Crypt(enc) {
		t.Fatalf("%q %v", enc, err)
	}
}
