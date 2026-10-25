package upstream

import (
	"crypto"
	"net/http"
	"testing"
)

func TestSplitJWTRejectsMalformed(t *testing.T) {
	good := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30.c2ln" // {"alg":"RS256","kid":"k1"} . {} . sig
	h, payload, in, sig, err := splitJWT(good)
	if err != nil || h.Alg != "RS256" || h.Kid != "k1" || string(payload) != "{}" || string(sig) != "sig" ||
		string(in) != "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30" {
		t.Fatalf("good token: %+v %q %q %q %v", h, payload, in, sig, err)
	}
	for name, tok := range map[string]string{
		"empty":             "",
		"two parts":         "a.b",
		"four parts":        "a.b.c.d",
		"header not base64": "!!!.e30.c2ln",
		"header not json":   "bm90anNvbg.e30.c2ln",
		"payload bad":       "eyJhbGciOiJSUzI1NiJ9.!!!.c2ln",
		"signature bad":     "eyJhbGciOiJSUzI1NiJ9.e30.!!!",
		"padded base64":     "eyJhbGciOiJSUzI1NiJ9==.e30.c2ln",
	} {
		if _, _, _, _, err := splitJWT(tok); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestHashFor(t *testing.T) {
	for alg, want := range map[string]crypto.Hash{"RS256": crypto.SHA256, "ES256": crypto.SHA256, "PS256": crypto.SHA256,
		"RS384": crypto.SHA384, "ES384": crypto.SHA384, "RS512": crypto.SHA512} {
		if got := hashFor(alg); got != want {
			t.Errorf("%s: %v", alg, got)
		}
	}
}

func TestPickKey(t *testing.T) {
	one := []verifyKey{{kid: "a"}}
	two := []verifyKey{{kid: "a"}, {kid: "b"}}
	if k := pickKey(one, ""); k == nil || k.kid != "a" {
		t.Fatal("a single key is unambiguous without a kid")
	}
	if pickKey(two, "") != nil || pickKey(nil, "") != nil {
		t.Fatal("no kid with several keys (or none) must pick nothing")
	}
	if k := pickKey(two, "b"); k == nil || k.kid != "b" {
		t.Fatal("kid lookup")
	}
	if pickKey(two, "c") != nil {
		t.Fatal("unknown kid")
	}
}

func TestNewDefaults(t *testing.T) {
	client := &http.Client{}
	s := New(nil, nil, "https://idp.example/", client)
	if s.PublicURL != "https://idp.example" || s.Now == nil || s.HTTP != client || s.GitHubAPIURL == "" || s.MicrosoftAuthority == "" {
		t.Fatalf("%+v", s)
	}
	if s.CallbackURL("p") != "https://idp.example/login/callback/p" {
		t.Fatal(s.CallbackURL("p"))
	}
}
