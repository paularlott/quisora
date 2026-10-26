package login

import (
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

func TestSafeNext(t *testing.T) {
	ok := []string{"/", "/account", "/oauth/authorize?flow=abc&x=1", "/a/b#frag", "/%2f%2fevil.example", "/a//b"}
	bad := []string{"", "account", "//evil.example", "///evil.example", "/\\evil.example", "https://evil.example", "http://x", "javascript:alert(1)",
		"/a\\b", "/a\nb", "/a\rb", "/a\x00b", "/a\tb", "/\x7f", "data:text/html,x", " /account", strings.Repeat("/a", 2000)}
	for _, n := range ok {
		if safeNext(n) != n {
			t.Errorf("safeNext(%q) rejected a local path", n)
		}
	}
	for _, n := range bad {
		if got := safeNext(n); got != "" {
			t.Errorf("safeNext(%q) = %q, want rejection", n, got)
		}
	}
	if nextOrDefault("//evil.example") != "/account" || nextOrDefault("/x") != "/x" {
		t.Error("nextOrDefault")
	}
}

func TestQRDataURL(t *testing.T) {
	uri := "otpauth://totp/Acme:pat%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA1&digits=6&period=30"
	d, err := qrDataURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := strings.CutPrefix(d, "data:image/svg+xml;base64,")
	if !ok {
		t.Fatal("not an svg data url")
	}
	svg, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	// well-formed XML, with nothing active in it
	dec := xml.NewDecoder(strings.NewReader(string(svg)))
	for {
		if _, err := dec.Token(); err != nil {
			if err != io.EOF {
				t.Fatalf("svg is not well-formed: %v", err)
			}
			break
		}
	}
	if strings.Contains(string(svg), "<script") {
		t.Fatal("script in the svg")
	}
	if d2, _ := qrDataURL(uri + "&x=1"); d == d2 {
		t.Fatal("different input, same code")
	}
}

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"pat@example.com":  "p•••@example.com",
		"éva@example.com":  "é•••@example.com",
		"@example.com":     "your email address",
		"no-at-sign":       "your email address",
		"":                 "your email address",
		"a@b":              "a•••@b",
		"x@y@example.test": "x•••@y@example.test",
	} {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoginURLBuilding(t *testing.T) {
	if withNext("/login", "") != "/login" || withNext("/login", "/a b?c=d") != "/login?next=%2Fa+b%3Fc%3Dd" {
		t.Error("withNext")
	}
	org := &model.Org{Name: "ac me"}
	if got := loginURL(org, "/x", "t1", "denied"); got != "/login/ac%20me?error=denied&next=%2Fx&tenant=t1" {
		t.Errorf("loginURL = %q", got)
	}
	if got := loginURL(org, "", "", ""); got != "/login/ac%20me" {
		t.Errorf("loginURL bare = %q", got)
	}
}

func TestTenantParam(t *testing.T) {
	for q, want := range map[string]string{
		"tenant=acme":                        "acme",
		"tenant=%20ACME%20":                  "acme",
		"tenant=":                            "",
		"":                                   "",
		"tenant=a/b":                         "",
		"tenant=..%2f..":                     "",
		"tenant=" + strings.Repeat("a", 500): "",
		"tenant=<script>":                    "",
	} {
		r := httptest.NewRequest("GET", "/login/x?"+q, nil)
		if got := tenantParam(r); got != want {
			t.Errorf("tenantParam(%.40q) = %q, want %q", q, got, want)
		}
	}
}
