package login

import (
	"encoding/base64"
	"encoding/xml"
	"io"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

const testOrg = "034nmRmWulzDzPeDXkYXtH"

var testOrgModel = &model.Org{ID: testOrg, Name: "acme"}

func TestSafeNext(t *testing.T) {
	in := "/o/" + testOrg
	ok := []string{in, "/o/acme", "/o/acme/account?x=1", "/o/ACME/account", in + "/account", in + "/oauth/authorize?flow=abc&x=1", in + "/a/b#frag", in + "/%2f%2fevil.example", in + "/a//b",
		"/admin", "/admin/orgs/acme/users?x=1"}
	bad := []string{"", "account", "/", "/account", "//evil.example", "///evil.example", "/\\evil.example", "https://evil.example", "http://x",
		"javascript:alert(1)", in + "/a\\b", in + "/a\nb", in + "/a\rb", in + "/a\x00b", in + "/a\tb", in + "/\x7f", "data:text/html,x",
		" " + in + "/account", in + strings.Repeat("/a", 2000),
		// another organization's space, by id or by name, and what only looks like this one's or the console's
		"/o/034nmRmWuYvwk3Xoa4mNaO/account", "/o/other/account", "/o/acmex/account", in + "x/account", "/administrator", "/o",
		// dot segments climb out of the space
		in + "/../034nmRmWuYvwk3Xoa4mNaO/account", in + "/./../x", in + "/%2e%2e/x", "/admin/../account"}
	for _, n := range ok {
		if safeNext(testOrgModel, n) != n {
			t.Errorf("safeNext(%q) rejected a path in the organization's space (by id or by name) or the console", n)
		}
	}
	for _, n := range bad {
		if got := safeNext(testOrgModel, n); got != "" {
			t.Errorf("safeNext(%q) = %q, want rejection", n, got)
		}
	}
	if nextOrDefault(testOrgModel, "//evil.example") != in+"/account" || nextOrDefault(testOrgModel, in+"/x") != in+"/x" {
		t.Error("nextOrDefault")
	}
	// Ids are case-sensitive: another organization's id, folded to lower case, spells this organization's name, and its
	// space is still not this one's (a request to it reaches the other organization).
	named := &model.Org{ID: testOrg, Name: "7n42dgm5tflk9n8mt7fhc0"}
	if !model.IsID("7n42DGM5Tflk9n8mt7Fhc0") || !model.ValidOrgName(named.Name) {
		t.Fatal("setup: the other organization's id or this one's name")
	}
	if got := safeNext(named, "/o/7n42DGM5Tflk9n8mt7Fhc0/account"); got != "" {
		t.Errorf("another organization's id accepted as this one's name: %q", got)
	}
	if got := safeNext(named, "/o/7n42dgm5tflk9n8mt7fhC0/account"); got == "" { // not an id: the name in another case
		t.Error("the organization's name in upper case refused")
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
	org := &model.Org{ID: testOrg, Name: "acme"}
	if got := loginURL(org, "/x", "t1", "denied"); got != "/o/"+testOrg+"/login?error=denied&next=%2Fx&tenant=t1" {
		t.Errorf("loginURL = %q", got)
	}
	if got := loginURL(org, "", "", ""); got != "/o/"+testOrg+"/login" {
		t.Errorf("loginURL bare = %q", got)
	}
}
