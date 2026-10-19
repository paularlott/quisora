package login

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
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
	// well-formed XML with a square viewBox and a body of module runs
	dec := xml.NewDecoder(strings.NewReader(string(svg)))
	var root xml.StartElement
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("svg is not well-formed: %v", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			root = se
			break
		}
	}
	var vb string
	for _, a := range root.Attr {
		if a.Name.Local == "viewBox" {
			vb = a.Value
		}
	}
	var w, h int
	if _, err := fmtSscanf(vb, &w, &h); err != nil || w != h || w < 29 {
		t.Fatalf("viewBox %q", vb)
	}
	if !strings.Contains(string(svg), `d="M`) || strings.Contains(string(svg), "<script") {
		t.Fatal("unexpected svg body")
	}
	if len(d) > 20000 {
		t.Fatalf("data url unexpectedly large: %d", len(d))
	}
	d2, _ := qrDataURL(uri + "&x=1")
	if d == d2 {
		t.Fatal("different input, same code")
	}
}

func fmtSscanf(vb string, w, h *int) (int, error) {
	var x, y int
	return fmt.Sscanf(vb, "%d %d %d %d", &x, &y, w, h)
}
