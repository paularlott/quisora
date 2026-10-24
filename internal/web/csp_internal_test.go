package web

import (
	"strings"
	"testing"
)

// Images load only from this server, data: URIs and the hosts of logos configured as https URLs.
func TestCSPImageSources(t *testing.T) {
	if p := contentSecurityPolicy("", ""); !strings.Contains(p, "img-src 'self' data:;") {
		t.Fatalf("default: %s", p)
	}
	p := contentSecurityPolicy("https://cdn.example/logo.svg", "https://cdn.example/dark.svg")
	if !strings.Contains(p, "img-src 'self' data: https://cdn.example;") {
		t.Fatalf("with an https logo: %s", p)
	}
	if p := contentSecurityPolicy("/etc/quisora/logo.svg", "http://plain.example/x.png"); !strings.Contains(p, "img-src 'self' data:;") {
		t.Fatalf("file and http logos add nothing: %s", p)
	}
}
