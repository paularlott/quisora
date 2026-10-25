package login

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

func TestCoverageMaskEmail(t *testing.T) {
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

func TestCoverageURLHelpers(t *testing.T) {
	if sepFor("/a") != "?" || sepFor("/a?b=1") != "&" {
		t.Error("sepFor")
	}
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

func TestCoverageTenantParam(t *testing.T) {
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
