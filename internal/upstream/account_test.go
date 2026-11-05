package upstream_test

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/upstream"
)

// The account a sign-in went through is passed on as each provider names it: Microsoft's object and tenant IDs (its
// sub differs per application) and user principal name, the sub and email of the other OpenID Connect providers,
// GitHub's user ID and username, and for another organization the user's ID there, that organization and the address it
// verified (never a username or an unverified address in its place). Nothing usable as an ID, nothing passed on.
func TestAccountOf(t *testing.T) {
	long := strings.Repeat("x", 300)
	for _, tc := range []struct {
		name string
		typ  string
		c    upstream.Claims
		want *model.UpstreamAccount
	}{
		{"microsoft", model.ProviderMicrosoft, upstream.Claims{Subject: "tid-1:oid-1", Email: "ada@contoso.com", Username: "ada@contoso.onmicrosoft.com"},
			&model.UpstreamAccount{Subject: "oid-1", Tenant: "tid-1", Login: "ada@contoso.onmicrosoft.com"}},
		{"microsoft without a UPN", model.ProviderMicrosoft, upstream.Claims{Subject: "tid-1:oid-1", Email: "ada@contoso.com"},
			&model.UpstreamAccount{Subject: "oid-1", Tenant: "tid-1", Login: "ada@contoso.com"}},
		{"microsoft without a tenant", model.ProviderMicrosoft, upstream.Claims{Subject: "oid-1"}, nil},
		{"google", model.ProviderGoogle, upstream.Claims{Subject: "1084", Email: "ada@gmail.com", Username: "ignored"},
			&model.UpstreamAccount{Subject: "1084", Login: "ada@gmail.com"}},
		{"oidc without an email", model.ProviderOIDC, upstream.Claims{Subject: "s", Username: "ada"},
			&model.UpstreamAccount{Subject: "s", Login: "ada"}},
		{"github", model.ProviderGitHub, upstream.Claims{Subject: "583231", Email: "ada@example.com", Username: "octo-ada"},
			&model.UpstreamAccount{Subject: "583231", Login: "octo-ada"}},
		{"organization", model.ProviderOrganization, upstream.Claims{Subject: "u1", Email: "ada@example.com", EmailVerified: true, Username: "ada"},
			&model.UpstreamAccount{Subject: "u1", Tenant: "src-org", Login: "ada@example.com"}},
		{"organization, unverified address", model.ProviderOrganization, upstream.Claims{Subject: "u1", Email: "ada@example.com", Username: "ada@example.com"},
			&model.UpstreamAccount{Subject: "u1", Tenant: "src-org"}},
		{"no subject", model.ProviderGoogle, upstream.Claims{Email: "ada@gmail.com"}, nil},
		{"subject too long", model.ProviderGoogle, upstream.Claims{Subject: long}, nil},
		{"login too long", model.ProviderGoogle, upstream.Claims{Subject: "s", Email: long}, &model.UpstreamAccount{Subject: "s"}},
	} {
		got := upstream.AccountOf(&model.Provider{Type: tc.typ, SourceOrg: "src-org"}, tc.c)
		if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
