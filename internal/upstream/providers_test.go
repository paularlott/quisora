package upstream_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/upstream"
)

func TestGitHub(t *testing.T) {
	e := setup(t)
	p := e.githubProvider(t, nil)
	authURL, _, err := e.up.BeginTenant(e.ctx, e.org, p, "/gh", "")
	if err != nil || !strings.HasPrefix(authURL, e.gh.Srv.URL+"/authorize?") {
		t.Fatalf("auth url %q %v", authURL, err)
	}
	if !strings.Contains(authURL, "scope=read%3Auser+user%3Aemail") || strings.Contains(authURL, "nonce") {
		t.Fatalf("github scopes/params: %s", authURL)
	}
	res, err := e.signIn(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Provisioned || res.User.Email != "octo@example.com" || res.User.FullName() != "The Octocat" || !res.User.EmailVerified {
		t.Fatalf("github user %+v", res.User)
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "583231")); err != nil {
		t.Fatalf("identity by numeric id: %v", err)
	}
	// A renamed account (new login, new primary email) is still the same user: subject is the numeric id.
	e.gh.Login = "renamed"
	e.gh.Emails = []map[string]any{{"email": "new@example.com", "primary": true, "verified": true}}
	res2, err := e.signIn(p, nil)
	if err != nil || res2.Provisioned || res2.User.ID != res.User.ID {
		t.Fatalf("renamed account: %v %+v", err, res2)
	}
}

func TestGitHubEmailRules(t *testing.T) {
	e := setup(t)
	p := e.githubProvider(t, func(in *service.ProviderInput) { in.AllowedDomains = &[]string{"example.com"} })
	for name, emails := range map[string][]map[string]any{
		"primary unverified":       {{"email": "a@example.com", "primary": true, "verified": false}},
		"verified but not primary": {{"email": "a@example.com", "primary": false, "verified": true}},
		"none":                     {},
		"verified secondary + unverified primary": {{"email": "x@example.com", "primary": true, "verified": false},
			{"email": "y@example.com", "primary": false, "verified": true}},
	} {
		e.gh.Emails = emails
		if _, err := e.signIn(p, nil); !errors.Is(err, upstream.ErrUnverifiedEmail) {
			t.Errorf("%s: want ErrUnverifiedEmail, got %v", name, err)
		}
	}
	e.gh.Emails = []map[string]any{{"email": "a@other.org", "primary": true, "verified": true}}
	if _, err := e.signIn(p, nil); !errors.Is(err, upstream.ErrDomain) {
		t.Fatalf("domain: %v", err)
	}
}

func TestGitHubTokenFailure(t *testing.T) {
	e := setup(t)
	p := e.githubProvider(t, nil)
	authURL, state, _ := e.up.BeginTenant(e.ctx, e.org, p, "", "")
	_ = e.gh.Authorize(authURL)
	if _, err := e.up.Finish(e.ctx, p.ID, state, state, "wrong-code"); !errors.Is(err, upstream.ErrUpstream) {
		t.Fatalf("want ErrUpstream, got %v", err)
	}
}

// Microsoft: each tenant issues its own tokens; only the allowed tenants sign in; the user is tenant:object ID; the
// email address is verified only when Microsoft vouches for its domain (xms_edov).
func TestMicrosoftProvider(t *testing.T) {
	e := setup(t)
	e.up.MicrosoftAuthority = e.oidc.Srv.URL
	tidA, tidB := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	p, err := e.svc.CreateProvider(e.ctx, service.System, e.org.ID, service.ProviderInput{Type: ptr(model.ProviderMicrosoft),
		Tenant: ptr("organizations"), AllowedTenants: &[]string{tidA}, ClientID: ptr("cid"), ClientSecret: ptr("s3cret"),
		AutoProvision: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	ms := func(tid, issTid, oid string, extra map[string]any) map[string]any {
		c := map[string]any{"iss": e.oidc.Srv.URL + "/" + issTid + "/v2.0", "tid": tid, "oid": oid, "sub": "pairwise-" + oid,
			"email": oid + "@contoso.example", "name": "Ms User"}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	// the authorization request goes to the "organizations" directory
	authURL, _, err := e.up.BeginTenant(e.ctx, e.org, p, "", "")
	if err != nil || !strings.HasPrefix(authURL, e.oidc.Srv.URL+"/authorize") {
		t.Fatalf("begin: %v %s", err, authURL)
	}
	res, err := e.signIn(p, ms(tidA, tidA, "obj-1", map[string]any{"xms_edov": true}))
	if err != nil || res.Claims.Subject != tidA+":obj-1" || !res.Claims.EmailVerified || res.User == nil {
		t.Fatalf("allowed tenant: %v %+v", err, res)
	}
	if _, err := e.signIn(p, ms(tidB, tidB, "obj-2", map[string]any{"xms_edov": true})); !errors.Is(err, upstream.ErrUpstream) {
		t.Errorf("a tenant that is not allowed: %v", err)
	}
	if _, err := e.signIn(p, ms(tidA, tidB, "obj-3", map[string]any{"xms_edov": true})); !errors.Is(err, upstream.ErrUpstream) {
		t.Errorf("issuer of another tenant: %v", err)
	}
	if _, err := e.signIn(p, ms(tidA, tidA, "", nil)); !errors.Is(err, upstream.ErrUpstream) {
		t.Errorf("no object id: %v", err)
	}
	// without xms_edov the address is not verified, so nobody is created for it (auto-provisioning needs a verified one)
	if res, err := e.signIn(p, ms(tidA, tidA, "obj-4", nil)); err == nil || (res != nil && res.User != nil) {
		t.Errorf("unverified email provisioned a user: %v %+v", err, res)
	}
}
