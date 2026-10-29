// Command seed prepares a STOPPED Quisora node's store for the OpenID conformance run: the primary organization (as a
// first start would), an organization "acme" with the fake sign-in provider, the user it signs in, and the suite's
// clients. Clients get generated ids and secrets, so seed writes the suite configurations with them: it fills the
// templates in conformance/config into -out. Only the back-channel plan's clients get a back-channel logout URI
// (the suite reports logout posts to the other clients as unexpected); two more clients have the FAPI 2.0 Security
// Profile, for its plan. Repeatable: it starts from an empty store.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

func ptr[T any](v T) *T { return &v }

func main() {
	dataDir := flag.String("data-dir", "", "data directory of the stopped node")
	masterKey := flag.String("master-key", "", "the node's master key")
	publicURL := flag.String("public-url", "https://host.docker.internal:8090", "the node's public URL")
	suite := flag.String("suite", "https://localhost.emobix.co.uk:8453/test/a/quisora", "the suite's base URL for alias quisora")
	relay := flag.String("relay", "https://127.0.0.1:8096/test/a/quisora", "fakeidp's back-channel relay, as Quisora reaches it")
	issuer := flag.String("idp", "https://127.0.0.1:8095", "fakeidp's issuer, as Quisora reaches it")
	templates := flag.String("templates", "conformance/config", "suite configuration templates")
	out := flag.String("out", "conformance/.run/config", "where the filled-in suite configurations go")
	tokenOut := flag.String("admin-token", "conformance/.run/admin-token", "where the super admin's API token (admin scope) goes, for rotate-keys.sh")
	loginOut := flag.String("admin-login", "conformance/.run/admin-login.json", "where the super admin's sign-in (email, password, TOTP secret) goes, for rotate-keys.py: rotating keys takes a re-authenticated session")
	flag.Parse()
	ctx := context.Background()
	must := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}

	cfg := config.Default()
	cfg.Server.DataDir, cfg.Server.MasterKey, cfg.Server.PublicURL = *dataDir, *masterKey, *publicURL
	must(cfg.Validate())
	key, err := base64.StdEncoding.DecodeString(*masterKey)
	must(err)
	sealer, err := secure.NewSealer(key)
	must(err)
	st, err := app.OpenStore(ctx, cfg)
	must(err)
	defer st.Close()
	svc := service.New(cfg, st, sealer)
	sys := service.System

	admin, _, err := svc.Bootstrap(ctx, "admin@example.com")
	if err != nil || admin == nil {
		log.Fatalf("bootstrap: %v (seed starts from an empty store)", err)
	}
	seed := service.ActorForUser(admin, "") // an interactive (unscoped) actor: tokens never mint tokens
	seed.Name = "seed"
	_, tok, err := svc.CreateAPIToken(ctx, seed, service.APITokenInput{Name: "conformance", Scopes: []string{"admin"}, Expires: 30})
	must(err)
	must(os.WriteFile(*tokenOut, []byte(tok+"\n"), 0o600))
	// A password and an authenticator for the super admin (a development node only): rotate-keys.py signs in with
	// them, as rotating signing keys takes a recently re-authenticated admin console session, not a token.
	pw, totp := secure.RandomToken(18), secure.NewTOTPSecret()
	admin, err = svc.UpdateUser(ctx, sys, admin.ID, service.UserInput{Password: &pw})
	must(err)
	admin.TOTPSecret = sealer.SealFor(service.TOTPBinding(admin.ID), []byte(totp))
	must(svc.Users.Update(ctx, admin))
	login, _ := json.Marshal(map[string]string{"email": admin.Email, "password": pw, "totp_secret": totp})
	must(os.WriteFile(*loginOut, login, 0o600))
	org, err := svc.CreateOrg(ctx, sys, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme")})
	must(err)
	// The suite signs in through the fake provider and cannot enter a second factor: the default tenant (which
	// requires one when created) does not.
	def, err := svc.DefaultTenant(ctx, org.ID)
	must(err)
	def.Settings.RequireMFA = false
	must(svc.Tenants.Update(ctx, def))
	_, err = svc.CreateProvider(ctx, sys, org.ID, service.ProviderInput{Type: ptr(model.ProviderOIDC), Name: ptr("Fake IdP"),
		Issuer: issuer, ClientID: ptr("quisora-upstream"), ClientSecret: ptr("upstream-secret"), LinkByEmail: ptr(true),
		AutoProvision: ptr(false), Enabled: ptr(true)})
	must(err)
	_, err = svc.CreateUser(ctx, sys, org.ID, service.UserInput{Email: ptr("user@acme.test"), GivenName: ptr("Conformance"),
		FamilyName: ptr("User"), Verified: ptr(true), Phone: ptr("+44 20 7946 0958"), PhoneVerified: ptr(true),
		Locale: ptr("en-GB"), ZoneInfo: ptr("Europe/London")}) // the FAPI plan's claims request asks for both
	must(err)

	repl := []string{}
	for _, c := range []struct{ key, method string }{{"CLIENT1", model.AuthMethodSecretBasic}, {"CLIENT2", model.AuthMethodSecretBasic},
		{"CLIENTPOST", model.AuthMethodSecretPost}, {"CLIENTPOST2", model.AuthMethodSecretPost},
		{"CLIENTJWT", model.AuthMethodPrivateJWT}, {"CLIENTJWT2", model.AuthMethodPrivateJWT},
		{"BC1", model.AuthMethodSecretBasic}, {"BC2", model.AuthMethodSecretBasic}} {
		in := service.ClientInput{Name: ptr("Conformance " + strings.ToLower(c.key)), AuthMethod: ptr(c.method), FirstParty: ptr(true),
			RedirectURIs: &[]string{*suite + "/callback"}, PostLogoutURIs: &[]string{*suite + "/post_logout_redirect"},
			GrantTypes: &[]string{"authorization_code", "refresh_token"},
			// the suite's OIDC client sends no PKCE: these confidential clients opt out (require_pkce off)
			RequirePKCE: ptr(false),
			Scopes:      &[]string{"openid", "profile", "email", "phone", "offline_access"}}
		if strings.HasPrefix(c.key, "BC") {
			in.BackchannelURI = ptr(*relay + "/backchannel_logout")
		}
		var private string
		if c.method == model.AuthMethodPrivateJWT { // the suite signs its client assertions with the private half
			pub, priv := jwkPair(c.key)
			in.JWKS, private = &pub, priv
		}
		cl, secret, err := svc.CreateClient(ctx, sys, org.ID, in)
		must(err)
		repl = append(repl, "@"+c.key+"_ID@", cl.ID, "@"+c.key+"_SECRET@", secret, "@"+c.key+"_JWKS@", private)
	}
	// The FAPI 2.0 plan's two clients: the profile on (private_key_jwt with ES256 keys, PAR and DPoP required, PKCE,
	// refresh tokens that do not rotate).
	// The plan's second client uses a redirect URI with a query string. The RSA pair (PS256 keys) runs the plan
	// again with the modules that need RSA client keys (an RS256 client assertion must be refused).
	for key, redirect := range map[string]string{"CLIENTFAPI": *suite + "/callback",
		"CLIENTFAPI2": *suite + "/callback?dummy1=lorem&dummy2=ipsum", "CLIENTFAPIRSA": *suite + "/callback",
		"CLIENTFAPIRSA2": *suite + "/callback?dummy1=lorem&dummy2=ipsum"} {
		pub, private := jwkPair(key)
		if strings.Contains(key, "RSA") {
			pub, private = rsaJWKPair(key)
		}
		cl, _, err := svc.CreateClient(ctx, sys, org.ID, service.ClientInput{Name: ptr("Conformance " + strings.ToLower(key)),
			AuthMethod: ptr(model.AuthMethodPrivateJWT), JWKS: &pub, FirstParty: ptr(true), FAPI: ptr(true),
			RedirectURIs: &[]string{redirect}, GrantTypes: &[]string{"authorization_code", "refresh_token"},
			Scopes: &[]string{"openid", "profile", "email", "phone", "offline_access"}})
		must(err)
		repl = append(repl, "@"+key+"_ID@", cl.ID, "@"+key+"_JWKS@", private)
	}
	// The FAPI 2.0 client credentials plan's two clients: no user, so the protected resource is SCIM, the API that
	// takes client tokens (with the scim scope, from a service account): its acme/Users list.
	for _, key := range []string{"CLIENTFAPICC", "CLIENTFAPICC2"} {
		pub, private := jwkPair(key)
		cl, _, err := svc.CreateServiceAccount(ctx, sys, org.ID, service.ServiceAccountInput{Name: ptr("Conformance " + strings.ToLower(key)),
			AuthMethod: ptr(model.AuthMethodPrivateJWT), JWKS: &pub, FAPI: ptr(true), Scopes: &[]string{"scim"}})
		must(err)
		repl = append(repl, "@"+key+"_ID@", cl.ID, "@"+key+"_JWKS@", private)
	}
	// The suite tests the organization's own issuer (/o/<id>): its discovery, endpoints and sign-in pages are all under it.
	r := strings.NewReplacer(append(repl, "@ISSUER@", cfg.OrgIssuer(org.ID))...)
	must(os.MkdirAll(*out, 0o700))
	files, _ := filepath.Glob(filepath.Join(*templates, "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		must(err)
		must(os.WriteFile(filepath.Join(*out, filepath.Base(f)), []byte(r.Replace(string(b))), 0o600))
	}
	log.Printf("seeded; suite configurations in %s", *out)
}

// rsaJWKPair makes an RSA key for PS256, as jwkPair does for ES256.
func rsaJWKPair(kid string) (public, private string) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	k.Precompute()
	b := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.Bytes()) }
	pub := map[string]string{"kty": "RSA", "alg": "PS256", "use": "sig", "kid": strings.ToLower(kid), "n": b(k.N),
		"e": b(big.NewInt(int64(k.E)))}
	priv := map[string]string{"d": b(k.D), "p": b(k.Primes[0]), "q": b(k.Primes[1]), "dp": b(k.Precomputed.Dp),
		"dq": b(k.Precomputed.Dq), "qi": b(k.Precomputed.Qinv)}
	for n, v := range pub {
		priv[n] = v
	}
	pj, _ := json.Marshal(map[string]any{"keys": []any{pub}})
	sj, _ := json.Marshal(map[string]any{"keys": []any{priv}})
	return string(pj), string(sj)
}

// jwkPair makes an ES256 key: the client's public JWKS (registered with Quisora) and the private JWKS (for the suite).
func jwkPair(kid string) (public, private string) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	b := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	pub := map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": strings.ToLower(kid),
		"x": b(k.X), "y": b(k.Y)}
	priv := map[string]string{"d": b(k.D)}
	for n, v := range pub {
		priv[n] = v
	}
	pj, _ := json.Marshal(map[string]any{"keys": []any{pub}})
	sj, _ := json.Marshal(map[string]any{"keys": []any{priv}})
	return string(pj), string(sj)
}
