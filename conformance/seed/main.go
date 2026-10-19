// Command seed prepares a STOPPED Quisora node's store for the OpenID conformance run: the primary organization (as a
// first start would), an organization "acme" with the fake sign-in provider, the user it signs in, and the suite's
// clients. Clients get generated ids and secrets, so seed writes the suite configurations with them: it fills the
// templates in conformance/config into -out. Only the back-channel plan's clients get a back-channel logout URI
// (the suite reports logout posts to the other clients as unexpected). Repeatable: it starts from an empty store.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	dataDir := flag.String("data", "", "data directory of the stopped node")
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
		FamilyName: ptr("User"), Verified: ptr(true), Phone: ptr("+44 20 7946 0958"), PhoneVerified: ptr(true)})
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
	r := strings.NewReplacer(append(repl, "@ISSUER@", *publicURL)...)
	must(os.MkdirAll(*out, 0o700))
	files, _ := filepath.Glob(filepath.Join(*templates, "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		must(err)
		must(os.WriteFile(filepath.Join(*out, filepath.Base(f)), []byte(r.Replace(string(b))), 0o600))
	}
	log.Printf("seeded; suite configurations in %s", *out)
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
