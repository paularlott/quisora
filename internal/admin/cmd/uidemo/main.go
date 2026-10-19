// Command uidemo runs the admin UI over an in-memory store seeded with demo data. It exists for design work and for
// the accessibility audit (web/tests): it serves HTTPS with a self-signed certificate and adds a development-only
// sign-in shortcut, GET /__demo/login?as=super|admin|manager|user&next=/path.
//
//	go run ./internal/admin/cmd/uidemo -addr 127.0.0.1:18443
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/events"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18443", "listen address")
	theme := flag.String("theme", "system", "default theme: light, dark or system")
	flag.Parse()

	dir, err := os.MkdirTemp("", "quisora-uidemo")
	must(err)
	defer os.RemoveAll(dir)

	cfg := config.Default()
	cfg.Server.Listen = *addr
	// WebAuthn needs a secure context and an RP id that is a registrable host name: "localhost" qualifies, an IP address
	// does not. Browse the demo at https://localhost:<port>.
	_, port, err := net.SplitHostPort(*addr)
	must(err)
	cfg.Server.PublicURL = "https://localhost:" + port
	cfg.Server.DataDir = dir
	cfg.UI.SiteName = "Quisora"
	cfg.UI.DefaultTheme = *theme
	cfg.UI.Footer = "Quisora demo · All data is in memory"
	cfg.Limits.PasswordWorkers = 4
	cfg.Mail.SMTPHost = demoMailHost
	must(cfg.Validate())

	hub := events.NewHub()
	st := &publishing{Store: memstore.New(), hub: hub}
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(cfg, st, sealer)
	ctx := context.Background()
	super, _, err := svc.Bootstrap(ctx, "admin@example.com")
	must(err)
	demo, byName := seed(ctx, svc, super)

	eph := ephemeral.NewLocal("demo")
	srv, err := web.New(cfg, svc, eph, logger.NewNullLogger())
	must(err)
	adm := admin.New()
	srv.Use(adm)
	srv.Use(&events.Module{Hub: hub})
	extraModules(srv, adm)
	srv.Mux.Handle("/", admin.NotFound(srv))
	srv.Mux.HandleFunc("GET /__demo/login", func(w http.ResponseWriter, r *http.Request) {
		u := demo[r.URL.Query().Get("as")]
		if u == nil {
			http.Error(w, "unknown role", http.StatusBadRequest)
			return
		}
		org, _ := svc.Orgs.Get(r.Context(), u.OrgID)
		amr := []string{"pwd"}
		if u.Role.Rank() >= model.RoleManager.Rank() {
			amr = []string{"pwd", "otp", "mfa"} // the console needs a second factor
		}
		if _, err := srv.Sessions.Create(r.Context(), w, r, u, org, amr); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		next := r.URL.Query().Get("next")
		if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
			next = "/admin"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
	})

	// Development-only: GET /__demo/invite?as=<username> redirects to a fresh invitation link for that seeded user
	// (so the invite page can be audited in each organization setup).
	srv.Mux.HandleFunc("GET /__demo/invite", func(w http.ResponseWriter, r *http.Request) {
		u := byName[r.URL.Query().Get("as")]
		if u == nil {
			http.Error(w, "unknown user", http.StatusBadRequest)
			return
		}
		link, _, err := svc.CreateInvite(r.Context(), service.System, u.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		http.Redirect(w, r, link, http.StatusSeeOther)
	})

	sctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	must(srv.Start(sctx))
	fmt.Println("uidemo listening on", cfg.Server.PublicURL, "— sign in with /__demo/login?as=super")
	<-sctx.Done()
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func ptr[T any](v T) *T { return &v }

// seed fills the store and returns one user per demo role (super, admin, manager, user), all in the "acme" org
// except the super admin, and every seeded user by username (for /__demo/invite).
//
// Besides the acme users with passwords, it seeds: "iris" (acme, no password yet), and the org "northwind" where
// passwords are off (passkey and the org's sign-in provider only) with "pat" (has a passkey) and "quinn" (nothing set up).
func seed(ctx context.Context, svc *service.Service, super *model.User) (map[string]*model.User, map[string]*model.User) {
	sys := service.System
	mk := func(name, display string) *model.Org {
		o, err := svc.CreateOrg(ctx, sys, service.OrgInput{Name: ptr(name), DisplayName: ptr(display)})
		must(err)
		return o
	}
	acme := mk("acme", "Acme Corporation")
	mk("globex", "Globex Industries")
	mk("initech", "Initech")
	mk("umbrella", "Umbrella Labs")

	byName := map[string]*model.User{"admin": super}
	mkUser := func(org *model.Org, username, display string, role model.Role, active bool, withPassword bool) *model.User {
		given, family, _ := strings.Cut(display, " ")
		in := service.UserInput{Username: ptr(username), Email: ptr(username + "@" + org.Name + ".example"),
			GivenName: ptr(given), FamilyName: ptr(family), Role: ptr(role), Active: ptr(active)}
		if withPassword {
			in.Password = ptr(secure.RandomToken(15))
		}
		u, err := svc.CreateUser(ctx, sys, org.ID, in)
		must(err)
		byName[username] = u
		return u
	}
	user := func(org *model.Org, username, display string, role model.Role, active bool) *model.User {
		return mkUser(org, username, display, role, active, true)
	}
	out := map[string]*model.User{"super": super}
	out["admin"] = user(acme, "ada", "Ada Lovelace", model.RoleAdmin, true)
	out["manager"] = user(acme, "grace", "Grace Hopper", model.RoleManager, true)
	out["user"] = user(acme, "alan", "Alan Turing", model.RoleUser, true)
	// a plain user reserved for browser tests that change their own sign-in set-up (authenticator app)
	out["otp"] = user(acme, "katherine", "Katherine Johnson", model.RoleUser, true)
	// Linked addresses for the email section: one verified (added by an administrator), one the user added and has
	// not verified yet.
	{
		alan := out["user"]
		_, lerr := svc.AddLinkedEmail(ctx, sys, alan.ID, "alan.turing@bletchley.example", true)
		must(lerr)
		_, lerr = svc.AddLinkedEmail(ctx, sys, alan.ID, "alan@the7thdream.example", false)
		must(lerr)
	}
	_, terr := svc.UpdateUser(ctx, sys, out["user"].ID, service.UserInput{Tags: &[]string{"dept:engineering", "vip"},
		Locale: ptr("en-GB"), ZoneInfo: ptr("Europe/London"), UserType: ptr("employee"), Phone: ptr("+44 20 7946 0958"), PhoneVerified: ptr(true),
		Work: &service.WorkInput{Title: ptr("Mathematician"), Department: ptr("Hut 8"), Organization: ptr("Bletchley Park"),
			EmployeeNumber: ptr("E-1912"), ManagerID: &out["manager"].ID}})
	must(terr)
	names := []string{"Margaret Hamilton", "Linus Torvalds", "Katherine Johnson", "Dennis Ritchie", "Barbara Liskov", "Ken Thompson",
		"Radia Perlman", "Donald Knuth", "Frances Allen", "Edsger Dijkstra", "Hedy Lamarr", "Tim Berners-Lee", "Sophie Wilson",
		"Guido van Rossum", "Joan Clarke", "Brian Kernighan", "Annie Easley", "Bjarne Stroustrup", "Mary Allen Wilkes",
		"Vint Cerf", "Jean Bartik", "Rob Pike", "Lynn Conway", "John McCarthy", "Karen Sparck Jones", "Niklaus Wirth",
		"Evelyn Boyd Granville", "Leslie Lamport", "Shafi Goldwasser", "Ada Yonath", "Whitfield Diffie", "Adele Goldberg",
		"Anita Borg", "Yukihiro Matsumoto", "Dorothy Vaughan", "Peter Norvig", "Tove Jansson", "Mae Jemison", "Ivan Sutherland"}
	mkUser(acme, "iris", "Iris Apfel", model.RoleUser, true, false)
	var members []*model.User
	for i, n := range names {
		role := model.RoleUser
		if i%9 == 0 {
			role = model.RoleManager
		}
		u := user(acme, strings.ToLower(strings.ReplaceAll(strings.Fields(n)[0], ".", ""))+fmt.Sprint(i), n, role, true)
		if i%7 == 3 { // disabled by an administrator, with the reason shown on the user page
			var derr error
			u, derr = svc.UpdateUser(ctx, service.ActorForUser(out["admin"], ""), u.ID, service.UserInput{Active: ptr(false),
				StatusReason: ptr("Left the company.")})
			must(derr)
		}
		members = append(members, u)
	}

	groupTags := map[string][]string{"Engineering": {"team:eng", "marketplace:seller"}, "Finance": {"dept:finance"}}
	for i, g := range []string{"Engineering", "Design", "Finance", "Support", "Everyone"} {
		gin := service.GroupInput{DisplayName: ptr(g)}
		if t, ok := groupTags[g]; ok {
			gin.Tags = &t
		}
		grp, err := svc.CreateGroup(ctx, sys, acme.ID, gin)
		must(err)
		for j, u := range members {
			if (i+j)%3 == 0 || g == "Everyone" {
				must(svc.SetMembership(ctx, sys, grp.ID, u.ID, true))
			}
		}
	}

	// Providers first, so tenants can pick among them.
	sso, err := svc.CreateProvider(ctx, sys, acme.ID, service.ProviderInput{Type: ptr(model.ProviderOIDC), Name: ptr("Acme SSO"), Issuer: ptr("https://login.acme.example"),
		ClientID: ptr("acme-quisora"), ClientSecret: ptr("s3cret-value"), AllowedDomains: &[]string{"acme.example"}, AutoProvision: ptr(true)})
	must(err)
	_, err = svc.CreateProvider(ctx, sys, acme.ID, service.ProviderInput{Type: ptr(model.ProviderGitHub), Name: ptr("GitHub"), ClientID: ptr("gh-client"),
		ClientSecret: ptr("gh-secret"), Enabled: ptr(false)})
	must(err)
	_, err = svc.CreateProvider(ctx, sys, acme.ID, service.ProviderInput{Type: ptr(model.ProviderOIDC), Name: ptr("Partner directory"), Issuer: ptr("https://id.partner.example"),
		ClientID: ptr("acme-partner"), ClientSecret: ptr("partner-secret")})
	must(err)
	// The other preset types, off so the sign-in page keeps its two buttons.
	_, err = svc.CreateProvider(ctx, sys, acme.ID, service.ProviderInput{Type: ptr(model.ProviderMicrosoft), Tenant: ptr("organizations"),
		AllowedTenants: &[]string{"72f988bf-86f1-41af-91ab-2d7cd011db47"}, ClientID: ptr("ms-client"), ClientSecret: ptr("ms-secret"), Enabled: ptr(false)})
	must(err)
	_, err = svc.CreateProvider(ctx, sys, acme.ID, service.ProviderInput{Type: ptr(model.ProviderGoogle), ClientID: ptr("g-client.apps.googleusercontent.com"),
		ClientSecret: ptr("g-secret"), Enabled: ptr(false)})
	must(err)

	// Tenants: "default" exists already; add a staff tenant (SSO only, MFA) and a customer tenant (password + passkey).
	tenant := func(name, display, desc string, set model.TenantSettings) *model.Tenant {
		t, err := svc.CreateTenant(ctx, sys, acme.ID, service.TenantInput{Name: ptr(name), DisplayName: ptr(display), Description: ptr(desc), Settings: &set})
		must(err)
		return t
	}
	staff := tenant("staff", "Staff tools", "Internal applications for employees",
		model.TenantSettings{PasswordLogin: false, PasskeyLogin: true, Providers: []string{sso.ID}, RequireMFA: true})
	customers := tenant("customers", "Customer apps", "Public-facing applications",
		model.TenantSettings{PasswordLogin: true, PasskeyLogin: true, AllProviders: true})
	_ = tenant("partners", "Partners", "", model.TenantSettings{PasswordLogin: true, AllProviders: true})
	curTenant := customers.ID

	client := func(name, desc, method string, grants []string, uris []string) *model.Client {
		in := service.ClientInput{TenantID: ptr(curTenant), Name: ptr(name), Description: ptr(desc), AuthMethod: ptr(method), GrantTypes: &grants, RedirectURIs: &uris}
		c, _, err := svc.CreateClient(ctx, sys, acme.ID, in)
		must(err)
		return c
	}
	portal := client("Customer portal", "Server-rendered web app", "client_secret_post", []string{"authorization_code", "refresh_token"}, []string{"https://portal.acme.example/callback"})
	client("Billing API", "Machine-to-machine", "client_secret_basic", []string{"client_credentials"}, nil)
	mobile := client("Mobile app", "iOS and Android", "none", []string{"authorization_code", "refresh_token"}, []string{"com.acme.app:/callback"})
	// Alan signed in through Acme SSO and allowed two applications (the user page's connections cards).
	alan := out["user"]
	must(svc.Identities.Create(ctx, model.NewIdentity(alan, sso, "acme-alan", "alan@acme.example", "provision")))
	for _, c := range []*model.Client{portal, mobile} {
		must(svc.Grants.Create(ctx, &model.Grant{UserID: alan.ID, OrgID: acme.ID, ClientID: c.ID, SessionID: "demo-" + c.ID,
			Scopes: []string{"openid", "profile", "email", "offline_access"}}))
	}
	client("Docs single-page app", "Public SPA with PKCE", "none", []string{"authorization_code", "refresh_token"}, []string{"https://docs.acme.example/cb", "http://localhost:5173/cb"})
	curTenant = staff.ID
	for i := 0; i < 3; i++ {
		client(fmt.Sprintf("Internal tool %d", i+1), "", "client_secret_post", []string{"authorization_code"}, []string{"https://tool.acme.example/cb"})
	}

	// An organization without passwords (passkeys and the organization's sign-in provider only) that requires a second
	// factor everywhere: its tenants do not offer the setting.
	nw, err := svc.CreateOrg(ctx, sys, service.OrgInput{Name: ptr("northwind"), DisplayName: ptr("Northwind Traders"),
		Settings: &model.OrgSettings{PasswordLogin: false, PasskeyLogin: true, RequireMFA: true}})
	must(err)
	_, err = svc.CreateProvider(ctx, sys, nw.ID, service.ProviderInput{Type: ptr(model.ProviderOIDC), Name: ptr("Northwind SSO"),
		Issuer: ptr("https://login.northwind.example"), ClientID: ptr("nw-quisora"), ClientSecret: ptr("nw-secret")})
	must(err)
	mkUser(nw, "nora", "Nora Admin", model.RoleAdmin, true, false)
	pat := mkUser(nw, "pat", "Pat Passkey", model.RoleUser, true, false)
	mkUser(nw, "quinn", "Quinn Newcomer", model.RoleUser, true, false)
	must(svc.Passkeys.Create(ctx, &model.Passkey{UserID: pat.ID, OrgID: nw.ID, Name: "Laptop", CredentialID: secure.RandomBytes(32), PublicKey: secure.RandomBytes(32)}))

	// Signing keys for the keys page (metadata only: the demo has no token endpoint): the previous key, the one
	// signing now and the next one, already published.
	now := time.Now().UTC()
	for _, k := range []*model.SigningKey{
		{Meta: model.Meta{ID: model.NewID()}, Alg: "ES256", NotBefore: now.Add(-45 * 24 * time.Hour), RetireAt: now.Add(-15 * 24 * time.Hour), Expires: now.Add(time.Hour)},
		{Meta: model.Meta{ID: model.NewID()}, Alg: "ES256", NotBefore: now.Add(-15 * 24 * time.Hour), RetireAt: now.Add(15 * 24 * time.Hour), Expires: now.Add(16 * 24 * time.Hour)},
		{Meta: model.Meta{ID: model.NewID()}, Alg: "ES256", NotBefore: now.Add(10 * time.Minute), RetireAt: now.Add(45 * 24 * time.Hour), Expires: now.Add(46 * 24 * time.Hour)},
	} {
		must(svc.Keys.Create(ctx, k))
	}
	return out, byName
}

// publishing feeds the live-update hub from every write, as the clustered application does through its change hook.
type publishing struct {
	store.Store
	hub *events.Hub
}

func (p *publishing) Put(ctx context.Context, rec *store.Record) error {
	err := p.Store.Put(ctx, rec)
	if err == nil {
		p.hub.Publish(rec)
	}
	return err
}

func (p *publishing) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	err := p.Store.CompareAndPut(ctx, rec, expect)
	if err == nil {
		p.hub.Publish(rec)
	}
	return err
}

func (p *publishing) PutReplicated(ctx context.Context, rec *store.Record) (bool, []string, error) {
	applied, losers, err := p.Store.PutReplicated(ctx, rec)
	if applied {
		p.hub.Publish(rec)
	}
	return applied, losers, err
}
