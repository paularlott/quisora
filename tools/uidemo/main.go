// Command uidemo runs the admin UI over an in-memory store seeded with demo data. It exists for design work and for
// the accessibility audit (web/tests): it serves HTTPS with a self-signed certificate and adds a development-only
// sign-in shortcut, GET /__demo/login?as=super|admin|manager|user|otp|account&next=/path.
//
//	go run ./tools/uidemo -addr 127.0.0.1:18443
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/web"
	"golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18443", "listen address")
	theme := flag.String("theme", "system", "default theme: light, dark or system")
	skin := flag.String("skin", "", "the primary organization's skin (so every organization's): a built-in one (web/skins), or the path of a folder holding skin.css, added as a custom skin named after the folder")
	rotation := flag.Bool("rotation", false, "show a master key rotation in progress (the master key rotation page)")
	clustered := flag.Bool("cluster", false, "show a three-node gossip cluster on the system overview (a made-up status)")
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
	// a secret store, so the system page offers "Read secret stores now" (it reads nothing until that is clicked)
	cfg.Secrets.Vault = config.Vault{Address: "https://vault.demo.invalid", Token: "demo"}
	must(cfg.Validate())

	hub := events.NewHub()
	st := &publishing{Store: memstore.New(), hub: hub}
	oldKey := secure.RandomBytes(32)
	sealer, _ := secure.NewSealer(oldKey)
	svc := service.New(cfg, st, sealer)
	hub.OrgOfUser = func(id string) string {
		if u, err := svc.Users.Get(context.Background(), id); err == nil {
			return u.OrgID
		}
		return ""
	}
	ctx := context.Background()
	super, _, err := svc.Bootstrap(ctx, "admin@example.com")
	must(err)
	demo, byName := seed(ctx, svc, super)
	// The primary organization's own MCP server is on, and a tenant owns its address and accepts AI clients, so its
	// overview lists the address.
	primary, err := svc.Org(ctx, super.OrgID)
	must(err)
	primarySettings := primary.Settings
	primarySettings.MCPServer = true
	_, err = svc.UpdateOrg(ctx, service.System, primary.ID, service.OrgInput{Settings: &primarySettings})
	must(err)
	_, err = svc.CreateTenant(ctx, service.System, super.OrgID, service.TenantInput{Name: ptr("ai"), DisplayName: ptr("AI assistants"),
		Description: ptr("AI clients that manage users through the MCP server"),
		Settings:    &model.TenantSettings{PasswordLogin: true, PasskeyLogin: true, RequireMFA: true, SelfRegistration: true},
		Resources:   &[]string{cfg.OrgMCP(super.OrgID)}})
	must(err)
	if *skin != "" {
		must(demoSkin(ctx, svc, super, *skin))
	}
	if *rotation {
		// Halfway through a rotation: this node seals with a new key, another still with the old one, and the secrets
		// sealed so far are under the old key.
		for _, u := range demo {
			if cur, err := svc.Users.Get(ctx, u.ID); err == nil && cur.TOTPSecret == "" {
				cur.TOTPSecret = sealer.SealFor(service.TOTPBinding(cur.ID), []byte("demo-totp"))
				_ = svc.Users.Update(ctx, cur)
			}
		}
		ring, _ := secure.NewKeyring(secure.RandomBytes(32), oldKey)
		sealer.Replace(ring)
		must(svc.ReportMasterKey(ctx, "0199a1c2-demo-node-one"))
		old, _ := secure.NewKeyring(oldKey)
		must(service.New(cfg, st, old).ReportMasterKey(ctx, "0199a1c2-demo-node-two"))
	}

	eph := ephemeral.NewLocal("demo")
	srv, err := web.New(cfg, svc, eph, logger.NewNullLogger())
	must(err)
	adm := admin.New()
	if *clustered {
		srv.Site.Clustered = true
		adm.ClusterStatus = demoClusterStatus
	}
	srv.Use(adm)
	srv.Use(&events.Module{Hub: hub})
	extraModules(srv, adm)
	srv.NotFound = admin.NotFound(srv)
	srv.Mux.Handle("/", srv.NotFound)
	srv.Mux.HandleFunc("GET /__demo/device-client", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(demoDeviceClient)) })
	srv.Mux.HandleFunc("GET /__demo/login", func(w http.ResponseWriter, r *http.Request) {
		u := demo[r.URL.Query().Get("as")]
		if u == nil {
			http.Error(w, "unknown role", http.StatusBadRequest)
			return
		}
		if fresh, err := svc.Users.Get(r.Context(), u.ID); err == nil {
			u = fresh // as it is now: a session is made in the account's current session epoch
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

// demoDeviceClient is the client id of the demo's device sign-in application (GET /__demo/device-client).
var demoDeviceClient string

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
// Besides the acme users with passwords, it seeds: "iris" (acme, no password yet), "sally" (an acme manager with no
// password or second factor yet, reserved for the browser test that accepts her invitation: accepting one replaces
// every way in and ends the account's sessions, so no test may invite an account others sign in as), and the org
// "northwind" where passwords are off (passkey and the org's sign-in provider only) with "pat" (has a passkey) and
// "quinn" (nothing set up).
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

	byName := map[string]*model.User{}
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
	// a plain user no other browser test signs in as or changes, for tests that check the account page once it has
	// settled: a change to an account others use reloads its lists live (account page), re-rendering them under a check
	out["account"] = user(acme, "dorothy", "Dorothy Vaughan", model.RoleUser, true)
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
	mkUser(acme, "sally", "Sally Ride", model.RoleManager, true, false)
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
	// The primary organization's people sign in to acme as guests: offered after the email form, in its own group.
	_, err = svc.CreateProvider(ctx, sys, acme.ID, service.ProviderInput{Type: ptr(model.ProviderOrganization), SourceOrg: &super.OrgID})
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
		model.TenantSettings{PasswordLogin: true, PasswordReset: true, PasskeyLogin: true, AllProviders: true})
	_ = tenant("partners", "Partners", "", model.TenantSettings{PasswordLogin: true, PasswordReset: true, AllProviders: true})
	servers := tenant("servers", "Servers", "Machines people reach over SSH",
		model.TenantSettings{PasswordLogin: true, PasswordReset: true, PasskeyLogin: true, AllProviders: true})
	seedSSH(ctx, svc, servers, out["user"], members)
	curTenant := customers.ID

	client := func(name, desc, method string, grants []string, uris []string) *model.Client {
		in := service.ClientInput{TenantID: ptr(curTenant), Name: ptr(name), Description: ptr(desc), AuthMethod: ptr(method), GrantTypes: &grants, RedirectURIs: &uris}
		c, _, err := svc.CreateClient(ctx, sys, acme.ID, in)
		must(err)
		return c
	}
	portal := client("Customer portal", "Server-rendered web app", "client_secret_post", []string{"authorization_code", "refresh_token"}, []string{"https://portal.acme.example/callback"})
	billing := client("Billing API", "Machine-to-machine", "client_secret_basic", []string{"client_credentials"}, nil)
	// Acme lets everyone make personal API tokens (an organization starts with none), and two of its applications accept them.
	acmeSettings := model.DefaultOrgSettings()
	acmeSettings.APITokens = model.APITokensEveryone
	_, err = svc.UpdateOrg(ctx, sys, acme.ID, service.OrgInput{Settings: &acmeSettings})
	must(err)
	for _, c := range []*model.Client{portal, billing} {
		_, err = svc.UpdateClient(ctx, sys, c.ID, service.ClientInput{AcceptsAPITokens: ptr(true)})
		must(err)
	}
	mobile := client("Mobile app", "iOS and Android", "none", []string{"authorization_code", "refresh_token"}, []string{"com.acme.app:/callback"})
	// Alan signed in through Acme SSO and allowed two applications (the user page's connections cards).
	alan := out["user"]
	must(svc.Identities.Create(ctx, model.NewIdentity(alan, sso, "acme-alan", "alan@acme.example", "provision")))
	for _, c := range []*model.Client{portal, mobile} {
		must(svc.Grants.Create(ctx, &model.Grant{UserID: alan.ID, OrgID: acme.ID, ClientID: c.ID, SessionID: "demo-" + c.ID,
			Scopes: []string{"openid", "profile", "email", "offline_access"}}))
	}
	client("Docs single-page app", "Public SPA with PKCE", "none", []string{"authorization_code", "refresh_token"}, []string{"https://docs.acme.example/cb", "http://localhost:5173/cb"})
	// Device sign-in (RFC 8628): the tests start one for the /device page and its consent screen.
	tv := client("Lobby display", "Device sign-in", "none", []string{"refresh_token", service.GrantDeviceCode}, nil)
	demoDeviceClient = tv.ID
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

// demoEvict clears the OAuth module's cached copy of a changed record (set by extraModules), as the server's own
// change hooks do: a rotated client secret, say, stops working at once.
var demoEvict func(*store.Record)

func (p *publishing) publish(rec *store.Record) {
	p.hub.Publish(rec)
	if demoEvict != nil {
		demoEvict(rec)
	}
}

func (p *publishing) Put(ctx context.Context, rec *store.Record) error {
	err := p.Store.Put(ctx, rec)
	if err == nil {
		p.publish(rec)
	}
	return err
}

func (p *publishing) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	err := p.Store.CompareAndPut(ctx, rec, expect)
	if err == nil {
		p.publish(rec)
	}
	return err
}

// Tx publishes the records a transaction wrote (not those it only asserted), as the cluster store's change hook does.
func (p *publishing) Tx(ctx context.Context, ops []store.Op) error {
	err := p.Store.Tx(ctx, ops)
	if err == nil {
		for _, op := range ops {
			if !op.Assert {
				p.publish(op.Rec)
			}
		}
	}
	return err
}

func (p *publishing) PutReplicated(ctx context.Context, rec *store.Record) (bool, error) {
	applied, err := p.Store.PutReplicated(ctx, rec)
	if applied {
		p.publish(rec)
	}
	return applied, err
}

// seedSSH turns SSH certificates on for tenant t (user and host CA keys, host certificates for *.acme.example) and
// issues some: ten for members (so the list has a second page), two for "pam" and one for "pia", whose certificates
// browser tests revoke, two for user, one of them revoked, and one for a host.
func seedSSH(ctx context.Context, svc *service.Service, t *model.Tenant, user *model.User, members []*model.User) {
	sys := service.System
	_, err := svc.UpdateTenantSSH(ctx, sys, t.ID, service.SSHSettingsInput{Enabled: ptr(true), HostCerts: ptr(true),
		HostPatterns: &[]string{"*.acme.example"}, PrincipalRoles: ptr(true), SourceAddresses: &[]string{"203.0.113.0/24"}})
	must(err)
	t, err = svc.Tenants.Get(ctx, t.ID)
	must(err)
	newKey := func() string {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		k, err := ssh.NewPublicKey(pub)
		must(err)
		return sshca.AuthorizedKey(k) + " demo@laptop"
	}
	stamp, err := svc.SessionStamp(ctx, t.OrgID)
	must(err)
	issued := 0
	for _, m := range members { // the first ten active users (managers and administrators get none unless the tenant allows it)
		if issued == 10 {
			break
		}
		if m.Role != model.RoleUser || !m.Active {
			continue
		}
		_, err := svc.SignUserSSH(ctx, service.SSHUserRequest{User: m, TenantID: t.ID, ClientID: t.SSH.ClientID, PublicKey: newKey(),
			AMR: []string{"pwd", "otp", "mfa"}, AuthTime: time.Now().Add(-time.Minute), Via: "cli",
			SessionEpoch: m.SessionEpoch, Stamp: stamp})
		must(err)
		issued++
	}
	// users browser tests revoke certificates of (the shared demo keeps the others as they are)
	for _, who := range []struct {
		name  string
		certs int
	}{{"pam", 2}, {"pia", 1}} {
		u, err := svc.CreateUser(ctx, sys, t.OrgID, service.UserInput{Username: ptr(who.name), Email: ptr(who.name + "@acme.example"),
			GivenName: ptr(strings.ToUpper(who.name[:1]) + who.name[1:]), FamilyName: ptr("Tester"), Role: ptr(model.RoleUser), Password: ptr(secure.RandomToken(15))})
		must(err)
		for range who.certs {
			_, err := svc.SignUserSSH(ctx, service.SSHUserRequest{User: u, TenantID: t.ID, ClientID: t.SSH.ClientID, PublicKey: newKey(),
				AMR: []string{"pwd", "otp", "mfa"}, AuthTime: time.Now().Add(-time.Minute), Via: "cli",
				SessionEpoch: u.SessionEpoch, Stamp: stamp})
			must(err)
		}
	}
	var first *model.SSHCert
	for i := range 2 {
		got, err := svc.SignUserSSH(ctx, service.SSHUserRequest{User: user, TenantID: t.ID, ClientID: t.SSH.ClientID, PublicKey: newKey(),
			AMR: []string{"pwd", "otp", "mfa"}, AuthTime: time.Now().Add(-time.Minute), Via: "cli",
			SessionEpoch: user.SessionEpoch, Stamp: stamp})
		must(err)
		if i == 0 {
			first = got.Cert
		}
	}
	must(svc.RevokeSSHCert(ctx, sys, t.OrgID, first.ID))
	_, err = svc.SignHostSSH(ctx, sys, t.ID, service.SSHHostRequest{PublicKey: newKey(), Principals: []string{"web1.acme.example"}})
	must(err)
}

// demoSkin gives the primary organization (and so every organization) skin v: a built-in skin's name, or the path of a
// folder holding skin.css, added first as a custom skin named after the folder (a skin being written can so be tried
// on every page: SKIN=./acme with the Playwright suite).
func demoSkin(ctx context.Context, svc *service.Service, super *model.User, v string) error {
	a := service.ActorForUser(super, "127.0.0.1")
	name := v
	if strings.ContainsRune(v, '/') {
		css, err := os.ReadFile(filepath.Join(v, "skin.css"))
		if err != nil {
			return err
		}
		name = filepath.Base(filepath.Clean(v))
		text := string(css)
		if _, err := svc.CreateSkin(ctx, a, service.SkinInput{Name: &name, CSS: &text}); err != nil {
			return fmt.Errorf("skin %s: %w", v, err)
		}
	}
	id, err := svc.PrimaryOrgID(ctx)
	if err != nil {
		return err
	}
	_, err = svc.UpdateBranding(ctx, a, id, service.BrandingInput{Skin: &name})
	return err
}
