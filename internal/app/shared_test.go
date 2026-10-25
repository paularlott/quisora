package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/paularlott/quisora/internal/store"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/webtest"
)

// Two complete servers on one database server (each of PostgreSQL, MySQL and MariaDB) and no gossip, behind an imaginary load balancer: every step of an
// OAuth sign-in lands on the other node from the one before (flow, sign-in, code, exchange and refresh all cross
// nodes), exactly one node runs housekeeping, and an administrator's change on one node takes effect on the other
// within seconds.
func TestSharedDatabaseNodes(t *testing.T) {
	for _, backend := range []string{"postgres", "mysql", "mariadb"} {
		t.Run(backend, func(t *testing.T) {
			storage := sharedStorage(t, backend)
			key := base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
			var publicURL string
			shared := func(c *config.Config) {
				storage(c)
				c.Server.MasterKey = key
				if publicURL == "" {
					publicURL = c.Server.PublicURL
				}
				c.Server.PublicURL = publicURL // one issuer for the whole cluster
			}
			testSharedNodes(t, backend, shared, func() string { return publicURL })
		})
	}
}

// sharedStorage returns a configuration hook pointing a node at a fresh database on the test
// server for backend, or skips when none is configured.
func sharedStorage(t *testing.T, backend string) func(*config.Config) {
	t.Helper()
	db := "qsr_shared_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	switch backend {
	case "postgres":
		admin := os.Getenv("QUISORA_TEST_POSTGRES_DSN")
		if admin == "" {
			t.Skip("QUISORA_TEST_POSTGRES_DSN not set")
		}
		sdb, err := sql.Open("pgx", admin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sdb.Exec("CREATE DATABASE " + db); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = sdb.Exec("DROP DATABASE " + db + " WITH (FORCE)"); sdb.Close() })
		u, _ := url.Parse(admin)
		u.Path = "/" + db
		return func(c *config.Config) { c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", u.String() }
	default: // mysql, mariadb
		admin := os.Getenv("QUISORA_TEST_" + strings.ToUpper(backend) + "_DSN")
		if admin == "" {
			t.Skipf("QUISORA_TEST_%s_DSN not set", strings.ToUpper(backend))
		}
		cfg, err := mysql.ParseDSN(admin)
		if err != nil {
			t.Fatal(err)
		}
		sdb, err := sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sdb.Exec("CREATE DATABASE " + db); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = sdb.Exec("DROP DATABASE " + db); sdb.Close() })
		cfg.DBName = db
		dsn := cfg.FormatDSN()
		return func(c *config.Config) {
			c.Storage.Backend = backend
			if backend == "mysql" {
				c.Storage.MySQL.DSN = dsn
			} else {
				c.Storage.MariaDB.DSN = dsn
			}
		}
	}
}

func testSharedNodes(t *testing.T, backend string, shared func(*config.Config), public func() string) {
	a, hc, _ := startAppWith(t, backend, shared)
	b, _, _ := startAppWith(t, backend, shared)
	if !a.Node.SharedDatabase() || !b.Node.SharedDatabase() {
		t.Fatal("nodes on a shared database without gossip must run in shared mode")
	}
	crossNodeOAuth(t, []*App{a, b}, hc, public())
}

// crossNodeOAuth runs an OAuth sign-in through apps (nodes of one cluster sharing the public URL), sending each step
// to the next node in turn as a load balancer without sticky sessions might. Then it checks that exactly one node
// leads, that a client disabled on one node stops working on another, and that a replayed code ends the grant.
func crossNodeOAuth(t *testing.T, apps []*App, hc *http.Client, publicURL string) {
	step := 0
	nextNode := func() string { // the listener of the next node, the public URL being the load balancer's
		u := "https://" + apps[step%len(apps)].Cfg.Server.Listen
		step++
		return u
	}
	a, b := apps[0], apps[len(apps)-1]
	ctx := context.Background()

	org, _ := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	webtest.NoTenantMFA(t, a.Svc, org.ID) // jane signs in with a password alone
	if _, err := a.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: ptr("jane"),
		Email: ptr("jane@acme.test"), Password: ptr("correct horse battery")}); err != nil {
		t.Fatal(err)
	}
	cl, secret, err := a.Svc.CreateClient(ctx, service.System, org.ID, service.ClientInput{Name: ptr("app"),
		RedirectURIs: ptr([]string{"https://app.example/cb"}), FirstParty: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil) // one cookie jar for both: cookies ignore ports, like one host behind a balancer
	hc.Jar = jar
	verifier := "a-very-long-pkce-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {cl.ID}, "redirect_uri": {"https://app.example/cb"},
		"scope": {"openid email offline_access"}, "state": {"s1"}, "nonce": {"n1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	get := func(u string) *http.Response {
		t.Helper()
		resp, err := hc.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	// 1. authorize on node 0 → the sign-in page
	resp := get(nextNode() + "/oauth/authorize?" + q.Encode())
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if !strings.HasPrefix(loc, "/login/acme?") {
		t.Fatalf("authorize: %d %s", resp.StatusCode, loc)
	}
	// 2. the sign-in page from node 1
	resp = get(nextNode() + loc)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindSubmatch(page)
	if resp.StatusCode != 200 || m == nil {
		t.Fatalf("login page on the other node: %d", resp.StatusCode)
	}
	lu, _ := url.Parse(loc)
	// 3. password sign-in on node 0
	body, _ := json.Marshal(map[string]string{"org": "acme", "email": "jane@acme.test", "password": "correct horse battery",
		"next": lu.Query().Get("next"), "tenant": lu.Query().Get("tenant")})
	code, out := doJSON(t, hc, "POST", nextNode()+"/api-internal/login/password", map[string]string{"Content-Type": "application/json",
		"X-CSRF-Token": string(m[1]), "Origin": publicURL}, strings.NewReader(string(body)))
	if code != 200 || out["next"] == nil {
		t.Fatalf("password sign-in: %d %v", code, out)
	}
	// 4. the flow resumes on node 1 and issues the code
	resp = get(nextNode() + out["next"].(string))
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	if cb.Query().Get("code") == "" {
		t.Fatalf("resume on the other node: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// 5. the code is exchanged on node 0, once
	form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {"https://app.example/cb"},
		"code_verifier": {verifier}, "client_id": {cl.ID}, "client_secret": {secret}}
	hdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	code, tok := doJSON(t, hc, "POST", nextNode()+"/oauth/token", hdr, strings.NewReader(form.Encode()))
	if code != 200 || tok["refresh_token"] == nil {
		t.Fatalf("code exchange on the other node: %d %v", code, tok)
	}
	// 6. refresh on node 1, userinfo on node 0
	rf := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {cl.ID}, "client_secret": {secret}}
	code, tok2 := doJSON(t, hc, "POST", nextNode()+"/oauth/token", hdr, strings.NewReader(rf.Encode()))
	if code != 200 {
		t.Fatalf("refresh on the other node: %d %v", code, tok2)
	}
	if code, _ := doJSON(t, hc, "GET", nextNode()+"/oauth/userinfo", map[string]string{"Authorization": "Bearer " + tok2["access_token"].(string)}, nil); code != 200 {
		t.Fatalf("userinfo: %d", code)
	}
	// Exactly one node runs housekeeping.
	waitLeaders := time.Now().Add(30 * time.Second)
	for {
		leaders := 0
		for _, n := range apps {
			if n.Node.IsLeader() {
				leaders++
			}
		}
		if leaders == 1 {
			break
		}
		if time.Now().After(waitLeaders) {
			t.Fatalf("%d leaders", leaders)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Disabling the client on one node stops its tokens on the others within seconds.
	if _, err := b.Svc.UpdateClient(ctx, service.System, cl.ID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for _, n := range apps { // every node, not just one
		for {
			code, _ := doJSON(t, hc, "GET", "https://"+n.Cfg.Server.Listen+"/oauth/userinfo",
				map[string]string{"Authorization": "Bearer " + tok2["access_token"].(string)}, nil)
			if code == 401 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("a client disabled on one node still works on %s after 8s: %d", n.Cfg.Server.Listen, code)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	// 7. replaying the code on another node is refused and ends the grant made from it (RFC 6749 §4.1.2)
	if _, err := a.Svc.UpdateClient(ctx, service.System, cl.ID, service.ClientInput{Enabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(8 * time.Second)
	for { // a node may still have the disabled client cached for a few seconds
		code, _ := doJSON(t, hc, "POST", nextNode()+"/oauth/token", hdr, strings.NewReader(form.Encode()))
		if code == 400 {
			break
		}
		if code != 401 || time.Now().After(deadline) {
			t.Fatalf("the code was accepted twice (second time on another node): %d", code)
		}
		time.Sleep(250 * time.Millisecond)
	}
	for { // the grant is gone everywhere; a node may still answer 401 while it has the disabled client cached
		code, _ := doJSON(t, hc, "POST", nextNode()+"/oauth/token", hdr, strings.NewReader(rf.Encode()))
		if code == 400 {
			break
		}
		if code != 401 || time.Now().After(deadline) {
			t.Fatalf("refresh after the code was replayed: %d", code)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Three complete servers, each with its own database, replicating over gossip: the same sign-in across nodes, then
// the cluster keeps serving with one node down (two of three are a majority).
func TestGossipNodes(t *testing.T) {
	addrs := []string{gossipAddr(t), gossipAddr(t), gossipAddr(t)}
	key := base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	ckey := base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	var publicURL string
	var apps []*App
	var hc *http.Client
	// One after another: a process normally runs one server, and start-up sets process-wide state (the record
	// origin, the trusted proxies). The first node waits for its peers to bootstrap; the cluster forms as they come.
	for i := range addrs {
		bootstrapNext = i == 0 // "quisora bootstrap" on the first node only; the others copy from it
		a, h, _ := startAppWith(t, "badgerdb", func(c *config.Config) {
			c.Server.MasterKey = key
			if publicURL == "" {
				publicURL = c.Server.PublicURL
			}
			c.Server.PublicURL = publicURL
			c.Cluster.Bind, c.Cluster.Advertise, c.Cluster.Key, c.Cluster.Peers = addrs[i], addrs[i], ckey, addrs
			c.Cluster.Size = len(addrs)
		})
		apps = append(apps, a)
		if hc == nil {
			hc = h
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for _, a := range apps {
		for {
			if ok, _ := a.Node.Ready(); ok {
				break
			}
			if time.Now().After(deadline) {
				_, why := a.Node.Ready()
				t.Fatalf("node not ready: %s", why)
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !a.Node.Replicating() || a.Node.SharedDatabase() {
			t.Fatal("gossip nodes replicate and keep their own databases")
		}
	}
	crossNodeOAuth(t, apps, hc, publicURL)
	gossipAudit(t, apps)

	// One node down: two of three are a majority, so the others still take changes, and see each other's.
	apps[2].Close()
	ctx := context.Background()
	var org *model.Org
	deadline = time.Now().Add(20 * time.Second)
	for {
		var err error
		if org, err = apps[0].Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("after")}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no write with one node of three down: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	for { // replicated to the other live node (broadcast, or the next anti-entropy pull)
		if got, err := apps[1].Svc.Orgs.Get(ctx, org.ID); err == nil && got.Name == "after" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a write made with one node down did not reach the other live node")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// gossipAddr is a 127.0.0.1 address with both its TCP and UDP port free.
func gossipAddr(t *testing.T) string {
	t.Helper()
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		u, err := net.ListenPacket("udp", addr)
		l.Close()
		if err == nil {
			u.Close()
			return addr
		}
	}
	t.Fatal("no free port")
	return ""
}

// gossipAudit: audit events stay on the node that records them; an audit page read through any node gathers every
// node's events, merged newest first, with offsets.
func gossipAudit(t *testing.T, apps []*App) {
	t.Helper()
	ctx := context.Background()
	primary, err := apps[0].Svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 4 { // node 0, node 1, node 0, node 1
		apps[i%2].Svc.Audit(ctx, nil, primary.ID, "test.gossip", fmt.Sprintf("event-%d", i), nil)
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(time.Second) // several sync rounds: nothing of it may replicate
	if l, _, _ := apps[2].Svc.Audits.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "action", Value: "test.gossip"}}}); len(l) != 0 {
		t.Fatalf("audit events replicated to node 2: %d", len(l))
	}
	q := service.AuditQuery{Action: "test.gossip", Sort: "created", Desc: true, Limit: 2}
	first, err := apps[2].Svc.ListAudit(ctx, service.System, primary.ID, q)
	if err != nil || first.Source != "cluster" || first.Nodes != 3 || first.Answered != 3 || first.Total != 4 ||
		len(first.Items) != 2 || first.Items[0].Target != "event-3" || first.Items[1].Target != "event-2" {
		t.Fatalf("first page through node 2: %+v %v", first, err)
	}
	q.Offset = 2
	second, _ := apps[2].Svc.ListAudit(ctx, service.System, primary.ID, q)
	if len(second.Items) != 2 || second.Items[0].Target != "event-1" || second.Items[1].Target != "event-0" {
		t.Fatalf("second page through node 2: %+v", second.Items)
	}
}
