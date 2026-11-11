package cluster

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// promotionGate runs beforeDelete once, just before the deletion of user id is written.
type promotionGate struct {
	store.Store
	id           string
	fired        atomic.Bool
	beforeDelete func()
}

func (g *promotionGate) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	if r.Deleted && r.Kind == model.KindUser && r.ID == g.id && g.fired.CompareAndSwap(false, true) {
		g.beforeDelete()
	}
	return g.Store.CompareAndPut(ctx, r, expected)
}

// A deletion decided on a copy read before the user was made a super admin is refused by the owner of the record,
// not applied unchecked: the rank rules (only a super admin deletes a super admin) were judged on the older copy.
func TestDeletionRefusesACopyPromotedMeanwhile(t *testing.T) {
	c := started(t, badgerBackend())
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(cfg, c.nodes[0].st(), sealer)
	root, _, err := svc.Bootstrap(bg, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, root.ID, func(u *model.User) bool { return u.Role == model.RoleSuperAdmin && u.Active })
	primary, err := svc.PrimaryOrg(bg)
	if err != nil {
		t.Fatal(err)
	}
	super := model.RoleSuperAdmin
	makeUser := func(name string, role model.Role) *model.User {
		email := name + "@example.test"
		u, err := svc.CreateUser(bg, service.System, primary.ID, service.UserInput{Username: &name, GivenName: &name,
			Email: &email, Role: &role})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	admin := makeUser("admin", model.RoleAdmin)
	target := makeUser("target", model.RoleUser)
	gate := &promotionGate{Store: svc.Users.S, id: target.ID}
	gate.beforeDelete = func() { // an ordinary administrator's deletion, decided before the promotion
		if _, err := svc.UpdateUser(bg, service.System, target.ID, service.UserInput{Role: &super}); err != nil {
			t.Error(err)
		}
	}
	svc.Users.S = gate
	if err := svc.DeleteUser(bg, service.ActorForUser(admin, ""), target.ID); err == nil {
		t.Fatal("an ordinary administrator deleted a user made a super admin meanwhile, unchecked")
	}
	if u, err := users(c.nodes[0]).Get(bg, target.ID); err != nil || u.Role != model.RoleSuperAdmin {
		t.Fatalf("the promoted user after the refused deletion: %v %v", u, err)
	}
}

// oidcSite is one node's service and OpenID provider, as the application wires them.
type oidcSite struct {
	svc *service.Service
	op  *oidc.Provider
	h   http.Handler
}

// oidcSites builds a service and an OpenID provider over every node's store, sharing one master key.
func oidcSites(t *testing.T, c *tcluster) []*oidcSite {
	t.Helper()
	key := secure.RandomBytes(32)
	sealer, err := secure.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]*oidcSite, len(c.nodes))
	for i, tn := range c.nodes {
		cfg := c.config(i, tn.dir)
		cfg.Server.PublicURL = "https://idp.test"
		cfg.Server.MasterKey = base64.StdEncoding.EncodeToString(key)
		cfg.Limits.PasswordWorkers = 2
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		svc := service.New(cfg, tn.st(), sealer)
		srv, err := web.New(cfg, svc, tn.n.EphemeralStore(), logger.NewNullLogger())
		if err != nil {
			t.Fatal(err)
		}
		op := oidc.New(srv)
		srv.Use(op)
		tn.n.OnChange(func(rec *store.Record, _ bool) {
			switch rec.Kind {
			case model.KindClient:
				op.InvalidateClient(rec.ID)
			case model.KindUser:
				op.InvalidateUser(rec.ID)
			case model.KindGrant:
				op.InvalidateGrant(rec.ID)
			case model.KindKey:
				op.Invalidate()
			}
		})
		t.Cleanup(svc.WaitBackground)
		out[i] = &oidcSite{svc: svc, op: op, h: srv.Handler()}
	}
	return out
}

// refresh presents a refresh token at a node's token endpoint, as client cl authenticated by its secret, and returns the
// status and the new refresh token.
func (s *oidcSite) refresh(t *testing.T, cl *model.Client, secret, token string) (int, string) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {cl.ID}, "client_secret": {secret}}
	req := httptest.NewRequest(http.MethodPost, "https://idp.test/o/"+cl.OrgID+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	var out struct {
		Refresh string `json:"refresh_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out.Refresh
}

// A refresh token presented again after the grant rotated past it, on a node whose copy of the grant is a message
// behind, is detected as reuse: the owner refuses the rotation as stale, the node waits until it has applied what the
// owner had (the refusal's position) before it reads the grant again, sees the later counter, revokes the grant and
// audits it. A client that retries, within the grace, the token it presented just before (its answer was lost) on
// another node that is a message behind is answered with the token it missed, not mistaken for reuse.
func TestRefreshReuseOnALaggingNode(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend())
	// (a node a message behind still serves local reads: the window this is about, well within StaleAfter here)
	c.opts = func(o *Options) {
		o.Partition = func(pc *partition.Config) { clustertest.Partition(pc); pc.StaleAfter = time.Minute }
	}
	c.startAll()
	c.waitReady()
	c.waitOwners()
	sites := oidcSites(t, c)
	ctx := context.Background()
	admin, _, err := sites[0].svc.Bootstrap(ctx, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := sites[0].op.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	cl, secret, err := sites[0].svc.CreateClient(ctx, service.ActorForUser(admin, ""), admin.OrgID, service.ClientInput{
		Name: ptrTo("app"), RedirectURIs: &[]string{"https://app.test/cb"},
		GrantTypes: &[]string{"authorization_code", "refresh_token"}, Scopes: &[]string{"openid", "offline_access"},
		FirstParty: ptrTo(true), RotateRefresh: ptrTo(true)})
	if err != nil {
		t.Fatal(err)
	}
	newGrant := func() (*model.Grant, func(counter uint64) string) {
		t.Helper()
		now := time.Now().UTC()
		g := &model.Grant{Meta: model.Meta{ID: model.NewID()}, ClientID: cl.ID, UserID: admin.ID, OrgID: admin.OrgID,
			Scopes: []string{"openid", "offline_access"}, AuthTime: now, Counter: 1, Rotated: now,
			Expires: now.Add(time.Hour), Epoch: admin.SessionEpoch}
		sites[0].svc.NewGrantKey(g)
		if err := sites[0].svc.Grants.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
		key, err := sites[0].svc.GrantRefreshKey(g)
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, 10*time.Second, "the grant everywhere", func() bool {
			for _, s := range sites {
				if _, err := s.svc.Grants.Get(ctx, g.ID); err != nil {
					return false
				}
			}
			return true
		})
		return g, func(n uint64) string {
			c := strconv.FormatUint(n, 10)
			return g.ID + "." + c + "." + base64.RawURLEncoding.EncodeToString(secure.MAC(key, g.ID, c))
		}
	}
	// lagging makes node i miss the partitions' writes (lagBehind), and the owners' heartbeats too: a heartbeat reports
	// what the owner has committed, and a node that hears it is ahead makes its reads wait for it (up to StaleAfter, the
	// staleness gate) instead of serving the copy a message behind that this test is about. Without them it learns it
	// was behind only from the owner's refusal of its rotation, as a node does whose heartbeat has not come yet.
	lagging := func(i int, on bool) {
		c.lagBehind(i, on)
		for j := range c.addrs {
			if j != i {
				c.drop(j, i, on, gossip.PartHeartbeatMsg)
			}
		}
	}
	// presentLagging presents token at node i while node i is a message behind: it misses the grant's latest writes until
	// the owner refuses its own rotation as stale, and catches up from then on.
	presentLagging := func(i int, token string) (int, string) {
		t.Helper()
		n := c.nodes[i].n
		refused := n.stats.refused.Load()
		done := make(chan struct{})
		defer close(done)
		go func() {
			for n.stats.refused.Load() == refused {
				select {
				case <-done:
					return
				case <-time.After(time.Millisecond):
				}
			}
			lagging(i, false)
		}()
		return sites[i].refresh(t, cl, secret, token)
	}

	// The node that lags is neither node 0, where the client rotates its tokens, nor the owner of the grants' partition
	// (whose copy is never behind).
	c.waitSettled()
	lag := 1
	if owner := c.ownerOf(partitionNum(admin.OrgID)); owner != 0 {
		lag = 3 - owner
	}

	// reuse: the grant rotates twice on node 0 while the lagging node misses it; the first token, presented there, ends it
	g, token := newGrant()
	lagging(lag, true)
	for n := uint64(1); n <= 2; n++ {
		if code, next := sites[0].refresh(t, cl, secret, token(n)); code != http.StatusOK || next != token(n+1) {
			t.Fatalf("rotation %d on node 0: %d %q", n, code, next)
		}
	}
	// (its own copy, past the staleness gate: a heartbeat telling it the owner is ahead would make a gated read wait out
	// StaleAfter and refuse, and this checks the test's precondition, not a read a client makes)
	if x, err := store.NewTable[model.Grant](c.nodes[lag].st().inner).Get(ctx, g.ID); err != nil || x.Counter != 1 {
		t.Fatalf("test set-up: node %d must still hold the first counter: %+v %v", lag, x, err)
	}
	if code, next := presentLagging(lag, token(1)); code != http.StatusBadRequest || next != "" {
		t.Fatalf("a reused token on a node a message behind: %d %q", code, next)
	}
	waitFor(t, 10*time.Second, "the grant ended everywhere", func() bool {
		for _, s := range sites {
			if _, err := s.svc.Grants.Get(ctx, g.ID); !errors.Is(err, store.ErrNotFound) {
				return false
			}
		}
		return true
	})
	events, _, err := sites[lag].svc.Audits.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "action",
		Value: "oauth.refresh.reuse"}}})
	if err != nil || len(events) != 1 {
		t.Fatalf("the reuse audited on node %d: %d events, %v", lag, len(events), err)
	}

	// a retry: the client rotated on node 0, lost the answer, and presents the same token again at the other node, a
	// message behind
	g, token = newGrant()
	lagging(lag, true)
	if code, next := sites[0].refresh(t, cl, secret, token(1)); code != http.StatusOK || next != token(2) {
		t.Fatalf("rotation on node 0: %d %q", code, next)
	}
	if code, next := presentLagging(lag, token(1)); code != http.StatusOK || next != token(2) {
		t.Fatalf("a retry within the grace on a node a message behind: %d %q, want the token it missed", code, next)
	}
	if x, err := sites[0].svc.Grants.Get(ctx, g.ID); err != nil || x.Counter != 2 {
		t.Fatalf("the grant after the retry: %+v %v", x, err)
	}
}

func ptrTo[T any](v T) *T { return &v }

// Nodes on different storage backends (BadgerDB, SQLite, memory) hold the same records: a first node bootstrapped as
// "quisora bootstrap" does it, records created, updated, deleted and created again on each, times kept to the
// nanosecond whichever backend keeps the index columns.
func TestMixedBackendsConverge(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	c := newTCluster(t, 3, badgerBackend())
	c.noSeed = true
	c.mks = map[int]backend{1: sqliteBackend(), 2: memBackend()}
	dir0 := t.TempDir()
	st := badgerBackend().open(t, dir0) // "quisora bootstrap" on node 0
	admin, _, err := service.New(cfg, st, sealer).Bootstrap(bg, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	primary := admin.OrgID
	if err := StartNewCluster(bg, dir0, st); err != nil {
		t.Fatal(err)
	}
	st.Close()
	c.nodes = []*tnode{c.build(0, dir0, nil), c.build(1, "", nil), c.build(2, "", nil)}
	t.Cleanup(c.closeAll)
	c.start(c.nodes...)
	c.waitReady()
	same := func(kind model.Kind, id string) func() bool {
		return func() bool {
			var first *store.Record
			for _, tn := range c.nodes {
				r, err := tn.st().Get(bg, kind, id)
				if err != nil {
					return false
				}
				if first == nil {
					first = r
				} else if r.Version != first.Version || r.Epoch != first.Epoch || r.Created != first.Created || string(r.Data) != string(first.Data) {
					return false
				}
			}
			return true
		}
	}
	waitFor(t, 20*time.Second, "bootstrap records everywhere", same(model.KindOrg, primary))
	waitFor(t, 20*time.Second, "bootstrap admin everywhere", same(model.KindUser, admin.ID))
	// The nodes that joined empty know the primary organization from the data set they copied.
	for i, tn := range c.nodes {
		if id, err := service.New(cfg, tn.st(), sealer).PrimaryOrgID(bg); err != nil || id != primary {
			t.Fatalf("node %d: primary organization %q %v, want %q", i, id, err, primary)
		}
	}
	// an update on the sqlite node, a new record on the memory node, then its deletion and re-creation on badger
	svc1 := service.New(cfg, c.nodes[1].st(), sealer)
	org, err := svc1.Orgs.Get(bg, primary)
	if err != nil {
		t.Fatal(err)
	}
	org.DisplayName = "Renamed on sqlite"
	if err := svc1.Orgs.Update(bg, org); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "update converged", same(model.KindOrg, primary))
	svc2 := service.New(cfg, c.nodes[2].st(), sealer)
	created := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC) // nanoseconds: SQL index columns keep microseconds
	g := &model.Group{Meta: model.Meta{ID: model.NewID(), Created: created}, OrgID: primary, DisplayName: "on memory"}
	if err := svc2.Groups.Create(bg, g); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "create converged", same(model.KindGroup, g.ID))
	svc0 := service.New(cfg, c.nodes[0].st(), sealer)
	if err := svc0.Groups.Delete(bg, g.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "deletion converged", func() bool {
		for _, tn := range c.nodes {
			if _, err := tn.st().Get(bg, model.KindGroup, g.ID); err == nil {
				return false
			}
		}
		return true
	})
	again := &model.Group{Meta: model.Meta{ID: g.ID}, OrgID: primary, DisplayName: "created again"}
	if err := svc0.Groups.Create(bg, again); err != nil {
		t.Fatalf("re-creating a deleted id: %v", err)
	}
	waitFor(t, 15*time.Second, "re-creation converged", same(model.KindGroup, g.ID))
	// every node is ready: re-creating a deleted id diverged no partition here. A node starved of CPU (a loaded test
	// run) can briefly have heard no owner of a partition lately, which passes; a divergence stays until an operator acts
	readyWithin(t, 15*time.Second, c.nodes...)
	g2 := &model.Group{Meta: model.Meta{ID: model.NewID(), Created: created}, OrgID: primary, DisplayName: "nanos"}
	if err := svc1.Groups.Create(bg, g2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "created on sqlite, converged", same(model.KindGroup, g2.ID))
	for i, tn := range c.nodes {
		got, err := service.New(cfg, tn.st(), sealer).Groups.Get(bg, g2.ID)
		if err != nil || !got.Created.Equal(created) {
			t.Fatalf("node %d: creation time not kept to the nanosecond: %v %v", i, got, err)
		}
	}
}
