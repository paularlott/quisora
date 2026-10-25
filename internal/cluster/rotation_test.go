package cluster

import (
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// A master key rotation across a three-node gossip cluster, following the documented procedure one node at a time
// (docs/RUNNING.md, "Rotating the master key"): secrets sealed on any node at any step open on every other node of
// the same or the next step; the re-seal brings every secret on every node under the new key; and once the old key
// is removed everywhere, every secret opens with the new key alone and none with the old key alone.
func TestMasterKeyRotationAcrossCluster(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	k0, k1 := secure.RandomBytes(32), secure.RandomBytes(32)
	ring := func(active []byte, prev ...[]byte) *secure.Sealer {
		s, err := secure.NewKeyring(active, prev...)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	svcs := make([]*service.Service, 3)
	restart := func(i int, s *secure.Sealer) { svcs[i] = service.New(cfg, c.nodes[i].st(), s) } // a node restarted with new keys
	for i := range 3 {
		restart(i, ring(k0))
	}

	// Data before the rotation, sealed with the old key on node 0: an organization, a user with an authenticator, a
	// sign-in provider's client secret and a relying party's refresh grant.
	org, err := svcs[0].CreateOrg(bg, service.System, service.OrgInput{Name: ptr("acme")})
	if err != nil {
		t.Fatal(err)
	}
	totp := map[string]string{} // user id -> plaintext
	addTOTP := func(i int, name string) {
		t.Helper()
		var u *model.User
		var err error
		for range 50 { // a fresh write on a node that has not seen everything yet can be refused as stale: retry
			if u, err = svcs[i].CreateUser(bg, service.System, org.ID, service.UserInput{Username: ptr(name),
				Email: ptr(name + "@example.com"), GivenName: ptr(name)}); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("create %s on node %d: %v", name, i, err)
		}
		plain := "totp-" + name
		u.TOTPSecret = svcs[i].Sealer.SealFor(service.TOTPBinding(u.ID), []byte(plain))
		if err := svcs[i].Users.Update(bg, u); err != nil {
			t.Fatalf("seal %s on node %d: %v", name, i, err)
		}
		totp[u.ID] = plain
	}
	addTOTP(0, "before")
	p, err := svcs[0].CreateProvider(bg, service.System, org.ID, service.ProviderInput{Type: ptr(model.ProviderOIDC),
		Name: ptr("SSO"), Issuer: ptr("https://sso.example.com"), ClientID: ptr("cid"), ClientSecret: ptr("provider-secret")})
	if err != nil {
		t.Fatal(err)
	}
	g := &model.Grant{ClientID: "c", UserID: "u", OrgID: org.ID, SessionID: "s", Expires: time.Now().Add(time.Hour)}
	g.ID = model.NewID()
	svcs[0].NewGrantKey(g)
	if err := svcs[0].Grants.Create(bg, g); err != nil {
		t.Fatal(err)
	}
	grantKey, _ := svcs[0].Sealer.OpenFor(service.GrantKeyBinding(g.ID), g.Key)

	// opensEverywhere waits until every node opens every secret with its own keyring, and (when want is set) holds
	// each sealed with the key want names.
	opensEverywhere := func(step string, want string) {
		t.Helper()
		waitFor(t, 20*time.Second, step, func() bool {
			for _, s := range svcs {
				for id, plain := range totp {
					u, err := s.Users.Get(bg, id)
					if err != nil {
						return false
					}
					if v, err := s.Sealer.OpenFor(service.TOTPBinding(id), u.TOTPSecret); err != nil || string(v) != plain {
						return false
					}
					if want != "" && s.Sealer.Stale(u.TOTPSecret) {
						return false
					}
				}
				pp, err := s.Providers.Get(bg, p.ID)
				if err != nil {
					return false
				}
				if v, err := s.Sealer.OpenFor(service.ProviderSecretBinding(p.ID), pp.ClientSecret); err != nil || string(v) != "provider-secret" {
					return false
				}
				gg, err := s.Grants.Get(bg, g.ID)
				if err != nil {
					return false
				}
				if key, err := s.GrantRefreshKey(gg); err != nil || string(key) != string(grantKey) {
					return false
				}
				if want != "" && (s.Sealer.Stale(pp.ClientSecret) || s.Sealer.Stale(gg.Key)) {
					return false
				}
			}
			return true
		})
	}
	opensEverywhere("the old key, before the rotation", "")

	// Step 2, one node at a time: the new key added as a previous key. Node 2 seals with the old key still.
	for i := range 3 {
		restart(i, ring(k0, k1))
	}
	addTOTP(2, "step2")
	opensEverywhere("step 2", "")

	// Step 3, rolled out node by node: while node 2 is still at step 2, nodes 0 and 1 seal with the new key and node 2
	// with the old one, and every node opens both.
	restart(0, ring(k1, k0))
	restart(1, ring(k1, k0))
	addTOTP(1, "step3new")
	addTOTP(2, "step3old")
	opensEverywhere("step 3 half rolled out", "")
	restart(2, ring(k1, k0))

	// The housekeeping leader (node 0 here) re-seals in passes until one finds nothing left. A pass works from this
	// node's copies: a value it has not received yet, or one changed meanwhile, waits for the next pass.
	waitFor(t, 30*time.Second, "the re-seal to finish", func() bool {
		r, err := svcs[0].ResealSecrets(bg, 1000)
		return err == nil && r.Done()
	})
	opensEverywhere("every secret re-sealed with the new key, on every node", secure.KeyID(k1))

	// Step 4: the old key removed everywhere. Every secret opens with the new key alone; nothing opens with the old.
	for i := range 3 {
		restart(i, ring(k1))
	}
	opensEverywhere("the old key removed", secure.KeyID(k1))
	old := ring(k0)
	for i, tn := range c.nodes {
		us, _, _ := store.NewTable[model.User](tn.st()).List(bg, store.ListQuery{Scope: org.ID})
		for _, u := range us {
			if u.TOTPSecret == "" {
				continue
			}
			if _, err := old.OpenFor(service.TOTPBinding(u.ID), u.TOTPSecret); err == nil {
				t.Fatalf("node %d: %s still opens with the old key", i, u.Username)
			}
		}
	}
	if r, err := svcs[1].ResealSecrets(bg, 1000); err != nil || !r.Done() || r.Resealed != 0 {
		t.Fatalf("a pass after the rotation on another node: %+v %v", r, err)
	}
}

func ptr[T any](v T) *T { return &v }
