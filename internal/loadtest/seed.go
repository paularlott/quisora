package loadtest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// baseMs is the millisecond timestamp (2025-01-01) that deterministic UUIDv7-shaped ids count up from, so the
// seeded records sort in creation order like real ones.
const baseMs = 1735689600000

// detID returns a deterministic UUIDv7-shaped id: a 48-bit "timestamp" of baseMs + org<<20 + local (so ids sort by
// organization, then creation order) and 74 bits derived from label.
func detID(label string, org, local int) string {
	h := sha256.Sum256([]byte(label))
	var u uuid.UUID
	copy(u[:], h[:16])
	ms := uint64(baseMs) + uint64(org)<<20 + uint64(local)
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], ms)
	copy(u[0:6], t[2:8])
	u[6] = 0x70 | u[6]&0x0f
	u[8] = 0x80 | u[8]&0x3f
	return u.String()
}

func orgID(i int) string { return detID("org|"+OrgName(i), i, 1<<20-1) }

func (o *SeedOptions) groupID(org, g int) string {
	return detID(fmt.Sprintf("group|%d|%d", org, g), org, o.Users+g)
}

func (o *SeedOptions) clientID(org, c int) string {
	return model.ClientIDFromUUID(uuid.MustParse(detID(fmt.Sprintf("client|%d|%d", org, c), org, o.Users+o.Groups+c)))
}

// seededTenants are the tenants every seeded org gets, in creation order.
var seededTenants = []struct{ Name, Display string }{{model.DefaultTenantName, "Default"}, {"apps", "Apps"}}

func (o *SeedOptions) tenantID(org, t int) string {
	return detID(fmt.Sprintf("tenant|%d|%d", org, t), org, o.Users+o.Groups+o.Clients+t)
}

// clientTenant is the index into seededTenants of client c: the first two clients (the web app and the service
// client) belong to the default tenant, the rest to "apps".
func clientTenant(c int) int {
	if c >= 2 {
		return 1
	}
	return 0
}

func (o *SeedOptions) userID(org, u int) string {
	return detID(fmt.Sprintf("user|%d|%d", org, u), org, u)
}

// clientSecret is deterministic so a resumed run (or a data file regenerated later) agrees with the stored hash.
func clientSecret(org, c int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("loadtest-client-secret|%d|%d", org, c)))
	return "qsrs_" + base64.RawURLEncoding.EncodeToString(h[:])
}

func grantID(n int) string { return detID(fmt.Sprintf("grant|%d", n), n%99999+1, 1<<20-2) }

func grantSecret(id string) []byte {
	h := sha256.Sum256([]byte("loadtest-grant-secret|" + id))
	return h[:]
}

var refreshEnc = base64.RawURLEncoding

// SeedSummary reports what a seed run did.
type SeedSummary struct {
	OrgsCreated, OrgsSkipped int
	Records                  int64 // records written in this run
	Users                    int64
	Grants                   int64
	Elapsed                  time.Duration
}

// RecordsPerSec is the write rate of the run.
func (s *SeedSummary) RecordsPerSec() float64 {
	if s.Elapsed <= 0 {
		return 0
	}
	return float64(s.Records) / s.Elapsed.Seconds()
}

type seeder struct {
	svc     *service.Service
	o       SeedOptions
	hash    string
	records atomic.Int64
	users   atomic.Int64
	grants  atomic.Int64
	orgsOK  atomic.Int64
	skipped atomic.Int64
}

// exists reports whether err only says the record is already there (a resumed run).
func exists(err error) bool {
	return errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrConflict)
}

// Seed fills the store behind svc with o.Orgs organizations. It is safe to run again: organizations are created
// last, in a deterministic order with deterministic ids, so an organization that already exists is skipped and one
// that was interrupted is completed. Records are written through the service's typed tables (the same Create path
// the API uses) but without per-record audit events and with one shared password hash.
func Seed(ctx context.Context, svc *service.Service, o SeedOptions, out io.Writer) (*SeedSummary, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	start := time.Now()
	s := &seeder{svc: svc, o: o}
	if svc.Cfg.Cluster.Bind != "" { // before anything is written: a node that has run cannot be seeded
		if err := cluster.CheckNewCluster(svc.Cfg.Server.DataDir, svc.Store); err != nil {
			return nil, err
		}
	}

	adminTok, err := s.bootstrap(ctx)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	h, err := svc.Hasher.Hash(ctx, "", o.Password)
	if err != nil {
		return nil, err
	}
	s.hash = h
	fmt.Fprintf(out, "seeding %d orgs x %d users (%d groups, %d clients per org), %d workers\n", o.Orgs, o.Users, o.Groups,
		o.Clients, o.Workers)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		var lastN int64
		last := start
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				n := s.records.Load()
				done := s.orgsOK.Load() + s.skipped.Load()
				rate := float64(n-lastN) / now.Sub(last).Seconds()
				lastN, last = n, now
				eta := "?"
				if c := s.orgsOK.Load(); c > 0 {
					rem := float64(int64(o.Orgs)-done) * now.Sub(start).Seconds() / float64(c)
					eta = (time.Duration(rem) * time.Second).Round(time.Second).String()
				}
				fmt.Fprintf(out, "  %d/%d orgs, %d records, %.0f records/s, eta %s\n", done, o.Orgs, n, rate, eta)
			}
		}
	}()

	work := make(chan int)
	var wg sync.WaitGroup
	var firstErr error
	var once sync.Once
	fail := func(err error) { once.Do(func() { firstErr = err; cancel() }) }
	for range o.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				if err := s.seedOrg(ctx, i); err != nil {
					fail(fmt.Errorf("%s: %w", OrgName(i), err))
					return
				}
			}
		}()
	}
feed:
	for i := 1; i <= o.Orgs; i++ {
		select {
		case work <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	if firstErr != nil {
		cancel()
		<-progressDone
		return nil, firstErr
	}

	if err := s.seedGrants(ctx); err != nil {
		cancel()
		<-progressDone
		return nil, fmt.Errorf("grants: %w", err)
	}
	cancel()
	<-progressDone

	// A gossip node's records must be writes of their partitions to reach the other nodes: the seeded node becomes the
	// first node of a new cluster, and the others, started with empty databases, copy everything from it.
	if svc.Cfg.Cluster.Bind != "" {
		fmt.Fprintln(out, "gossip node: making the seeded records the first writes of their partitions")
		if err := cluster.StartNewCluster(context.WithoutCancel(ctx), svc.Cfg.Server.DataDir, svc.Store); err != nil {
			return nil, fmt.Errorf("starting the cluster: %w", err)
		}
	}

	sum := &SeedSummary{OrgsCreated: int(s.orgsOK.Load()), OrgsSkipped: int(s.skipped.Load()), Records: s.records.Load(),
		Users: s.users.Load(), Grants: s.grants.Load(), Elapsed: time.Since(start)}
	fmt.Fprintf(out, "done: %d orgs created, %d already present; %d records (%d users, %d grants) in %s = %.0f records/s\n",
		sum.OrgsCreated, sum.OrgsSkipped, sum.Records, sum.Users, sum.Grants, sum.Elapsed.Round(time.Millisecond),
		sum.RecordsPerSec())
	if o.DataFile != "" {
		d := s.dataFile(adminTok)
		if err := d.Save(o.DataFile); err != nil {
			return sum, err
		}
		fmt.Fprintf(out, "wrote %s (%d org samples, %d refresh tokens)\n", o.DataFile, len(d.Samples), len(d.Grants))
	}
	return sum, nil
}

// bootstrap makes sure the primary org and its super admin exist and returns a fresh API token for that admin.
func (s *seeder) bootstrap(ctx context.Context) (string, error) {
	if _, _, err := s.svc.Bootstrap(ctx, s.svc.Cfg.Server.BootstrapAdmin); err != nil {
		return "", err
	}
	primary, err := s.svc.PrimaryOrg(ctx)
	if err != nil {
		return "", err
	}
	adminEmail := s.svc.Cfg.Server.BootstrapAdmin
	if adminEmail == "" {
		adminEmail = "admin@example.com"
	}
	admin, err := s.svc.FindUserByEmail(ctx, primary.ID, adminEmail)
	if err != nil {
		return "", err
	}
	_, tok, err := s.svc.CreateAPIToken(ctx, service.ActorForUser(admin, ""), service.APITokenInput{Name: "loadtest " + time.Now().Format("20060102-150405"),
		Scopes: []string{service.ScopeAdmin, service.ScopeSCIM}})
	return tok, err
}

func (s *seeder) put(err error) error {
	if err == nil {
		s.records.Add(1)
		return nil
	}
	if exists(err) {
		return nil
	}
	return err
}

var webScopes = []string{"openid", "profile", "email", "groups"}

func (s *seeder) seedOrg(ctx context.Context, i int) error {
	name := OrgName(i)
	if _, err := s.svc.Orgs.GetByUnique(ctx, model.OrgNameKey(name)); err == nil {
		s.skipped.Add(1)
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	o := &s.o
	oid := orgID(i)
	now := time.Now().UTC()

	groups := make([]string, o.Groups)
	for g := range o.Groups {
		groups[g] = o.groupID(i, g)
		gr := &model.Group{Meta: model.Meta{ID: groups[g], Created: now}, OrgID: oid, DisplayName: fmt.Sprintf("group-%02d", g+1)}
		if err := s.put(s.svc.Groups.Create(ctx, gr)); err != nil {
			return err
		}
	}
	for t, st := range seededTenants {
		tn := &model.Tenant{Meta: model.Meta{ID: o.tenantID(i, t), Created: now}, OrgID: oid, Name: st.Name,
			DisplayName: st.Display, Settings: model.DefaultTenantSettings()}
		if err := s.put(s.svc.Tenants.Create(ctx, tn)); err != nil {
			return err
		}
	}
	for c := range o.Clients {
		cl := &model.Client{Meta: model.Meta{ID: o.clientID(i, c), Created: now}, OrgID: oid, Enabled: true,
			TenantID:   o.tenantID(i, clientTenant(c)),
			AuthMethod: model.AuthMethodSecretPost,
			SecretHash: string(secure.HashSecret(clientSecret(i, c)))}
		switch c {
		case 1:
			cl.Name = "service"
			cl.GrantTypes = []string{"client_credentials"}
			cl.Scopes = []string{"read"}
		default:
			cl.Name = fmt.Sprintf("web-%d", c+1)
			cl.RedirectURIs = []string{"https://app" + fmt.Sprint(c) + "." + name + ".test/callback"}
			cl.PostLogoutURIs = []string{"https://app" + fmt.Sprint(c) + "." + name + ".test/"}
			cl.GrantTypes = []string{"authorization_code", "refresh_token"}
			cl.Scopes = webScopes
		}
		if err := s.put(s.svc.Clients.Create(ctx, cl)); err != nil {
			return err
		}
	}
	for u := 1; u <= o.Users; u++ {
		un := UserName(u)
		role := model.RoleUser
		switch u {
		case 1:
			role = model.RoleAdmin
		case 2:
			role = model.RoleManager
		}
		usr := &model.User{Meta: model.Meta{ID: o.userID(i, u), Created: now}, OrgID: oid, Username: un,
			Email: UserEmail(name, u), EmailVerified: true,
			GivenName: "User", FamilyName: fmt.Sprintf("%04d", u), Role: role, Active: true, Locale: "en"}
		usr.PasswordHash = s.svc.SealPasswordHash(usr.ID, s.hash) // one hash for every user: sealing per user is cheap
		if err := s.put(s.svc.Users.Create(ctx, usr)); err != nil {
			return err
		}
		s.users.Add(1)
		if o.Groups > 0 && (u-1)%100 < o.MemberPct {
			g := groups[(u-1)%o.Groups]
			m := &model.Member{Meta: model.Meta{ID: model.MemberID(g, usr.ID), Created: now}, GroupID: g, UserID: usr.ID, OrgID: oid}
			if err := s.put(s.svc.Members.Create(ctx, m)); err != nil {
				return err
			}
		}
		if u%256 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
	}
	org := &model.Org{Meta: model.Meta{ID: oid, Created: now}, Name: name, DisplayName: fmt.Sprintf("Organization %05d", i),
		Settings: model.DefaultOrgSettings()}
	if err := s.put(s.svc.Orgs.Create(ctx, org)); err != nil {
		return err
	}
	s.orgsOK.Add(1)
	return nil
}

// grantTarget picks the organization and user of grant n: spread evenly over all orgs and users.
func (s *seeder) grantTarget(n int) (org, user int) {
	return n*7919%s.o.Orgs + 1, n*104729%s.o.Users + 1
}

func (s *seeder) seedGrants(ctx context.Context) error {
	o := &s.o
	var wg sync.WaitGroup
	next := atomic.Int64{}
	errc := make(chan error, o.Workers)
	for range o.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := int(next.Add(1)) - 1
				if n >= o.Grants || ctx.Err() != nil {
					return
				}
				org, usr := s.grantTarget(n)
				id := grantID(n)
				// seeded grants have no browser session behind them: they are offline grants (offline_access)
				scopes := []string{"openid", "profile", "email", "offline_access"}
				if n%2 == 1 {
					scopes = append(append([]string{}, webScopes...), "offline_access")
				}
				now := time.Now().UTC()
				g := &model.Grant{Meta: model.Meta{ID: id, Created: now}, ClientID: o.clientID(org, 0), UserID: o.userID(org, usr),
					OrgID: orgID(org), SessionID: id, Scopes: scopes, AMR: []string{"pwd"}, AuthTime: now,
					Key:     s.svc.Sealer.SealFor(service.GrantKeyBinding(id), grantSecret(id)),
					Expires: now.Add(s.svc.Cfg.Tokens.Refresh())}
				if err := s.svc.Grants.Create(ctx, g); err != nil {
					if exists(err) {
						continue
					}
					errc <- err
					return
				}
				s.records.Add(1)
				s.grants.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errc)
	return <-errc
}

func (s *seeder) dataFile(adminTok string) *Data {
	o := &s.o
	d := &Data{Orgs: o.Orgs, Users: o.Users, Password: o.Password, APIToken: adminTok}
	step := float64(o.Orgs) / float64(o.Sample)
	for k := range o.Sample {
		i := int(float64(k)*step) + 1
		sm := OrgSample{Org: OrgName(i), OrgID: orgID(i), WebID: o.clientID(i, 0), WebSec: clientSecret(i, 0)}
		for t, st := range seededTenants {
			sm.Tenants = append(sm.Tenants, TenantSample{Name: st.Name, ID: o.tenantID(i, t)})
		}
		if o.Clients > 1 {
			sm.CCID, sm.CCSecret = o.clientID(i, 1), clientSecret(i, 1)
		}
		d.Samples = append(d.Samples, sm)
	}
	for n := range o.Grants {
		org, _ := s.grantTarget(n)
		id := grantID(n)
		d.Grants = append(d.Grants, GrantSample{Token: id + "." + refreshEnc.EncodeToString(grantSecret(id)),
			Org: OrgName(org), ClientID: o.clientID(org, 0), Secret: clientSecret(org, 0), Groups: n%2 == 1})
	}
	return d
}
