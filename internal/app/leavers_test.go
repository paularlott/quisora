package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

// The leaver check replays refresh tokens to providers one request at a time, and a provider that does not answer
// holds it for as long as the client waits. It must not hold up the housekeeping tasks that are due on time: here a
// provider accepts the connection and says nothing while a user's end date passes, and the user is still disabled
// within the housekeeping interval.
func TestSlowProviderDoesNotDelayHousekeeping(t *testing.T) {
	saved := housekeepingEvery
	housekeepingEvery = time.Second
	t.Cleanup(func() { housekeepingEvery = saved })

	// The provider: accepts connections and never answers (the TLS handshake waits for it).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	c := config.Default()
	c.Server.Listen, c.Server.PublicURL, c.Server.DataDir, c.Storage.Backend = addr, "https://"+addr, t.TempDir(), "sqlite"
	c.Server.MasterKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	c.Server.AllowPrivateNetworks = true
	c.Limits.PasswordWorkers = 2
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Bootstrap(context.Background(), c, logger.NewNullLogger()); err != nil {
		t.Fatal(err)
	}
	n := &rotNode{cfg: c}
	n.start(t)
	ctx := context.Background()
	svc := n.app.Svc
	org, err := svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Users signed in through providers (a refresh token kept, a live session). Each provider is a separate wait of
	// the client's handshake timeout, as one that did not answer parks the identities that share it for the run.
	for i := range 4 {
		name := fmt.Sprintf("lee%d", i)
		p, err := svc.CreateProvider(ctx, service.System, org.ID, service.ProviderInput{Type: ptr(model.ProviderOIDC),
			Name: ptr("SSO " + name), Issuer: ptr("https://" + ln.Addr().String() + "/" + name), ClientID: ptr("cid"), ClientSecret: ptr("s3cret")})
		if err != nil {
			t.Fatal(err)
		}
		lee, err := svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: ptr(name), Email: ptr(name + "@example.com"), GivenName: ptr(name)})
		if err != nil {
			t.Fatal(err)
		}
		id := model.NewIdentity(lee, p, name+"-sub", name+"@example.com", "admin")
		id.ID = model.NewID() // (the token is sealed to it)
		id.Refresh = svc.Sealer.SealFor(service.IdentityRefreshBinding(id.ID), []byte("refresh-token"))
		id.RefreshChecked = time.Now().Add(-48 * time.Hour)
		if err := svc.Identities.Create(ctx, id); err != nil {
			t.Fatal(err)
		}
		sess := &model.Session{UserID: lee.ID, OrgID: org.ID, Provider: p.ID, AuthTime: time.Now(), LastSeen: time.Now(),
			Expires: time.Now().Add(24 * time.Hour)}
		if err := svc.Sessions.Create(ctx, sess); err != nil {
			t.Fatal(err)
		}
	}
	// A user whose end date is still far off.
	pat, err := svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: ptr("pat"), Email: ptr("pat@example.com"), GivenName: ptr("pat"),
		ValidUntil: ptr(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))})
	if err != nil {
		t.Fatal(err)
	}

	// Restart, so that the first housekeeping pass (and the first leaver check) find the data.
	n.restart(t, c.Server.MasterKey)
	svc = n.app.Svc
	deadline := time.Now().Add(20 * time.Second)
	for accepted.Load() == 0 { // the leaver check is waiting for the provider
		if time.Now().After(deadline) {
			t.Fatal("the leaver check never called the provider")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := svc.UpdateUser(ctx, service.System, pat.ID, service.UserInput{ValidUntil: ptr("2000-01-01")}); err != nil {
		t.Fatal(err)
	}
	// The next housekeeping pass is a second away; the provider's silence lasts as long as the client waits (five
	// seconds for each of the four providers), so a pass held up by it would not come in time.
	deadline = time.Now().Add(6 * time.Second)
	for {
		if u, err := svc.Users.Get(ctx, pat.ID); err == nil && !u.Active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a user past their end date was not disabled while a provider did not answer: housekeeping is held up")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
