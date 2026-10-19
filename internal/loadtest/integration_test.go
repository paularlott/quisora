package loadtest_test

import (
	"context"
	"encoding/base64"
	"github.com/paularlott/quisora/internal/secure"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/loadtest"
)

func TestSeedAndRunEveryScenario(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	c := config.Default()
	c.Server.Listen = addr
	c.Server.PublicURL = "https://" + addr
	c.Server.DataDir = t.TempDir()
	c.Storage.Backend = "sqlite"
	c.Limits.PasswordWorkers = 4
	c.Limits.LoginPerIPMin = 0 // the load generator is one IP
	c.Server.MasterKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, c, logger.NewNullLogger())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); a.Close() })

	dataFile := filepath.Join(t.TempDir(), "seed.json")
	o := loadtest.DefaultSeedOptions()
	o.Orgs, o.Users, o.Grants, o.Sample, o.Workers, o.DataFile = 3, 20, 10, 3, 4, dataFile
	sum, err := loadtest.Seed(ctx, a.Svc, o, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	// 3 x (20 users + 5 groups + 3 clients + 4 members/20 users... + org) + 10 grants
	if sum.OrgsCreated != 3 || sum.Users != 60 || sum.Grants != 10 || sum.Records < 60+15+9+3+10 {
		t.Fatalf("summary %+v", sum)
	}
	// 2 tenants per org (default + apps), and the data file names them.
	if n, err := a.Svc.Tenants.Count(ctx, ""); err != nil || n < 6 {
		t.Fatalf("tenants %d %v", n, err)
	}
	if dd, err := loadtest.LoadData(dataFile); err != nil || len(dd.Samples[0].Tenants) != 2 || dd.Samples[0].Tenants[1].Name != "apps" {
		t.Fatalf("data file tenants: %v %+v", err, dd.Samples[0])
	}
	// Seeding again is a no-op for organizations.
	sum2, err := loadtest.Seed(ctx, a.Svc, o, io.Discard)
	if err != nil || sum2.OrgsSkipped != 3 || sum2.OrgsCreated != 0 || sum2.Users != 0 {
		t.Fatalf("resume %+v %v", sum2, err)
	}

	for _, sc := range loadtest.Scenarios {
		t.Run(sc, func(t *testing.T) {
			rep, err := loadtest.Run(ctx, loadtest.RunOptions{URLs: []string{c.Server.PublicURL}, Scenario: sc,
				Concurrency: 4, Duration: time.Second, Insecure: true, DataFile: dataFile})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Requests == 0 || rep.OK != rep.Requests {
				t.Fatalf("%s: %d requests, %d ok, errors %v", sc, rep.Requests, rep.OK, rep.Errors)
			}
			if rep.P99Ms <= 0 || rep.P50Ms > rep.P99Ms {
				t.Fatalf("%s: latencies %+v", sc, rep)
			}
		})
	}
}
