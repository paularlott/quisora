package main

import (
	"context"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/login"
	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// demoMailHost turns email on for the demo (so the pages that offer email can be audited); nothing is delivered.
const demoMailHost = "mail.demo.invalid"

// extraModules registers modules owned by other packages so their pages can be audited together with the admin UI.
// The demo has email turned on with a transport that delivers nothing.
func extraModules(s *web.Server, adm *admin.Module) {
	m := mail.New(s.Cfg, logger.NewNullLogger(), s.Svc.Store, "uidemo", s.Svc.Sealer,
		mail.TransportFunc(func(context.Context, mail.Message) error { return nil }))
	m.SetService(s.Svc)
	adm.Mailer = demoMailer{m}
	op := oidc.New(s) // the OAuth pages: consent, device sign-in
	s.Use(op)
	demoEvict = func(rec *store.Record) {
		switch rec.Kind {
		case model.KindClient:
			op.InvalidateClient(rec.ID)
		case model.KindUser:
			op.InvalidateUser(rec.ID)
		case model.KindOrg:
			s.Svc.InvalidateOrgs()
		case model.KindTenant:
			op.InvalidateTenant(rec.ID)
		case model.KindGrant:
			op.InvalidateGrant(rec.ID)
		case model.KindMember, model.KindGroup:
			op.InvalidateMembership(rec.Scope)
		}
	}
	s.Use(login.New(s, login.Options{Mail: m, StepUp: op.FlowWantsMFA}))
}

type demoMailer struct{ m *mail.Mailer }

func (d demoMailer) SendInviteLink(ctx context.Context, org *model.Org, u *model.User, url string, expires time.Time) error {
	return d.m.SendInviteLink(ctx, u, org, url, expires)
}

func (d demoMailer) SendVerifyAddress(ctx context.Context, org *model.Org, u *model.User, address string) error {
	return d.m.SendVerifyAddress(ctx, u, org, address)
}

// demoClusterStatus is a made-up three-node gossip cluster (-cluster), in the shape of GET /api/cluster.
func demoClusterStatus() any {
	return map[string]any{
		"node_id": "node-a", "replicating": true, "size": 3, "quorum": 2, "members": 3, "alive": 3, "leader": true,
		"ready": true, "writable": true, "partitions_owned": 21, "refused": 0,
		"unconfirmed": 0, "clock_skewed": 0, "skew_refused": 0, "cluster_keys": []string{"k2", "k1"},
		"nodes": []map[string]any{
			{"id": "node-a", "address": "10.0.0.11:7946", "state": "alive", "ready": true, "leader": true, "self": true, "version": "dev"},
			{"id": "node-b", "address": "10.0.0.12:7946", "state": "alive", "ready": true, "version": "dev"},
			{"id": "node-c", "address": "10.0.0.13:7946", "state": "suspect", "ready": false, "version": "dev"},
		},
	}
}
