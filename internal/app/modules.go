package app

import (
	"context"

	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/events"
	"time"

	"github.com/paularlott/quisora/internal/login"
	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/scim"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// modules builds the HTTP modules and hooks their caches and housekeeping into the cluster.
func modules(ctx context.Context, a *App) []web.Module {
	op := oidc.New(a.Server)
	if a.Node.SharedDatabase() {
		op.ShortCaches()
	}
	op.AllowPrivateNetworks = a.Cfg.Server.AllowPrivateNetworks
	a.OIDC = op
	a.onChange = append(a.onChange, func(rec *store.Record) {
		switch rec.Kind {
		case model.KindClient:
			op.InvalidateClient(rec.ID)
		case model.KindUser:
			op.InvalidateUser(rec.ID)
		case model.KindOrg:
			op.InvalidateOrg(rec.ID)
		case model.KindTenant:
			op.InvalidateTenant(rec.ID)
		case model.KindGrant:
			op.InvalidateGrant(rec.ID)
		case model.KindKey:
			op.Invalidate()
		case model.KindMember, model.KindGroup:
			op.InvalidateMembership(rec.Scope) // tombstones and invalidations carry no scope: "" clears all orgs
		}
	})
	// Without an SMTP server nothing is emailed or offered by email: no mailer at all (login hides password reset and
	// address verification; the admin module's default mailer refuses, and administrators share invitation links).
	var lopts login.Options
	var adminMail admin.Mailer
	if a.Cfg.Mail.Enabled() {
		mailer := mail.New(a.Cfg, a.Log)
		a.closers = append(a.closers, mailer.Close)
		mailer.SetService(a.Server.Svc) // invitation/reset links are durable service records: any node, any restart
		lopts.Mail = mailer
		adminMail = adminMailer{mailer}
	} else {
		a.Log.Info("email is off (no smtp-host): invitation links are shown to administrators to share")
	}
	lopts.StepUp = op.FlowWantsMFA
	lm := login.New(a.Server, lopts)

	// Key rotation runs on one node (the leader), every minute: EnsureKeys is a no-op unless a key is due or missing
	// (a new cluster's first key is made here, as no node makes keys before it is writable).
	// Users past their end date are disabled (sessions end, applications are told) within a minute.
	// Sessions signed in through an upstream provider are checked with the provider's refresh token every
	// session.upstream_check_minutes (leaver detection); the identities due are looked for every few minutes.
	var lastLeaverRun time.Time
	go a.Node.RunHousekeeping(ctx, time.Minute, func(ctx context.Context) {
		if err := op.EnsureKeys(ctx); err != nil {
			a.Log.Error("signing key rotation", "error", err)
		}
		if n, err := a.Svc.ExpireUsers(ctx); err != nil {
			a.Log.Error("user end dates", "error", err)
		} else if n > 0 {
			a.Log.Info("users past their end date disabled", "count", n)
		}
		if every := time.Duration(a.Cfg.Session.UpstreamCheckMinutes) * time.Minute; every > 0 && time.Since(lastLeaverRun) >= min(every, 5*time.Minute) {
			lastLeaverRun = time.Now()
			if r, err := lm.Upstream.CheckSessions(ctx, every); err != nil {
				a.Log.Error("upstream session check", "error", err)
			} else if r.Ended > 0 || r.Failed > 0 {
				a.Log.Info("upstream session check", "checked", r.Checked, "ended", r.Ended, "failed", r.Failed)
			}
		}
	})

	hub := events.NewHub()
	a.onChange = append(a.onChange, hub.Publish)

	adm := admin.New()
	adm.RotateKeys = op.RotateKeys
	adm.ClusterStatus = func() any { return a.Node.Status() }
	if adminMail != nil {
		adm.Mailer = adminMail
	}
	a.Admin = adm
	a.Server.Mux.Handle("/", admin.NotFound(a.Server))
	return []web.Module{op, lm, &scim.Module{TokenVerifier: scimVerifier(a)}, adm, &events.Module{Hub: hub}}
}

// adminMailer adapts the mailer to the admin module's interface.
type adminMailer struct{ m *mail.Mailer }

func (a adminMailer) SendInviteLink(ctx context.Context, org *model.Org, u *model.User, url string, expires time.Time) error {
	return a.m.SendInviteLink(ctx, u, org, url, expires)
}

func (a adminMailer) SendVerifyAddress(ctx context.Context, org *model.Org, u *model.User, address string) error {
	return a.m.SendVerifyAddress(ctx, u, org, address)
}
