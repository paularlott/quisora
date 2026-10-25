package app

import (
	"context"
	"fmt"
	"strings"

	"time"

	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/events"

	"github.com/paularlott/quisora/internal/login"
	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/scim"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// modules builds the HTTP modules and hooks their caches and housekeeping into the cluster.
func modules(ctx context.Context, a *App) []web.Module {
	op := oidc.New(a.Server)
	if a.Node.SharedDatabase() {
		// Load-bearing: nodes sharing a database without gossip hear of no change, so the caches' age is the only
		// bound on how long a disabled client, a rotated secret or key keeps working on another node.
		op.ShortCaches()
	}
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
	if mailer := a.mailer; mailer != nil {
		metrics.Default.Gauge("quisora_mail_queued", "Emails waiting to be sent (invitations, password resets, verifications).",
			nil, metrics.Value(func() float64 { return float64(mailer.Queued()) }))
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
	// Every node reports the master key it seals with (renewed well within service.MasterKeyReportTTL).
	a.background(func() { a.reportMasterKey(ctx) })

	// Secrets sealed with anything but the active master key (a rotation, or values from before sealed values named
	// their key) are re-sealed by the leader in passes, but only once every live node seals with the leader's key: a
	// rotation rolled out node by node is finished first. Passes run every minute while there is work and every ten
	// otherwise, for as long as previous keys are configured (a node could still seal with one); without them, until
	// one finds nothing left. Once nothing needs the previous keys, the leader says every hour that they must be removed.
	var lastLeaverRun, lastReseal, lastRemind, lastSelfReg time.Time
	var resealEvery time.Duration
	var resealed bool
	var lastResult service.ResealResult
	var lastOthers string
	var lastRing string
	var sweep service.Sweep
	every := housekeepingEvery // read once: the closure below runs on its own goroutine
	a.background(func() {
		a.Node.RunHousekeeping(ctx, every, func(ctx context.Context) {
			if ring := strings.Join(a.Svc.Sealer.KeyIDs(), ","); ring != lastRing { // started, or keys reloaded (SIGHUP)
				lastRing, resealed, resealEvery, lastRemind, lastOthers = ring, false, 0, time.Time{}, ""
			}
			if !(resealed && !a.Svc.Sealer.Previous()) && time.Since(lastReseal) >= resealEvery {
				lastReseal, resealEvery = time.Now(), every
				agreed, others, err := a.Svc.MasterKeyAgreed(ctx)
				switch {
				case err != nil:
					a.Log.Error("master key: reading the nodes' keys", "error", err)
				case !agreed:
					if o := fmt.Sprint(others); o != lastOthers {
						lastOthers = o
						a.Log.Warn("master key rotation: waiting for every node to seal with the same master key as this "+
							"one before re-sealing (finish the step on every node)", "key", a.Svc.Sealer.ActiveKeyID(),
							"other_nodes", others)
					}
					resealed = false
				default:
					lastOthers = ""
					r, err := a.Svc.ResealSecrets(ctx, 1000)
					if err != nil {
						a.Log.Error("master key: re-sealing secrets", "error", err)
						break
					}
					if r.Resealed > 0 || r.Pending > 0 {
						a.Log.Info("master key: secrets re-sealed with the active key", "key", a.Svc.Sealer.ActiveKeyID(),
							"resealed", r.Resealed, "left", r.Pending)
					}
					if r.Failed > 0 && r.Failed != lastResult.Failed {
						a.Log.Error("master key: secrets that no configured master key opens (sealed with a key that is "+
							"not in server.previous_master_keys, or damaged)", "count", r.Failed)
					}
					if r.Resealed == 0 {
						resealEvery = 10 * every
					}
					lastResult, resealed = r, r.Done()
				}
			}
			if resealed && a.Svc.Sealer.Previous() && time.Since(lastRemind) >= time.Hour {
				lastRemind = time.Now()
				a.Log.Warn("master key rotation complete: every node seals with the active key and every stored secret is "+
					"sealed with it; nothing needs the previous keys any more: remove server.previous_master_keys now on "+
					"every node (keep the old keys only with backups made before the rotation)", "key", a.Svc.Sealer.ActiveKeyID())
			}
			if err := op.EnsureKeys(ctx); err != nil {
				a.Log.Error("signing key rotation", "error", err)
			}
			if n, err := a.Svc.ExpireUsers(ctx); err != nil {
				a.Log.Error("user end dates", "error", err)
			} else if n > 0 {
				a.Log.Info("users past their end date disabled", "count", n)
			}
			// A change of a group's members whose writer died after committing it is finished here (it is visible
			// to every reader meanwhile): its membership records are written and the entry cleared.
			if n, err := a.Svc.FinishGroupChanges(ctx, service.GroupChangeGrace); err != nil {
				a.Log.Error("finishing group changes", "error", err)
			} else if n > 0 {
				a.Log.Info("group changes left unfinished by their writer were finished", "count", n)
			}
			// Records whose owner is gone (what a deleted organization, user, group, tenant or provider owned: they
			// stopped counting at its deletion) are found a batch a minute: a pass over every record of the kinds that
			// do not expire takes about a day at five million users.
			if n, err := a.Svc.SweepOrphans(ctx, &sweep, 20_000); err != nil {
				a.Log.Error("orphan sweep", "error", err)
			} else if n > 0 {
				a.Log.Info("removed records whose owner is gone", "count", n)
			}
			// self-registered applications never used to sign anyone in go a day after registering (hourly sweep)
			if time.Since(lastSelfReg) >= time.Hour {
				lastSelfReg = time.Now()
				if n := a.Svc.PurgeSelfRegistered(ctx, time.Now()); n > 0 {
					a.Log.Info("removed unused self-registered applications", "count", n)
				}
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
	})

	hub := events.NewHub()
	hub.OrgOfUser = func(id string) string {
		if u, err := a.Svc.Users.Get(context.WithoutCancel(ctx), id); err == nil {
			return u.OrgID
		}
		return ""
	}
	a.onChange = append(a.onChange, hub.Publish)

	adm := admin.New()
	adm.RotateKeys = op.RotateKeys
	adm.RemoveKey = op.RemoveKey
	adm.ClusterStatus = func() any { return a.Node.Status() }
	adm.ReloadCluster = func(ctx context.Context) (any, error) { return a.Node.ReloadCluster(ctx) }
	if adminMail != nil {
		adm.Mailer = adminMail
	}
	a.Admin = adm
	a.Server.Mux.Handle("/", admin.NotFound(a.Server))
	return []web.Module{op, lm, &scim.Module{TokenVerifier: scimVerifier(a)}, adm, &events.Module{Hub: hub}, commandModule{a}}
}

// adminMailer adapts the mailer to the admin module's interface.
type adminMailer struct{ m *mail.Mailer }

func (a adminMailer) SendInviteLink(ctx context.Context, org *model.Org, u *model.User, url string, expires time.Time) error {
	return a.m.SendInviteLink(ctx, u, org, url, expires)
}

func (a adminMailer) SendVerifyAddress(ctx context.Context, org *model.Org, u *model.User, address string) error {
	return a.m.SendVerifyAddress(ctx, u, org, address)
}

// housekeepingEvery is how often the housekeeping leader runs (tests shorten it).
var housekeepingEvery = time.Minute

// reportMasterKey reports this node's master key (service.ReportMasterKey) now and every few minutes, retrying while
// the node cannot write yet.
func (a *App) reportMasterKey(ctx context.Context) {
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := a.Svc.ReportMasterKey(ctx, a.Node.ID()); err != nil {
			wait = 5 * time.Second
			continue
		}
		wait = service.MasterKeyReportTTL / 3
	}
}
