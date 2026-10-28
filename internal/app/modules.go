package app

import (
	"context"
	"fmt"
	"strings"

	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/events"

	"github.com/paularlott/quisora/internal/login"
	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/scim"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/upstream"
	"github.com/paularlott/quisora/internal/web"
)

// modules builds the HTTP modules and hooks their caches and housekeeping into the cluster.
func modules(ctx context.Context, a *App) []web.Module {
	op := oidc.New(a.Server)
	a.OIDC = op
	a.onChange = append(a.onChange, func(rec *store.Record) {
		switch rec.Kind {
		case model.KindClient:
			op.InvalidateClient(rec.ID)
		case model.KindUser:
			op.InvalidateUser(rec.ID)
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
	// Every node reports the master key it seals with (renewed well within service.MasterKeyReportTTL).
	a.background(func() { a.reportMasterKey(ctx) })

	// Secrets sealed with anything but the active master key (a rotation, or values from before sealed values named
	// their key) are re-sealed by the leader in passes of a third of a tick at most (each goes on where the last
	// stopped), but only once every live node seals with the leader's key: a rotation rolled out node by node is
	// finished first. Passes run every minute while there is work and every ten otherwise, for as long as previous
	// keys are configured (a node could still seal with one); without them, until one finds nothing left. A pass
	// that has nothing left to do reads nothing: no record is read again until the keys change. Once nothing needs
	// the previous keys, the leader says every hour that they must be removed.
	var lastReseal, lastRemind, lastSelfReg time.Time
	var resealEvery time.Duration
	var resealed bool
	var lastResult service.ResealResult
	var lastOthers string
	var lastRing string
	var sweep service.Sweep
	hk := housekeepingLog{log: a.Log}
	every := housekeepingEvery // read once: the closure below runs on its own goroutine
	a.background(func() {
		a.Node.RunHousekeeping(ctx, every, func(ctx context.Context) {
			a.passes.Add(1)
			if ring := strings.Join(a.Svc.Sealer.KeyIDs(), ","); ring != lastRing { // started, or keys reloaded (SIGHUP)
				lastRing, resealed, resealEvery, lastRemind, lastOthers = ring, false, 0, time.Time{}, ""
			}
			if !(resealed && !a.Svc.Sealer.Previous()) && time.Since(lastReseal) >= resealEvery {
				lastReseal, resealEvery = time.Now(), every
				agreed, others, err := a.Svc.MasterKeyAgreed(ctx, a.Node.ID())
				switch {
				case !hk.ok("master key: reading the nodes' keys", err):
				case !agreed:
					if o := fmt.Sprint(others); o != lastOthers {
						lastOthers = o
						a.Log.Warn("master key rotation: waiting for every node to seal with the same master key as this "+
							"one before re-sealing (finish the step on every node)", "key", a.Svc.Sealer.ActiveKeyID(),
							"other_nodes", others)
					}
					resealed = false
					hk.ok("master key: restarting the re-seal", a.Svc.ResealRestart(ctx))
				default:
					lastOthers = ""
					r, err := a.Svc.ResealSecrets(ctx, every/3)
					if !hk.ok("master key: re-sealing secrets", err) {
						break
					}
					if r.Resealed > 0 {
						a.Log.Info("master key: secrets re-sealed with the active key", "key", a.Svc.Sealer.ActiveKeyID(),
							"resealed", r.Resealed, "resealed_total", r.Total)
					}
					if r.Unopenable > 0 && r.Unopenable != lastResult.Unopenable {
						a.Log.Error("master key: secrets that no configured master key opens (sealed with a key that is "+
							"not in server.previous_master_keys, or damaged)", "count", r.Unopenable)
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
			hk.ok("signing key rotation", op.EnsureKeys(ctx))
			if n, err := a.Svc.ExpireUsers(ctx); hk.ok("user end dates", err) && n > 0 {
				a.Log.Info("users past their end date disabled", "count", n)
			}
			// A change of a group's members whose writer died after committing it is finished here (it is visible
			// to every reader meanwhile): its membership records are written and the entry cleared.
			if n, err := a.Svc.FinishGroupChanges(ctx, service.GroupChangeGrace); hk.ok("finishing group changes", err) && n > 0 {
				a.Log.Info("group changes left unfinished by their writer were finished", "count", n)
			}
			// A deletion of an organization that decided and whose last write did not land (a store outage) is
			// finished here: the organization refuses new users until it is.
			if n, err := a.Svc.FinishOrgDeletions(ctx, service.OrgDeletionGrace); hk.ok("finishing organization deletions", err) && n > 0 {
				a.Log.Info("organization deletions left unfinished were finished", "count", n)
			}
			// Records whose owner is gone (what a deleted organization, user, group, tenant or provider owned: they
			// stopped counting at its deletion) are found a batch a minute: a pass over every record of the kinds that
			// do not expire takes about a day at five million users.
			if n, err := a.Svc.SweepOrphans(ctx, &sweep, 20_000); hk.ok("orphan sweep", err) && n > 0 {
				a.Log.Info("removed records whose owner is gone", "count", n)
			}
			// self-registered applications never used to sign anyone in go a day after registering (hourly sweep)
			if time.Since(lastSelfReg) >= time.Hour {
				lastSelfReg = time.Now()
				if n := a.Svc.PurgeSelfRegistered(ctx, time.Now()); n > 0 {
					a.Log.Info("removed unused self-registered applications", "count", n)
				}
			}
		})
	})

	if every := time.Duration(a.Cfg.Session.UpstreamCheckMinutes) * time.Minute; every > 0 {
		a.background(func() { a.runLeaverChecks(ctx, lm.Upstream, every) })
	}

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

// housekeepingLog reports the outcome of the housekeeping tasks. A task that fails because the cluster cannot take
// writes for a reason it knows (it is forming, so a partition has no owner yet while other nodes copy their data; it has
// no majority; this node is catching up) is logged once at warn level, and tried again quietly at the next run until it
// succeeds; any other failure is an error, every time.
type housekeepingLog struct {
	log     logger.Logger
	waiting map[string]bool // the tasks waiting for a writable cluster (logged once)
}

// ok reports whether err is nil, logging it as above.
func (h *housekeepingLog) ok(task string, err error) bool {
	if err == nil {
		if h.waiting[task] {
			delete(h.waiting, task)
			h.log.Info(task + ": the cluster takes writes again")
		}
		return true
	}
	if !service.IsUnavailable(err) {
		h.log.Error(task, "error", err)
		return false
	}
	if !h.waiting[task] {
		if h.waiting == nil {
			h.waiting = map[string]bool{}
		}
		h.waiting[task] = true
		h.log.Warn(task+": waiting for the cluster to take writes (tried again every run, logged again once it succeeds)",
			"reason", err)
	}
	return false
}

// housekeepingEvery is how often the housekeeping leader runs (tests shorten it).
var housekeepingEvery = time.Minute

// leaverCheckBudget is the longest one run of the leaver check works before it hands over to the next (it resumes
// where this one stopped), and so the longest a backlog goes unreported. Runs follow one another as long as there is
// work (a run starts when the previous ended, once the interval since its start has passed).
const leaverCheckBudget = 5 * time.Minute

// runLeaverChecks is the leaver detection (upstream.Service.CheckSessions): sessions signed in through an upstream
// provider are checked with the provider's refresh token every `every` (session.upstream_check_minutes). It is a loop
// of its own on the housekeeping leader, not a task of the housekeeping pass: it makes one HTTP request per identity
// to servers that may be slow, which would hold up the tasks that must run on time (end dates, key rotation) for as long
// as it takes. A run is a time-bounded slice, with every request made only while this node still leads.
func (a *App) runLeaverChecks(ctx context.Context, up *upstream.Service, every time.Duration) {
	up.Tenure, up.Unfenced = a.Node.Tenure, cluster.Unfenced
	budget := min(every, leaverCheckBudget)
	hk := housekeepingLog{log: a.Log}
	a.Node.RunHousekeeping(ctx, budget, func(ctx context.Context) {
		r, err := up.CheckSessions(ctx, every, budget)
		if !hk.ok("upstream session check", err) {
			return
		}
		if r.Ended > 0 || r.Failed > 0 {
			a.Log.Info("upstream session check", "checked", r.Checked, "ended", r.Ended, "failed", r.Failed)
		}
		if r.Unfinished {
			a.Log.Warn("upstream session check: more identities than one run's time allows; the next run resumes after "+
				"where this one stopped (providers slow to answer, or very many sessions through providers)",
				"budget", budget, "checked", r.Checked, "reached", r.Reached)
		}
	})
}

// reportMasterKey reports this node's master key (reportKey) every few minutes, retrying every second while the store
// refuses.
func (a *App) reportMasterKey(ctx context.Context) {
	wait := time.Duration(0)
	if a.keyReportCurrent() {
		wait = service.MasterKeyReportTTL / 3 // (reported at start)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := a.reportKey(ctx); err != nil {
			wait = time.Second
			continue
		}
		wait = service.MasterKeyReportTTL / 3
	}
}

// reportKey stores this node's master key report (service.ReportMasterKey) and notes when.
func (a *App) reportKey(ctx context.Context) error {
	at := time.Now()
	if err := a.Svc.ReportMasterKey(ctx, a.Node.ID()); err != nil {
		return err
	}
	a.keyReported.Store(at.UnixNano())
	return nil
}

// keyReportCurrent says whether this node's last stored report still counts (service.MasterKeyReportTTL from when it
// was made): a node serves only while it does, so a node whose report lapsed (a store that refused its renewals) seals
// nothing a rotation does not see.
func (a *App) keyReportCurrent() bool {
	at := a.keyReported.Load()
	return at != 0 && time.Since(time.Unix(0, at)) < service.MasterKeyReportTTL
}
