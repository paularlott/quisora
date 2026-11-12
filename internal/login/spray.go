package login

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/web"
)

// Password spray: the lockout stops any one account's password being guessed (at most the organization's lockout
// attempts in its lockout time, from all addresses together), but whoever knows an organization's email addresses
// can spend every account's attempts and so keep everyone out of signing in from a browser they have not signed in
// from before (device.go). The per-address request limit (allow) does not stop that from many addresses.
//
// So an organization whose sign-ins fail more often than limits.org_failures_per_minute in some minute is under
// spray until a lockout time has passed without such a minute. While it is, a password attempt from a browser that
// has not signed in to the account before is charged to its address too: each address gets as many failed attempts
// across the whole organization as one account gets, and is refused past them before the account is charged at all.
// An address can then lock at most one account per lockout time, instead of every account it has names for. The
// attempts refused as locked count towards the limit too, so the spray lasts as long as the attack does.
//
// The account is still charged and locked as before. Charging the address instead of the account (or no longer
// locking it) would let a botnet guess each password once per address; charging both bounds each account at its
// lockout attempts whatever the number of addresses, and the address budget only ever refuses more. An attacker with
// at least one address per account can still lock every account (no server can tell their wrong passwords from its
// users' own), but not the browsers people signed in from before (device.go), and the operator sees the spray in
// the audit log (org.spray.start, org.spray.end) and can block the addresses upstream.

const (
	nsSpray = "spray" // failed passwords per organization and minute, and the spray an organization is under

	// sprayRecordTTL is how long the record of a spray outlives its last minute over the limit: its end is audited
	// by the first sign-in to find it over (spray), so an organization nobody signs in to for this long goes without.
	sprayRecordTTL = 24 * time.Hour
)

// sprayState is the record of a spray: when it started and the last minute that passed the limit.
type sprayState struct {
	Start time.Time `json:"s"`
	Last  time.Time `json:"l"`
}

// spray reports whether org is under a password spray, and since when: a minute of its lockout time just past had
// more failed passwords than limits.org_failures_per_minute (sprayFailed). The first request to find a spray over
// takes its record and audits the end (org.spray.end). A record that cannot be read is an error: the caller refuses
// the attempt as charge does when its counter fails.
func (m *Module) spray(ctx context.Context, org *model.Org) (sprayState, bool, error) {
	if m.s.Cfg.LiveLimits().OrgFailuresPerMin <= 0 {
		return sprayState{}, false, nil
	}
	st, err := readSpray(m.s.Eph.Get(ctx, nsSpray, org.ID))
	if errors.Is(err, ephemeral.ErrNotFound) {
		return sprayState{}, false, nil
	}
	if err != nil {
		return sprayState{}, false, err
	}
	window := m.lockWindow(org)
	if time.Since(st.Last) < window {
		return st, true, nil
	}
	// Over: exactly one request takes the record. One the limit was passed again for meanwhile is current, and goes
	// back.
	ctx = context.WithoutCancel(ctx)
	if st, err = readSpray(m.s.Eph.Take(ctx, nsSpray, org.ID)); err != nil {
		return sprayState{}, false, nil
	}
	if time.Since(st.Last) < window {
		m.putSpray(ctx, org, st)
		return st, true, nil
	}
	end := st.Last.Add(window)
	m.s.Svc.Audit(ctx, nil, org.ID, "org.spray.end", org.Name, map[string]string{
		"started": st.Start.UTC().Format(time.RFC3339), "ended": end.UTC().Format(time.RFC3339),
		"minutes": strconv.Itoa(int(end.Sub(st.Start).Minutes()))})
	return sprayState{}, false, nil
}

func readSpray(b []byte, err error) (sprayState, error) {
	var st sprayState
	if err == nil {
		err = json.Unmarshal(b, &st)
	}
	return st, err
}

func (m *Module) putSpray(ctx context.Context, org *model.Org, st sprayState) {
	b, _ := json.Marshal(st)
	_ = m.s.Eph.Set(ctx, nsSpray, org.ID, b, sprayRecordTTL)
}

// sprayFailed counts a password attempt at org's sign-in that failed (a wrong password, or one refused as locked)
// towards limits.org_failures_per_minute. The failure that passes the limit in its minute (one per minute: the
// counter is the organization's alone) puts org under spray for a lockout time from now, and records the start
// (org.spray.start) when it was not under one already.
func (m *Module) sprayFailed(r *http.Request, org *model.Org) {
	limit := int64(m.s.Cfg.LiveLimits().OrgFailuresPerMin)
	if limit <= 0 {
		return
	}
	ctx := context.WithoutCancel(r.Context())
	n, err := m.s.Eph.Incr(ctx, nsSpray, "n|"+org.ID, 1, time.Minute)
	if err != nil || n != limit+1 {
		return
	}
	st, on, err := m.spray(ctx, org)
	if err != nil {
		return
	}
	now := time.Now()
	if !on {
		st.Start = now
		m.s.Svc.Audit(ctx, nil, org.ID, "org.spray.start", org.Name, map[string]string{
			"failures": strconv.FormatInt(n, 10), "per_minute": strconv.FormatInt(limit, 10),
			"minutes": strconv.Itoa(int(m.lockWindow(org).Minutes()))})
	}
	st.Last = now
	m.putSpray(ctx, org, st)
}

// sprayCharge charges a password attempt from a browser that has not signed in to the account before to its address
// (charge) while org is under spray: key is that counter ("" when org is not under spray, and nothing was charged),
// for the caller to settle as it settles the account's; open is false when the address has spent its attempts.
func (m *Module) sprayCharge(r *http.Request, org *model.Org) (key string, open bool, err error) {
	_, on, err := m.spray(r.Context(), org)
	if err != nil || !on {
		return "", err == nil, err
	}
	key = "addr:" + org.ID + ":" + web.RateKeyIP(r)
	_, open, err = m.charge(r.Context(), org, key)
	return key, open, err
}
