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
// An address can then lock at most one account per lockout time, instead of every account it has names for. Only
// passwords checked and found wrong count towards the limit, not attempts refused as locked (the account's or the
// address's): counted, one address could keep its organization under spray for ever from its refusals alone, and
// with it every other address held to the spray's budget. Under spray each address has at most its budget of wrong
// passwords per lockout time, so the spray goes on only while more than the limit's worth a minute come from many
// addresses, which is the attack it is for.
//
// The account is still charged and locked as before. Charging the address instead of the account (or no longer
// locking it) would let a botnet guess each password once per address; charging both bounds each account at its
// lockout attempts whatever the number of addresses, and the address budget only ever refuses more. An attacker with
// at least one address per account can still lock every account (no server can tell their wrong passwords from its
// users' own), but not the browsers people signed in from before (device.go), and the operator sees the spray in
// the audit log (org.spray.start, org.spray.end) and can block the addresses upstream.

const (
	// nsSpray holds the failed passwords per organization and minute (counters), and the record of the spray an
	// organization is under. The limit rests on that record, so it is a guard namespace (ephemeral.GuardPrefix):
	// sign-in state that fills this node never takes its room, which a spray's author could otherwise arrange first
	// so that the limit never engaged. One small record for each organization under spray; when even that cannot be
	// kept, a counter here remembers the spray instead (putSpray), so the limit holds.
	nsSpray = ephemeral.GuardPrefix + "spray"

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
// takes its record and audits the end (org.spray.end). A spray whose record is lost (this node's short-lived state
// restarted, or its owner node changed) is over from then on without an org.spray.end: the record is all there is to
// remember it by, and keeping it on several nodes would need coordination for a rare, harmless gap. A record that
// cannot be read is an error: the caller refuses the attempt as charge does when its counter fails. A spray whose
// record could not be kept (putSpray) is still one: the organization is under it for as long as sprayUnkept says,
// with no start to report.
func (m *Module) spray(ctx context.Context, org *model.Org) (sprayState, bool, error) {
	if m.s.Cfg.LiveLimits().OrgFailuresPerMin <= 0 {
		return sprayState{}, false, nil
	}
	st, err := readSpray(m.s.Eph.Get(ctx, nsSpray, org.ID))
	if errors.Is(err, ephemeral.ErrNotFound) {
		on, err := m.sprayUnkept(ctx, org)
		return sprayState{}, on, err
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

// putSpray keeps the record of org's spray. One that cannot be kept must not switch the limit off (its room is apart
// from the sign-in state's, and a record is small and one for each organization, so this is that room full of
// codes' and device sign-ins' records, or a store that cannot be written at all): the spray is then remembered by a
// counter instead (sprayUnkeptKey), which has the counters' room, not the guard records', and the organization
// stays under spray by it (sprayUnkept): each address is held to its budget as under a recorded one. Only when that
// cannot be counted either is the limit not in force, and said so.
func (m *Module) putSpray(ctx context.Context, org *model.Org, st sprayState) {
	b, _ := json.Marshal(st)
	err := m.s.Eph.Set(ctx, nsSpray, org.ID, b, sprayRecordTTL)
	if err == nil {
		return
	}
	n, cerr := m.s.Eph.Incr(ctx, nsSpray, sprayUnkeptKey(org), 1, max(m.lockWindow(org), time.Minute))
	if cerr != nil || n >= ephemeral.Contended { // not counted either: nothing remembers the spray
		m.s.Log.Warn("the record of a password spray could not be kept: the organization's spray limit is not in force",
			"org", org.ID, "error", err, "counter_error", cerr)
		return
	}
	m.s.Log.Warn("the record of a password spray could not be kept: the organization's spray limit stays in force "+
		"without it, and the spray's end will not be audited", "org", org.ID, "error", err)
}

// sprayUnkeptKey is the counter that remembers a spray of org whose record could not be kept.
func sprayUnkeptKey(org *model.Org) string { return "unkept|" + org.ID }

// sprayUnkept reports whether org is under a spray whose record could not be kept (putSpray). The counter lasts a
// lockout time from the first minute over the limit whose record could not be kept, so the organization is under
// spray for that long, and again from the next such minute (a spray that goes on passes the limit again within a
// minute of the counter's end). A counter the store could not make (its counters are at their cap) was reported as
// one over any limit when it was counted, and nothing remembers the spray then: said by putSpray's warning. One
// that cannot be read is an error, and the caller refuses the attempt.
func (m *Module) sprayUnkept(ctx context.Context, org *model.Org) (bool, error) {
	n, err := m.s.Eph.Incr(ctx, nsSpray, sprayUnkeptKey(org), 0, max(m.lockWindow(org), time.Minute))
	return n > 0, err
}

// sprayFailed counts a password attempt at org's sign-in that was checked and found wrong (not one refused as
// locked) towards limits.org_failures_per_minute. The failure that passes the limit in its minute (one per minute: the
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
	if st.Start.IsZero() { // none recorded: a new spray, or one whose record could not be kept (sprayUnkept)
		st.Start = now
	}
	if !on {
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
