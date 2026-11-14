package login

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/upstream"
	"github.com/paularlott/quisora/internal/web"
)

// stateCookie binds an upstream sign-in to the browser that started it (the state alone is not enough: login CSRF).
// One cookie per sign-in, named for its state (stateCookieName), not one per browser: a sign-in can start another
// inside it - a guest of an organization provider signing in at the source organization through that organization's
// own provider - and with a single cookie the inner one would replace the outer one's, whose callback would then fail.
const stateCookie = "__Host-quisora_up"

// stateCookieName is the name of the cookie that binds the sign-in with this state to the browser.
func stateCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return stateCookie + "_" + hex.EncodeToString(sum[:8])
}

// setStateCookie binds the upstream sign-in with this state to the browser, for as long as the state lasts.
func setStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{Name: stateCookieName(state), Value: state, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(upstream.StateTTL.Seconds())})
}

// providerStart handles GET /o/{org}/login/provider/{id}: redirect the browser to the upstream provider.
func (m *Module) providerStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := web.Org(r)
	next := safeNext(org, r.URL.Query().Get("next"))
	tenantParam := r.URL.Query().Get("tenant")
	eff, tenant, err := m.methods(ctx, org, tenantParam, next)
	if err != nil {
		http.Redirect(w, r, loginURL(org, next, "", "failed"), http.StatusFound)
		return
	}
	back := func(code string) {
		http.Redirect(w, r, loginURL(org, next, tenant, code), http.StatusFound)
	}
	if !m.rateLimit(w, r, org.ID, known{orgID: org.ID}) {
		return
	}
	p, err := m.s.Svc.Providers.Get(ctx, r.PathValue("id"))
	if err != nil || p.OrgID != org.ID || !p.Enabled || !eff.AllowsProvider(p.ID) {
		back("disabled")
		return
	}
	// The state of the sign-in under way is kept for the address that asked: nobody has signed in.
	authURL, state, err := m.Upstream.BeginTenant(m.heldByIP(r), org, p, next, tenant)
	if errors.Is(err, ephemeral.ErrHeld) { // the address holds as much as it may: counted by the budget
		tooManyHeld(w, err)
		return
	}
	if errors.Is(err, ephemeral.ErrContended) { // the budget's counter could not be updated: 503, counted where refused
		m.internalError(w, r, "upstream begin", err)
		return
	}
	if err != nil {
		if !errors.Is(err, ephemeral.ErrFull) { // a full store logs that itself, once a minute
			m.s.Log.Warn("upstream begin", "provider", p.Name, "error", err)
		}
		back("failed")
		return
	}
	setStateCookie(w, state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// A callback with a state started for the provider makes the upstream token exchange, a request to the provider's
// token endpoint with the organization's client secret. Anyone may start a state (providerStart) and send its callback
// a made-up code: the exchange then fails at the provider, and a flood of them (as many as the sign-in limits allow,
// limits.login_per_ip_min three times over, from each address) could get the organization's client rate-limited or
// flagged there, which no limit on this side would see. So failed exchanges are limited:
//
//   - Each address has a share of a provider's failed exchanges a minute (upstreamFailPerIPMin), and its IPv6 /48
//     web.NetShareFactor times that (upstreamFailPerNetMin): counted by /64 alone, one /48 would bring 65,536 shares.
//   - Past the provider's minute (upstreamFailPerProviderMin, every address together), an address whose /64 or /48 has
//     had a failed exchange of the provider in the last hour or so (upstreamFailedFor) is refused. An address with no
//     such failure never is, whatever the provider's minute holds: the provider-wide limit is no switch that turns off
//     the provider's sign-ins for everyone. Every address that floods spends its own first failure, and then waits
//     out the hour whenever the provider's minute is full; and a failure is marked against an address only by an
//     exchange made from it, so nobody can have another's address refused (but from that address, or its /48).
//
// This was chosen over a cap on the provider's minute that refuses everyone past it, with a reserve for addresses with
// no failure in the minute: any state anyone starts, from as many addresses as they hold, counted against it, and a
// few /64s of one /56, each failing once, turned it into a switch that refused every sign-in with the provider, those
// with good codes included. It was chosen over shares by address alone (and an alert) too: those let each address
// fail upstreamFailPerIPMin a minute for ever, where this lets a flood from many addresses fail at most the provider's
// minute plus one exchange per fresh address an hour, which bounds what the organization's client is seen doing at
// the provider as nearly as anything can without refusing its users. The cost is borne by an address that failed an
// exchange (a code used twice, a sign-in left too long) while the provider's minute is full: it waits for the
// minute, or the hour.
//
// Only an exchange made counts: the callback with no code (Finish fails it before any request to the provider) takes
// no part, nor one whose state turns out not valid, nor an account this server refused after a good exchange (not
// linked, a domain not allowed), which costs the provider nothing more than a sign-in that works. What counts is a
// failure the provider answered ("failed": the exchange refused, or the token it gave not valid). The shares and the
// provider's minute are taken before the exchange (upstreamReserve) and given back after it unless it failed: read
// before and counted after, callbacks from one address at the same moment all passed the reads. They are taken only
// for an enabled provider of the organization the path names, which a valid state must have been started for: a path
// naming a made-up provider makes no counter. Past a limit the callback is refused before the state is taken (429,
// the state cookie kept): the sign-in can be finished a minute later.
const (
	upstreamFailPerProviderMin = 60
	upstreamFailPerIPMin       = 10
	upstreamFailPerNetMin      = upstreamFailPerIPMin * web.NetShareFactor
	// upstreamFailedFor is the least time a failed exchange marks its address (upstreamFailedMarks): a mark is kept in
	// the hour it was made and the next, so for between one and two hours.
	upstreamFailedFor = time.Hour
)

// upstreamReservation is what a callback took of the limits on failed exchanges before its exchange
// (upstreamReserve): given back after the exchange unless it failed, and then the address marked.
type upstreamReservation struct {
	m          *Module
	r          *http.Request
	orgID, id  string
	counters   []string
	addr, wide string // the address's keys: RateKeyIP, RateNetIP ("" for IPv4)
	settled    bool   // given back or kept: nothing more to do
}

// upstreamFailedMarks are the counters that mark the address (its key, and its /48 when it has one) as having failed
// an exchange of provider id at organization orgID in hour (hours since the epoch, upstreamHour): a mark lasts that
// hour and the next (upstreamFailedFor), so one made at any moment is seen for an hour at least. Only a failed
// exchange makes one (two at most), so they number no more than the failed exchanges the limits let through.
func upstreamFailedMarks(orgID, id, addr, wide string, hour int64) []string {
	h := strconv.FormatInt(hour, 10)
	marks := []string{"upstream-failed|" + orgID + "|" + id + "|" + addr + "|" + h}
	if wide != "" {
		marks = append(marks, "upstream-failed|"+orgID+"|"+id+"|"+wide+"|"+h)
	}
	return marks
}

// upstreamHour is the hour since the epoch that upstreamFailedMarks are kept by.
func upstreamHour() int64 { return time.Now().Unix() / int64(upstreamFailedFor/time.Second) }

// upstreamReserve takes the request's place in the limits on failed exchanges of provider id at organization orgID,
// before the callback's exchange: the address's share, its /48's, and the provider's minute, past which only an
// address with no failed exchange of the provider marked in the last hour goes on. ok is false when the callback is
// to be refused (nothing is kept then); err when a counter cannot be used (the callback is refused: a limit never
// fails open). The caller gives the reservation back (giveBack), or keeps it (failed), once the exchange is done.
func (m *Module) upstreamReserve(r *http.Request, orgID, id string) (res *upstreamReservation, ok bool, err error) {
	ctx := r.Context()
	addr, wide := web.RateKeyIP(r), web.RateNetIP(r)
	res = &upstreamReservation{m: m, r: r, orgID: orgID, id: id, addr: addr, wide: wide}
	type limit struct {
		key string
		max int64
	}
	limits := []limit{{"upstream-fail-ip|" + orgID + "|" + id + "|" + addr, upstreamFailPerIPMin}}
	if wide != "" {
		limits = append(limits, limit{"upstream-fail-net|" + orgID + "|" + id + "|" + wide, upstreamFailPerNetMin})
	}
	for _, l := range limits {
		n, err := m.s.Eph.Incr(ctx, nsRate, l.key, 1, time.Minute)
		if err != nil {
			res.giveBack()
			return nil, false, err
		}
		res.counters = append(res.counters, l.key)
		if n > l.max {
			res.giveBack()
			return nil, false, nil
		}
	}
	pk := "upstream-fail|" + orgID + "|" + id
	n, err := m.s.Eph.Incr(ctx, nsRate, pk, 1, time.Minute)
	if err != nil {
		res.giveBack()
		return nil, false, err
	}
	res.counters = append(res.counters, pk)
	if n <= upstreamFailPerProviderMin {
		return res, true, nil
	}
	// Past the provider's minute: only an address that has not failed lately goes on.
	hour := upstreamHour()
	for _, h := range []int64{hour, hour - 1} {
		for _, k := range upstreamFailedMarks(orgID, id, addr, wide, h) {
			marked, err := m.s.Eph.Incr(ctx, nsRate, k, 0, 2*upstreamFailedFor)
			if err != nil {
				res.giveBack()
				return nil, false, err
			}
			if marked > 0 {
				res.giveBack()
				return nil, false, nil
			}
		}
	}
	return res, true, nil
}

// giveBack returns what the reservation took: the exchange was not made, or did not fail.
func (u *upstreamReservation) giveBack() {
	if u == nil || u.settled {
		return
	}
	u.settled = true
	// not the request's context: a request that hung up still gives back what it took
	ctx := context.WithoutCancel(u.r.Context())
	for _, k := range u.counters {
		_, _ = u.m.s.Eph.Incr(ctx, nsRate, k, -1, time.Minute)
	}
}

// failed keeps the reservation, the exchange having failed at the provider, and marks the address (its key and its
// /48) as having failed one: past the provider's minute it is refused for the next hour or so (upstreamReserve).
func (u *upstreamReservation) failed() {
	if u == nil || u.settled {
		return
	}
	u.settled = true
	ctx := context.WithoutCancel(u.r.Context())
	for _, k := range upstreamFailedMarks(u.orgID, u.id, u.addr, u.wide, upstreamHour()) {
		_, _ = u.m.s.Eph.Incr(ctx, nsRate, k, 1, 2*upstreamFailedFor)
	}
}

// providerCallback handles GET /o/{org}/login/callback/{provider}: the provider sends the browser back to its own
// address, which is its organization's (upstream.CallbackURL): a sign-in started for another organization than the
// path's is refused as any unknown state is.
func (m *Module) providerCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	pathOrg := web.Org(r)
	state, provider := q.Get("state"), r.PathValue("provider")
	var browser string
	if c, err := r.Cookie(stateCookieName(state)); err == nil {
		browser = c.Value
	}
	// Rate-limited first: a refused callback leaves the state cookie, so the user's sign-in can still finish.
	if !m.rateLimit(w, r, pathOrg.ID+"|callback", known{any: true}) {
		return
	}
	// The limits on failed exchanges, for a callback that will make one: with a code, for an enabled provider of the
	// organization (Finish makes none for anything else, so it takes nothing and makes no counter).
	var reserved *upstreamReservation
	if q.Get("error") == "" && q.Get("code") != "" {
		if p, err := m.s.Svc.Providers.Get(ctx, provider); err == nil && p.OrgID == pathOrg.ID && p.Enabled {
			ok := false
			if reserved, ok, err = m.upstreamReserve(r, pathOrg.ID, p.ID); err != nil {
				unavailableResponse(w)
				return
			} else if !ok {
				w.Header().Set("Retry-After", "60")
				writeErr(w, http.StatusTooManyRequests, "Too many sign-ins with this provider failed. Please wait a minute and try again.", "")
				return
			}
			defer reserved.giveBack() // unless the exchange failed (failed, below)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookieName(state), Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if q.Get("error") != "" { // the user declined, or the provider failed
		if org, next, tenant, ok := m.Upstream.CancelTenant(ctx, pathOrg.ID, provider, state, browser); ok {
			http.Redirect(w, r, loginURL(org, next, tenant, "denied"), http.StatusFound)
			return
		}
		http.Redirect(w, r, loginURL(pathOrg, "", "", "failed"), http.StatusFound)
		return
	}
	res, err := m.Upstream.Finish(ctx, pathOrg.ID, provider, state, browser, q.Get("code"))
	if err != nil {
		code := upstreamErrorCode(err)
		var org *model.Org
		var u *model.User
		next, tenant := "", ""
		detail := map[string]string{"reason": "upstream " + code}
		if res != nil {
			org, next, tenant = res.Org, res.Next, res.Tenant
			if res.Provider != nil {
				detail["provider"] = res.Provider.Name
			}
		}
		// The step names what failed, one of a few fixed names: a state that was not valid ("callback", no exchange
		// made), else the provider's answer by its code (upstreamErrorCode), so each kind of failure is seen.
		step := "callback"
		if res != nil && res.Provider != nil {
			step = "upstream " + code
			if code == "failed" && reserved != nil && res.Provider.ID == reserved.id {
				reserved.failed() // the exchange, or the token it got, failed: not an account refused
			}
		}
		if org == nil { // the state was not valid: back to the organization's sign-in page, with nothing of the attempt
			org = pathOrg
		}
		m.auditFailure(r, step, org, u, "", "", detail)
		http.Redirect(w, r, loginURL(org, next, tenant, code), http.StatusFound)
		return
	}
	if res.Connect != "" { // connecting the provider to a signed-in account, not a sign-in
		m.connectFinish(w, r, res)
		return
	}
	// The tenant may have changed since the sign-in started: check again that it still allows this provider.
	eff, _, err := m.methods(ctx, res.Org, res.Tenant, res.Next)
	if err != nil || !eff.AllowsProvider(res.Provider.ID) {
		m.auditFailure(r, "upstream tenant", res.Org, res.User, "", "", map[string]string{"reason": "provider not allowed for tenant",
			"provider": res.Provider.Name})
		http.Redirect(w, r, loginURL(res.Org, res.Next, res.Tenant, "disabled"), http.StatusFound)
		return
	}
	// The provider sign-in is a first factor: the user's own second factor follows when they have one or MFA is
	// required (the sign-in page continues with the step). A provider trusted to ask for a second factor itself
	// (TrustMFA) counts as both for plain users, when it says it did: an ID token whose amr lacks "mfa" gets the user's
	// own second factor as an untrusted provider's does (one that sends no amr at all, as many do not, is taken at
	// its trust). Managers and above always give their own second factor here.
	amr := []string{"fed"}
	account := upstream.AccountOf(res.Provider, res.Claims)
	var step stepResp
	if trustedMFA(res.Provider, res.User, res.Claims.AMR) {
		amr = append(amr, "mfa")
	} else {
		step, err = m.secondFactor(r, res.User, eff, ticket{Next: res.Next, AMR: amr, Tenant: res.Tenant, Provider: res.Provider.ID,
			UpstreamAMR: res.Claims.AMR, Upstream: account, Sources: res.Sources})
	}
	if errors.Is(err, errFactorLost) {
		m.auditFailure(r, "upstream factor_lost", res.Org, res.User, "", "", map[string]string{"reason": "second factor unusable",
			"provider": res.Provider.Name})
		http.Redirect(w, r, loginURL(res.Org, res.Next, res.Tenant, "factor_lost"), http.StatusFound)
		return
	}
	if errors.Is(err, errNoOwnFactor) {
		m.auditFailure(r, "upstream no_own_factor", res.Org, res.User, "", "", map[string]string{"reason": "no second factor of its own",
			"provider": res.Provider.Name})
		http.Redirect(w, r, loginURL(res.Org, res.Next, res.Tenant, "no_own_factor"), http.StatusFound)
		return
	}
	if err != nil {
		if !errors.Is(err, ephemeral.ErrHeld) && !errors.Is(err, ephemeral.ErrFull) &&
			!errors.Is(err, ephemeral.ErrContended) { // those are counted where refused
			m.s.Log.Error("ticket", "error", err)
		}
		http.Redirect(w, r, loginURL(res.Org, res.Next, res.Tenant, "failed"), http.StatusFound)
		return
	}
	if step.Step != "" {
		// The ticket goes in a short-lived cookie, not the URL (history, logs, Referer): the sign-in page reads it.
		http.SetCookie(w, &http.Cookie{Name: stepCookie, Value: step.Ticket, Path: "/", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode, MaxAge: int(enrolTTL / time.Second)})
		u := loginURL(res.Org, res.Next, res.Tenant, "")
		http.Redirect(w, r, u+sepFor(u)+"step=1", http.StatusSeeOther)
		return
	}
	dest, err := m.completeWith(w, r, res.User, res.Org, web.SessionOptions{AMR: amr, Provider: res.Provider.ID, UpstreamAMR: res.Claims.AMR,
		Upstream: account, Sources: res.Sources}, res.Next)
	if err != nil {
		m.s.Log.Error("create session", "error", err)
		http.Redirect(w, r, loginURL(res.Org, res.Next, res.Tenant, "failed"), http.StatusFound)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func upstreamErrorCode(err error) string {
	switch {
	case errors.Is(err, upstream.ErrNotLinked):
		return "not_linked"
	case errors.Is(err, upstream.ErrUnverifiedEmail):
		return "unverified"
	case errors.Is(err, upstream.ErrDomain):
		return "domain"
	case errors.Is(err, upstream.ErrGroup):
		return "group"
	case errors.Is(err, upstream.ErrExists):
		return "exists"
	case errors.Is(err, upstream.ErrDisabled):
		return "disabled"
	case errors.Is(err, upstream.ErrPrivileged):
		return "connect"
	}
	return "failed"
}

// upstreamMessages are the only error texts a sign-in page will show for ?error=<code>.
var upstreamMessages = map[string]string{
	"failed":        "Signing in with that provider did not work. Please try again.",
	"denied":        "Sign-in with that provider was cancelled.",
	"not_linked":    "No account here is linked to that identity. Ask an administrator for access.",
	"unverified":    "That provider has not verified your email address, so an account could not be created.",
	"domain":        "Your email domain is not allowed to sign in to this organization.",
	"group":         "Your account is not in a group allowed to sign in to this organization.",
	"exists":        "An account with your email address already exists. Sign in the way you usually do; an administrator can link this provider.",
	"disabled":      "This sign-in method or account is disabled.",
	"factor_lost":   msgFactorLost,
	"no_own_factor": msgNoOwnFactor,
	"connect":       "Your account manages others, so it is not linked to a provider automatically. Sign in the usual way, then connect this provider on your account page.",
}

// loginURL is org's sign-in page, with what it needs to carry on (the tenant and next of the sign-in) and the error a
// failed attempt shows (one of upstreamMessages).
func loginURL(org *model.Org, next, tenant, errCode string) string {
	v := url.Values{}
	if tenant != "" {
		v.Set("tenant", tenant)
	}
	if next != "" {
		v.Set("next", next)
	}
	if errCode != "" {
		v.Set("error", errCode)
	}
	u := web.OrgPath(org.ID, "/login")
	if len(v) > 0 {
		u += "?" + v.Encode()
	}
	return u
}

func withNext(path, next string) string {
	if next == "" {
		return path
	}
	return path + "?next=" + url.QueryEscape(next)
}

// stepCookie carries the ticket of the second-factor step after a provider sign-in to the sign-in page.
const stepCookie = "__Host-quisora_step"

// sepFor is the separator to append query parameters to u.
func sepFor(u string) string {
	for _, c := range u {
		if c == '?' {
			return "&"
		}
	}
	return "?"
}

// trustedMFA reports whether sign-in through provider p counts as a second factor for u: p is trusted to ask for one
// (TrustMFA), u is a plain user, and p's ID token says one was used ("mfa" in its amr) or says nothing of how.
func trustedMFA(p *model.Provider, u *model.User, upstream []string) bool {
	return p.TrustMFA && !u.Role.Privileged() && (len(upstream) == 0 || slices.Contains(upstream, "mfa"))
}
