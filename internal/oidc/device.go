package oidc

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// The device authorization grant (RFC 8628): sign-in on a device that cannot show a browser (a CLI, a TV, a kiosk).
// The device posts to /o/<org>/oauth/device_authorization and gets a device_code it keeps and a short user_code it
// shows; the user opens /o/<org>/device on a phone or computer, types the code, signs in there as for any application
// and approves on a consent screen that always asks; meanwhile the device polls the token endpoint with the
// device_code until it gets its tokens (or access_denied, or expired_token).
//
// A user code is the one secret that the user carries between the two: 8 letters from an alphabet without vowels (no
// words, nothing to misread), guessed at most deviceGuessesPerIP times per address in deviceGuessWindow. The grant is
// on per client (GrantTypes), off by default, and never for FAPI clients. The page after the code is the usual
// authorization flow (authorize.go: sign-in, re-authentication, a second factor, access) with a consent screen
// warning about codes someone else sent: a person talked into entering an attacker's code would sign the attacker's
// device in. For the same reason managers and above may approve only where the client allows it (DevicePrivileged).
const (
	nsDevice     = "oauth.device"      // device_code -> deviceGrant
	nsDeviceUser = "oauth.device.user" // normalised user code -> device_code
	// What slow_down rests on, so a guard namespace (ephemeral.GuardPrefix): sign-in state that fills this node never
	// takes its room. One record for each device sign-in under way, whose address was charged for it as it started,
	// against the small part of its budget an address may hold in guard records (ephemeral.Budget.ChargeGuard).
	nsDevicePoll = ephemeral.GuardPrefix + "oauth.device.poll" // device_code -> devicePoll
	nsDeviceTurn = "oauth.device.turn"                         // device_code -> the right to decide it, taken by the first decision

	deviceTTL          = 10 * time.Minute
	deviceInterval     = 5 // seconds between polls
	userCodeAlphabet   = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLen        = 8
	deviceGuessesPerIP = 20
	deviceGuessWindow  = 15 * time.Minute
	deviceStartsPerIP  = 30 // device authorization requests per address and minute
	// deviceExtraCost is what a device sign-in holds beyond its own record, charged with it as it starts: the user
	// code's and the turn's entries, and what an approval adds to the sign-in (the user, their session and how they
	// signed in). devicePollCost is the record of its polls, charged apart (nsDevicePoll).
	deviceExtraCost = 1024
	devicePollCost  = 128
)

// deviceGrant is a device sign-in waiting for its user (ephemeral, ns oauth.device, keyed by the device_code).
type deviceGrant struct {
	ClientID  string   `json:"c"`
	Scopes    []string `json:"sc"`
	Resources []string `json:"res,omitempty"`
	ADTypes   []string `json:"adt,omitempty"` // authorization details types asked for (authdetails.go)
	UserCode  string   `json:"uc"`
	Expires   int64    `json:"x"` // unix seconds
	// MFA and MaxAge are what the device asked for with acr_values and max_age, which the sign-in that approves it
	// meets as an authorization request's do (flow.MFA, flow.MaxAge); MaxAge nil: not asked.
	MFA    bool `json:"mfa,omitempty"`
	MaxAge *int `json:"ma,omitempty"`
	// Decision is "" while pending, then "allow" (with the approving user's sign-in below) or "deny".
	Decision   string                 `json:"d,omitempty"`
	UserID     string                 `json:"u,omitempty"`
	OrgID      string                 `json:"o,omitempty"`
	SessionID  string                 `json:"s,omitempty"`
	AuthTime   int64                  `json:"at,omitempty"`
	AMR        []string               `json:"amr,omitempty"`
	IdP        string                 `json:"idp,omitempty"`  // codeData.IdP
	Upstream   []string               `json:"uamr,omitempty"` // codeData.UpstreamAMR
	Account    *model.UpstreamAccount `json:"upa,omitempty"`  // codeData.Upstream
	GrantID    string                 `json:"g,omitempty"`    // codeData.GrantID
	ConsentGen int64                  `json:"cg,omitempty"`   // codeData.ConsentGen: the client's when the user approved
	AppFence   uint32                 `json:"af,omitempty"`   // codeData.AppFence: the session's when the user approved
	// Held and Polls are the charges for the sign-in against what the address that started it may hold (its record
	// and what goes with it; the record of its polls), given back when it ends: its tokens issued, or its refusal
	// collected (endDevice). Nil when that budget was off.
	Held  *ephemeral.Held `json:"h,omitempty"`
	Polls *ephemeral.Held `json:"hp,omitempty"`
}

// devicePoll is when the device last polled, and how far apart its polls must be (it grows with every slow_down).
type devicePoll struct {
	Last     int64 `json:"l"` // unix nanos
	Interval int   `json:"i"` // seconds
}

func (d *deviceGrant) ttl() time.Duration { return time.Until(time.Unix(d.Expires, 0)) }

// newUserCode returns a random user code, normalised (no separator).
func newUserCode() (string, error) {
	b := make([]byte, userCodeLen)
	n := big.NewInt(int64(len(userCodeAlphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		b[i] = userCodeAlphabet[v.Int64()]
	}
	return string(b), nil
}

// formatUserCode shows a normalised code as two groups: WDJB-MJHT.
func formatUserCode(c string) string {
	if len(c) != userCodeLen {
		return c
	}
	return c[:4] + "-" + c[4:]
}

// normUserCode turns what someone typed into a normalised code: case, spaces and dashes do not matter. It returns ""
// for anything that cannot be a code.
func normUserCode(s string) string {
	if len(s) > 32 {
		return ""
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ' || r == '\t':
		case strings.ContainsRune(userCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return ""
		}
	}
	if b.Len() != userCodeLen {
		return ""
	}
	return b.String()
}

// handleDeviceAuthorization is POST /o/<org>/oauth/device_authorization (RFC 8628 §3.1): client authentication (or a
// public client's client_id), scope and resource -> device_code, user_code, verification URIs, lifetime and poll
// interval. acr_values and max_age are taken as an authorization request takes them: they decide the sign-in the user
// approves with (a second factor, a recent sign-in).
func (p *Provider) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, oerr("invalid_request", "the request body could not be read"))
		return
	}
	form := r.PostForm
	if dup := repeated(form); dup != "" {
		writeOAuthError(w, oerr("invalid_request", dup+" is repeated"))
		return
	}
	ctx := r.Context()
	n, err := p.s.Eph.Incr(ctx, nsRateOIDC, "device-start|"+web.RateKeyIP(r), 1, time.Minute)
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	if n > deviceStartsPerIP {
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down",
			desc: "too many device sign-ins from this address; try again in a minute", retry: true})
		return
	}
	ce, e := p.authenticateClient(r, true)
	if e != nil {
		writeOAuthError(w, e)
		return
	}
	c := ce.c
	if !slices.Contains(c.GrantTypes, service.GrantDeviceCode) || c.SelfRegistered || c.FAPI {
		writeOAuthError(w, oerr("unauthorized_client", "the client may not use the device authorization grant"))
		return
	}
	scopes := dedupe(splitScope(form.Get("scope")))
	if len(scopes) == 0 {
		scopes = slices.Clone(c.Scopes)
	}
	if !subset(scopes, c.Scopes) {
		writeOAuthError(w, oerr("invalid_scope", "the requested scope is not available to this client"))
		return
	}
	res, err := parseResources(form["resource"])
	if err != nil {
		writeOAuthError(w, oerr("invalid_target", err.Error()))
		return
	}
	if !subset(res, c.Resources) {
		writeOAuthError(w, oerr("invalid_target", "the resource is not registered for this client"))
		return
	}
	ad, e := parseAuthDetailsParam(form.Get("authorization_details"), c)
	if e != nil {
		writeOAuthError(w, e)
		return
	}
	var maxAge *int
	if v := form.Get("max_age"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeOAuthError(w, oerr("invalid_request", "max_age must be a non-negative integer"))
			return
		}
		maxAge = &n
	}
	// A fresh user code: one already waiting is never handed out twice.
	var userCode string
	for range 5 {
		uc, err := newUserCode()
		if err != nil {
			writeOAuthError(w, serverError(err))
			return
		}
		if _, err := p.s.Eph.Get(ctx, nsDeviceUser, uc); errors.Is(err, ephemeral.ErrNotFound) {
			userCode = uc
			break
		}
	}
	if userCode == "" {
		writeOAuthError(w, serverError(errors.New("no free user code")))
		return
	}
	d := deviceGrant{GrantID: model.NewID(), ClientID: c.ID, Scopes: scopes, Resources: res, ADTypes: ad, UserCode: userCode, Expires: time.Now().Add(deviceTTL).Unix(),
		MFA: demandsMFA(strings.Fields(form.Get("acr_values"))), MaxAge: maxAge}
	// A public client's request is anyone's: what it has this server keep until the sign-in is decided or expires
	// (the sign-in, its user code, the right to decide it, the times it is polled at, and what the decision adds) is
	// charged to its address (limits.held_kb), as a sign-in flow is, so that the number of device sign-ins an
	// address has waiting is bounded by what they hold, not only by how fast it may start them. A confidential
	// client's is charged the same way: the request is cheap to make with any client's credentials. The record of
	// its polls is a guard record, charged against the address's far smaller part of those (ChargeGuard), so that
	// the device sign-ins of a few addresses cannot fill the room every tenant's code redemptions need. Both are
	// given back when the sign-in ends (endDevice): devices signing in one after another from an address many
	// people share are bounded by how many wait at once, not by how many there were in twenty minutes.
	holder := web.HolderIP(r)
	held, err := p.s.Held.Charge(ctx, holder, nsDevice, len(ephemeral.JSON(d))+deviceExtraCost, deviceTTL)
	if err == nil {
		if d.Polls, err = p.s.Held.ChargeGuard(ctx, holder, nsDevicePoll, devicePollCost, deviceTTL); err != nil {
			held.Refund(ctx, p.s.Eph)
		}
	}
	d.Held = held
	b := ephemeral.JSON(d)
	if errors.Is(err, ephemeral.ErrHeld) { // counted by the budget
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down",
			desc: "too many device sign-ins from this address are waiting; finish one, or try again in a few minutes", retry: true})
		return
	}
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	deviceCode, err := p.s.Eph.New(ctx, nsDevice, b, deviceTTL)
	if err == nil { // kept by the node that holds the sign-in (the device code names it)
		err = p.s.Eph.Set(ctx, nsDeviceTurn, deviceCode, []byte{1}, deviceTTL)
	}
	if err == nil {
		err = p.s.Eph.Set(ctx, nsDeviceUser, userCode, []byte(deviceCode), deviceTTL)
	}
	if err != nil {
		held.Refund(ctx, p.s.Eph)
		d.Polls.Refund(ctx, p.s.Eph)
		writeOAuthError(w, serverError(err))
		return
	}
	if p.cfg.Audit.Tokens {
		record := func(detail map[string]string) {
			detail["scopes"] = strings.Join(scopes, " ")
			p.auditClient(ctx, c, nil, "oauth.device.start", detail)
		}
		if c.Public() {
			// Anyone can start a public client's device sign-ins, thirty a minute from each address: an event for
			// each would make the audit log the target. One per client and address a minute, the next saying how
			// many were held back (service.AuditDeviceStart).
			p.svc.AuditDeviceStart(c.OrgID, c.ID+"|"+web.RateKeyIP(r), record)
		} else {
			record(map[string]string{})
		}
	}
	o := newObj(512)
	o.str("device_code", deviceCode)
	o.str("user_code", formatUserCode(userCode))
	verify := p.cfg.OrgEndpoints(c.OrgID).DeviceVerification
	o.str("verification_uri", verify)
	o.str("verification_uri_complete", verify+"?user_code="+url.QueryEscape(formatUserCode(userCode)))
	o.num("expires_in", int64(deviceTTL/time.Second))
	o.num("interval", deviceInterval)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(o.bytes())
}

// deviceToken is the token endpoint's device_code grant (RFC 8628 §3.4, §3.5): authorization_pending until the user
// decides (slow_down for a device polling faster than its interval), then the tokens once, or access_denied.
func (p *Provider) deviceToken(ctx context.Context, c *model.Client, deviceCode string, ad []string, jkt string) (*tokenResponse, *oauthError) {
	if deviceCode == "" || len(deviceCode) > 200 {
		return nil, oerr("invalid_request", "device_code is required")
	}
	expired := oerr("expired_token", "the device code has expired: start again")
	raw, err := p.s.Eph.Get(ctx, nsDevice, deviceCode)
	if errors.Is(err, ephemeral.ErrNotFound) {
		return nil, expired
	}
	if err != nil {
		return nil, serverError(err)
	}
	var d deviceGrant
	if json.Unmarshal(raw, &d) != nil || d.ClientID != c.ID {
		return nil, oerr("invalid_grant", "the device code was not issued to this client")
	}
	switch d.Decision {
	case "":
		return nil, p.devicePending(ctx, deviceCode, &d)
	case "deny":
		if _, err := p.s.Eph.Take(ctx, nsDevice, deviceCode); err == nil { // the one poll that collects the refusal
			p.endDevice(ctx, deviceCode, &d)
		}
		return nil, oerr("access_denied", "the user denied the sign-in")
	}
	// Checked before the approval is taken: a request that asks for more than the device did is refused, and the
	// next poll can still have the tokens.
	ad, oe := narrowAuthDetails(ad, d.ADTypes)
	if oe != nil {
		return nil, oe
	}
	// Approved: the tokens are issued once, whichever poll takes them first. A failure of ours (5xx) puts the
	// approval back for the next poll, rather than making the user approve again.
	if _, err := p.s.Eph.Take(ctx, nsDevice, deviceCode); err != nil {
		return nil, expired
	}
	// Put back by the poll that took it (nobody else can have it meanwhile), until the moment it was to expire at.
	// A sign-in that is back is still its address's: its charges are given back by the poll that ends it.
	restore := func(oe *oauthError) *oauthError {
		if left := d.ttl(); oe != nil && oe.status >= 500 && left > 0 && p.s.Eph.Set(ctx, nsDevice, deviceCode, raw, left) == nil {
			return oe
		}
		p.endDevice(ctx, deviceCode, &d)
		return oe
	}
	// The approver's role is checked on the user as they are now (userGrant then checks the rest about them); a
	// user that cannot be read decides nothing, and a user that is gone is refused by userGrant.
	u, err := p.user(ctx, d.UserID)
	if err != nil && !gone(err) {
		return nil, restore(serverError(unavailable(err)))
	}
	if err == nil && u.Role.Privileged() && !c.DevicePrivileged {
		return nil, restore(oerr("access_denied", "managers and administrators may not approve this application's device sign-ins"))
	}
	cd := codeData{ClientID: c.ID, SessionID: d.SessionID, UserID: d.UserID, OrgID: d.OrgID, AuthTime: d.AuthTime,
		AMR: d.AMR, IdP: d.IdP, UpstreamAMR: d.Upstream, Upstream: d.Account, Scopes: d.Scopes, Resources: d.Resources, ADTypes: d.ADTypes, GrantID: d.GrantID, ConsentGen: d.ConsentGen,
		AppFence: d.AppFence}
	tr, _, oe := p.userGrant(ctx, c, &cd, nil, ad, jkt, "device_code") // the approved resources, grantResources
	return tr, restore(oe)
}

// endDevice is called once for a device sign-in d that has ended, by the poll that took it: the record of its polls
// goes, and what its address was charged for it is given back (handleDeviceAuthorization).
func (p *Provider) endDevice(ctx context.Context, deviceCode string, d *deviceGrant) {
	_ = p.s.Eph.Delete(context.WithoutCancel(ctx), nsDevicePoll, deviceCode)
	d.Held.Refund(ctx, p.s.Eph)
	d.Polls.Refund(ctx, p.s.Eph)
}

// devicePending answers a poll of a sign-in the user has not decided: slow_down when it came sooner than the device's
// interval (which then grows by five seconds, RFC 8628 §3.5), authorization_pending otherwise.
func (p *Provider) devicePending(ctx context.Context, deviceCode string, d *deviceGrant) *oauthError {
	pending := oerr("authorization_pending", "the user has not finished signing in yet")
	var pl devicePoll
	if raw, err := p.s.Eph.Get(ctx, nsDevicePoll, deviceCode); err == nil {
		_ = json.Unmarshal(raw, &pl)
	}
	if pl.Interval == 0 {
		pl.Interval = deviceInterval
	}
	now := time.Now()
	slow := pl.Last != 0 && now.Sub(time.Unix(0, pl.Last)) < time.Duration(pl.Interval)*time.Second
	if slow {
		pl.Interval += 5
	}
	pl.Last = now.UnixNano()
	b, _ := json.Marshal(pl)
	// A poll whose time cannot be kept (the room for these records is full) is told to slow down: the next one could
	// not be told from a first, and a device polling as fast as it likes would never be.
	if err := p.s.Eph.Set(ctx, nsDevicePoll, deviceCode, b, max(d.ttl(), time.Second)); err != nil {
		slow = true
	}
	if slow {
		return oerr("slow_down", "polling too fast: wait longer between requests")
	}
	return pending
}

// ---------------------------------------------------------------------------------------------------------------
// The verification page

// DeviceData feeds pages/device.html.
type DeviceData struct {
	Code  string // what was typed, shown again with an error
	Error string
}

// handleDevicePage is GET /o/<org>/device: the form for the code shown on the device, and with ?user_code= (typed, or from
// verification_uri_complete) the start of the sign-in that approves it.
func (p *Provider) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	typed, given := r.URL.Query().Get("user_code"), r.URL.Query().Has("user_code")
	render := func(status int, msg string) {
		p.s.Render.Render(w, status, "device", p.s.Page(w, r, "Sign in on a device", "", DeviceData{Code: typed, Error: msg}))
	}
	if !given {
		render(http.StatusOK, "")
		return
	}
	ctx := r.Context()
	guessKey := "device-code|" + web.RateKeyIP(r)
	n, err := p.s.Eph.Incr(ctx, nsRateOIDC, guessKey, 0, deviceGuessWindow)
	if err != nil {
		render(http.StatusServiceUnavailable, "Something went wrong. Try again in a moment.")
		return
	}
	if n >= deviceGuessesPerIP {
		render(http.StatusTooManyRequests, "Too many codes were tried from here. Wait 15 minutes, then try again.")
		return
	}
	code := normUserCode(typed)
	if code == "" {
		render(http.StatusBadRequest, "Enter the 8-letter code your device shows, like WDJB-MJHT.")
		return
	}
	d, deviceCode, c, err := p.pendingDevice(ctx, web.Org(r).ID, code)
	if err != nil && !errors.Is(err, ephemeral.ErrNotFound) { // a read that failed says nothing about the code
		render(http.StatusServiceUnavailable, "Something went wrong. Try again in a moment.")
		return
	}
	if err != nil {
		_, _ = p.s.Eph.Incr(ctx, nsRateOIDC, guessKey, 1, deviceGuessWindow)
		render(http.StatusBadRequest, "That code is not valid. It may have expired: check the code on your device, or start again there.")
		return
	}
	f := &flow{Org: c.OrgID, ClientID: c.ClientID(), Scopes: d.Scopes, Resources: d.Resources, MaxAge: -1, MFA: d.MFA, Mode: "query",
		Created: time.Now().UnixNano(), Device: deviceCode}
	if d.MaxAge != nil {
		f.MaxAge = *d.MaxAge
	}
	secret, bind := newFlowSecret()
	f.Bind = bind
	id, ok := p.startFlow(w, r, f)
	if !ok {
		return
	}
	setFlowCookie(w, id, secret)
	p.proceed(w, r, id, f, c)
}

// pendingDevice finds the undecided device sign-in of a normalised user code in organization orgID, and its client
// (enabled, still allowed the grant, and the organization's: another's codes are not valid here). It answers
// ephemeral.ErrNotFound for a code that is not valid, and another error when a read failed.
func (p *Provider) pendingDevice(ctx context.Context, orgID, code string) (*deviceGrant, string, *model.Client, error) {
	dc, err := p.s.Eph.Get(ctx, nsDeviceUser, code)
	if err != nil {
		return nil, "", nil, err
	}
	raw, err := p.s.Eph.Get(ctx, nsDevice, string(dc))
	if err != nil {
		return nil, "", nil, err
	}
	var d deviceGrant
	if json.Unmarshal(raw, &d) != nil || d.Decision != "" {
		return nil, "", nil, ephemeral.ErrNotFound
	}
	ce, err := p.recordClient(ctx, d.ClientID)
	if gone(err) {
		return nil, "", nil, ephemeral.ErrNotFound
	}
	if err != nil {
		return nil, "", nil, err
	}
	if ce.c.OrgID != orgID || !ce.c.Enabled || !slices.Contains(ce.c.GrantTypes, service.GrantDeviceCode) {
		return nil, "", nil, ephemeral.ErrNotFound
	}
	return &d, string(dc), ce.c, nil
}

// decideDevice records the user's decision on the device sign-in a flow approves (an approval with the client's
// consent generation as it was approved, gen). It answers ephemeral.ErrNotFound when the sign-in has expired or was
// decided already (another browser with the same code), and another error when a store failed. Its user code stops
// working once the decision is taken.
func (p *Provider) decideDevice(ctx context.Context, f *flow, allow bool, sess *model.Session, u *model.User, idp string, gen int64) error {
	raw, err := p.s.Eph.Get(ctx, nsDevice, f.Device)
	if err != nil {
		return err
	}
	var d deviceGrant
	if json.Unmarshal(raw, &d) != nil || d.Decision != "" || d.ttl() <= 0 {
		return ephemeral.ErrNotFound
	}
	// One decision per sign-in, whichever browser makes it first. The sign-in itself stays readable meanwhile: a
	// poll in between is still pending (taking it away would answer expired_token, which ends the device's flow).
	if _, err := p.s.Eph.Take(ctx, nsDeviceTurn, f.Device); err != nil {
		return err
	}
	_ = p.s.Eph.Delete(ctx, nsDeviceUser, d.UserCode)
	d.Decision = "deny"
	if allow {
		d.Decision = "allow"
		d.UserID, d.OrgID, d.SessionID, d.AuthTime, d.AMR = u.ID, u.OrgID, sess.ID, sess.AuthTime.Unix(), sess.AMR
		d.IdP, d.Upstream, d.Account = idp, sess.UpstreamAMR, upstreamAccount(idp, sess)
		d.ConsentGen, d.AppFence = gen, sess.AppFence(d.ClientID)
	}
	// Only if the sign-in is still there, and until the moment it was to expire at (Store.Replace): one that expired
	// since it was read is not made again by its decision.
	return p.s.Eph.Replace(ctx, nsDevice, f.Device, ephemeral.JSON(d))
}

// deviceRespond ends a device flow in the browser, where an authorization flow would answer at the redirect URI:
// a declined or refused sign-in tells the device (access_denied), and the user reads what happened.
func (p *Provider) deviceRespond(w http.ResponseWriter, r *http.Request, f *flow, params url.Values) {
	switch params.Get("error") {
	case "access_denied":
		if f.Device != "" {
			p.decideDevice(r.Context(), f, false, nil, nil, "", 0)
		}
		p.message(w, r, http.StatusOK, "Device sign-in cancelled", "Your device was not signed in",
			"You can close this page.")
	default:
		p.message(w, r, http.StatusBadRequest, "Device sign-in failed", "Your device could not be signed in",
			"Start again on your device to get a new code.")
	}
}
