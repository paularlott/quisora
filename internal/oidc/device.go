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
	nsDevicePoll = "oauth.device.poll" // device_code -> devicePoll
	nsDeviceTurn = "oauth.device.turn" // device_code -> the right to decide it, taken by the first decision

	deviceTTL          = 10 * time.Minute
	deviceInterval     = 5 // seconds between polls
	userCodeAlphabet   = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLen        = 8
	deviceGuessesPerIP = 20
	deviceGuessWindow  = 15 * time.Minute
	deviceStartsPerIP  = 30 // device authorization requests per address and minute
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
	Decision  string   `json:"d,omitempty"`
	UserID    string   `json:"u,omitempty"`
	OrgID     string   `json:"o,omitempty"`
	SessionID string   `json:"s,omitempty"`
	AuthTime  int64    `json:"at,omitempty"`
	AMR       []string `json:"amr,omitempty"`
	IdP       string   `json:"idp,omitempty"`  // codeData.IdP
	Upstream  []string `json:"uamr,omitempty"` // codeData.UpstreamAMR
	GrantID   string   `json:"g,omitempty"`    // codeData.GrantID
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
	b, _ := json.Marshal(d)
	deviceCode, err := p.s.Eph.New(ctx, nsDevice, b, deviceTTL)
	if err == nil { // kept by the node that holds the sign-in (the device code names it)
		err = p.s.Eph.Set(ctx, nsDeviceTurn, deviceCode, []byte{1}, deviceTTL)
	}
	if err == nil {
		err = p.s.Eph.Set(ctx, nsDeviceUser, userCode, []byte(deviceCode), deviceTTL)
	}
	if err != nil {
		writeOAuthError(w, serverError(err))
		return
	}
	if p.cfg.Audit.Tokens {
		p.auditClient(ctx, c, nil, "oauth.device.start", map[string]string{"scopes": strings.Join(scopes, " ")})
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
		_ = p.s.Eph.Delete(ctx, nsDevice, deviceCode)
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
	restore := func(oe *oauthError) *oauthError {
		if left := d.ttl(); oe != nil && oe.status >= 500 && left > 0 {
			_ = p.s.Eph.Set(ctx, nsDevice, deviceCode, raw, left)
		}
		return oe
	}
	_ = p.s.Eph.Delete(ctx, nsDevicePoll, deviceCode)
	// The approver's role is checked on the user as they are now (userGrant then checks the rest about them); a
	// user that cannot be read decides nothing, and a user that is gone is refused by userGrant.
	u, err := p.user(ctx, d.UserID)
	if err != nil && !gone(err) {
		return nil, restore(serverError(unavailable(err)))
	}
	if err == nil && u.Role.Privileged() && !c.DevicePrivileged {
		return nil, oerr("access_denied", "managers and administrators may not approve this application's device sign-ins")
	}
	cd := codeData{ClientID: c.ID, SessionID: d.SessionID, UserID: d.UserID, OrgID: d.OrgID, AuthTime: d.AuthTime,
		AMR: d.AMR, IdP: d.IdP, UpstreamAMR: d.Upstream, Scopes: d.Scopes, Resources: d.Resources, ADTypes: d.ADTypes, GrantID: d.GrantID}
	tr, _, oe := p.userGrant(ctx, c, &cd, d.Resources, ad, jkt, "device_code")
	return tr, restore(oe)
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
	_ = p.s.Eph.Set(ctx, nsDevicePoll, deviceCode, b, max(d.ttl(), time.Second))
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
	d, deviceCode, c, ok := p.pendingDevice(ctx, web.Org(r).ID, code)
	if !ok {
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
	b, _ := json.Marshal(f)
	id, err := p.s.Eph.New(ctx, nsFlow, b, flowTTL)
	if err != nil {
		render(http.StatusServiceUnavailable, "Something went wrong. Try again in a moment.")
		return
	}
	setFlowCookie(w, id, secret)
	p.proceed(w, r, id, f, c)
}

// pendingDevice finds the undecided device sign-in of a normalised user code in organization orgID, and its client
// (enabled, still allowed the grant, and the organization's: another's codes are not valid here).
func (p *Provider) pendingDevice(ctx context.Context, orgID, code string) (*deviceGrant, string, *model.Client, bool) {
	dc, err := p.s.Eph.Get(ctx, nsDeviceUser, code)
	if err != nil {
		return nil, "", nil, false
	}
	raw, err := p.s.Eph.Get(ctx, nsDevice, string(dc))
	if err != nil {
		return nil, "", nil, false
	}
	var d deviceGrant
	if json.Unmarshal(raw, &d) != nil || d.Decision != "" {
		return nil, "", nil, false
	}
	ce, err := p.recordClient(ctx, d.ClientID)
	if err != nil || ce.c.OrgID != orgID || !ce.c.Enabled || !slices.Contains(ce.c.GrantTypes, service.GrantDeviceCode) {
		return nil, "", nil, false
	}
	return &d, string(dc), ce.c, true
}

// decideDevice records the user's decision on the device sign-in a flow approves; it reports false when the sign-in
// has expired or was decided already (another browser with the same code). Its user code stops working either way.
func (p *Provider) decideDevice(ctx context.Context, f *flow, allow bool, sess *model.Session, u *model.User, idp string) bool {
	raw, err := p.s.Eph.Get(ctx, nsDevice, f.Device)
	if err != nil {
		return false
	}
	var d deviceGrant
	if json.Unmarshal(raw, &d) != nil || d.Decision != "" || d.ttl() <= 0 {
		return false
	}
	// One decision per sign-in, whichever browser makes it first. The sign-in itself stays readable meanwhile: a
	// poll in between is still pending (taking it away would answer expired_token, which ends the device's flow).
	if _, err := p.s.Eph.Take(ctx, nsDeviceTurn, f.Device); err != nil {
		return false
	}
	_ = p.s.Eph.Delete(ctx, nsDeviceUser, d.UserCode)
	d.Decision = "deny"
	if allow {
		d.Decision = "allow"
		d.UserID, d.OrgID, d.SessionID, d.AuthTime, d.AMR = u.ID, u.OrgID, sess.ID, sess.AuthTime.Unix(), sess.AMR
		d.IdP, d.Upstream = idp, sess.UpstreamAMR
	}
	b, _ := json.Marshal(d)
	return p.s.Eph.Set(ctx, nsDevice, f.Device, b, d.ttl()) == nil
}

// deviceRespond ends a device flow in the browser, where an authorization flow would answer at the redirect URI:
// a declined or refused sign-in tells the device (access_denied), and the user reads what happened.
func (p *Provider) deviceRespond(w http.ResponseWriter, r *http.Request, f *flow, params url.Values) {
	switch params.Get("error") {
	case "access_denied":
		if f.Device != "" {
			p.decideDevice(r.Context(), f, false, nil, nil, "")
		}
		p.message(w, r, http.StatusOK, "Device sign-in cancelled", "Your device was not signed in",
			"You can close this page.")
	default:
		p.message(w, r, http.StatusBadRequest, "Device sign-in failed", "Your device could not be signed in",
			"Start again on your device to get a new code.")
	}
}
