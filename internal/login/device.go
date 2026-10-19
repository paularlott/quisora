package login

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// Device cookies (OWASP's answer to sign-in lockout): a browser that has signed in to an account gets a signed
// cookie naming that account. A sign-in request that carries one for the account (or org) it is for is counted
// against that account's own budget instead of the client address's, so whoever floods the sign-in endpoints from
// the same address (an office NAT, a load balancer without trusted_proxies) cannot keep people who have signed in
// from this browser before out. The cookie grants nothing else: the password, second factor, lockout and everything
// after are unchanged, and a request without a matching cookie is limited by address as before.

const (
	deviceCookie     = "__Host-quisora_dev"
	deviceTTL        = 90 * 24 * time.Hour
	deviceMaxEntries = 5 // accounts remembered per browser
)

// deviceEntry is one verified account a browser has signed in to.
type deviceEntry struct {
	userID, orgID string
	login         string // loginTag of the email the account signs in with ("" when it has none)
}

// known says which device cookie entry lets a sign-in request through on its own budget: the user when the step
// knows them (a ticket), else the org and the login typed in, else the org; any entry will do only for steps that
// verify nothing guessable (one-time links, passkey assertions, provider callbacks), where it merely moves the caller
// onto their own account's budget.
type known struct {
	userID, orgID, login string
	any                  bool
}

func (k known) match(e deviceEntry) bool {
	switch {
	case k.userID != "":
		return e.userID == k.userID
	case k.orgID != "" && k.login != "":
		return e.orgID == k.orgID && e.login != "" && e.login == k.login
	case k.orgID != "":
		return e.orgID == k.orgID
	}
	return k.any
}

// loginTag is a keyed digest of an org's sign-in email, so the cookie can be matched to what is typed into the
// form without carrying the address itself.
func (m *Module) loginTag(orgID, login string) string {
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(m.s.Svc.Sealer.MAC("login device email", orgID, login)[:12])
}

func (m *Module) deviceMAC(userID, orgID, login, issued string) string {
	return base64.RawURLEncoding.EncodeToString(m.s.Svc.Sealer.MAC("login device", userID, orgID, login, issued)[:16])
}

// devices returns the browser's valid device cookie entries, newest first, with their raw form.
func (m *Module) devices(r *http.Request) (entries []deviceEntry, raw []string) {
	c, err := r.Cookie(deviceCookie)
	if err != nil || len(c.Value) > 4096 {
		return nil, nil
	}
	now := time.Now()
	for _, s := range strings.Split(c.Value, "~") {
		p := strings.Split(s, ".")
		if len(p) != 5 || len(entries) == deviceMaxEntries {
			continue
		}
		issued, err := strconv.ParseInt(p[3], 36, 64)
		if err != nil || now.Sub(time.Unix(issued, 0)) > deviceTTL || time.Unix(issued, 0).After(now.Add(time.Minute)) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(p[4]), []byte(m.deviceMAC(p[0], p[1], p[2], p[3]))) != 1 {
			continue
		}
		entries = append(entries, deviceEntry{userID: p[0], orgID: p[1], login: p[2]})
		raw = append(raw, s)
	}
	return entries, raw
}

// knownDevice returns the user id of the browser's device cookie entry that k accepts.
func (m *Module) knownDevice(r *http.Request, k known) (string, bool) {
	entries, _ := m.devices(r)
	for _, e := range entries {
		if k.match(e) {
			return e.userID, true
		}
	}
	return "", false
}

// rememberDevice records that this browser has signed in as u, keeping the other accounts it remembers.
func (m *Module) rememberDevice(w http.ResponseWriter, r *http.Request, u *model.User) {
	issued := strconv.FormatInt(time.Now().Unix(), 36)
	login := m.loginTag(u.OrgID, u.Email)
	out := []string{strings.Join([]string{u.ID, u.OrgID, login, issued, m.deviceMAC(u.ID, u.OrgID, login, issued)}, ".")}
	entries, raw := m.devices(r)
	for i, e := range entries {
		if e.userID != u.ID && len(out) < deviceMaxEntries {
			out = append(out, raw[i])
		}
	}
	// Lax, not Strict: the browser comes back from an upstream provider by a cross-site redirect.
	http.SetCookie(w, &http.Cookie{Name: deviceCookie, Value: strings.Join(out, "~"), Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(deviceTTL.Seconds())})
}

// knownLogin is the known for a step that names an org and the email to sign in with (no match when the org does
// not exist).
func (m *Module) knownLogin(org *model.Org, login string) known {
	if org == nil {
		return known{}
	}
	tag := m.loginTag(org.ID, login)
	if tag == "" {
		return known{}
	}
	return known{orgID: org.ID, login: tag}
}
