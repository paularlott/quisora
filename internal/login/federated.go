package login

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/upstream"
	"github.com/paularlott/quisora/internal/web"
)

// stateCookie binds an upstream sign-in to the browser that started it (the state alone is not enough: login CSRF).
const stateCookie = "__Host-quisora_up"

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
	authURL, state, err := m.Upstream.BeginTenant(ctx, org, p, next, tenant)
	if err != nil {
		m.s.Log.Warn("upstream begin", "provider", p.Name, "error", err)
		back("failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(upstream.StateTTL.Seconds())})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// providerCallback handles GET /o/{org}/login/callback/{provider}: the provider sends the browser back to its own
// address, which is its organization's (upstream.CallbackURL): a sign-in started for another organization than the
// path's is refused as any unknown state is.
func (m *Module) providerCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	pathOrg := web.Org(r)
	var browser string
	if c, err := r.Cookie(stateCookie); err == nil {
		browser = c.Value
	}
	// Rate-limited first: a refused callback leaves the state cookie, so the user's sign-in can still finish.
	if !m.rateLimit(w, r, pathOrg.ID+"|callback", known{any: true}) {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
	state, provider := q.Get("state"), r.PathValue("provider")
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
		if org == nil { // the state was not valid: back to the organization's sign-in page, with nothing of the attempt
			org = pathOrg
		}
		m.audit(r, "login.failure", org, u, "", detail)
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
		m.audit(r, "login.failure", res.Org, res.User, "", map[string]string{"reason": "provider not allowed for tenant",
			"provider": res.Provider.Name})
		http.Redirect(w, r, loginURL(res.Org, res.Next, res.Tenant, "disabled"), http.StatusFound)
		return
	}
	// The provider sign-in is a first factor: the user's own second factor follows when they have one or MFA is
	// required (the sign-in page continues with the step). A provider trusted to ask for a second factor itself
	// (TrustMFA) counts as both for plain users; managers and above always give their own second factor here.
	amr := []string{"fed"}
	var step stepResp
	if res.Provider.TrustMFA && !res.User.Role.Privileged() {
		amr = append(amr, "mfa")
	} else {
		step, err = m.secondFactor(r, res.User, eff, ticket{Next: res.Next, AMR: amr, Tenant: res.Tenant, Provider: res.Provider.ID,
			UpstreamAMR: res.Claims.AMR})
	}
	if errors.Is(err, errFactorLost) {
		m.audit(r, "login.failure", res.Org, res.User, "", map[string]string{"reason": "second factor unusable",
			"provider": res.Provider.Name})
		http.Redirect(w, r, loginURL(res.Org, res.Next, res.Tenant, "factor_lost"), http.StatusFound)
		return
	}
	if err != nil {
		m.s.Log.Error("ticket", "error", err)
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
	dest, err := m.completeWith(w, r, res.User, res.Org, web.SessionOptions{AMR: amr, Provider: res.Provider.ID, UpstreamAMR: res.Claims.AMR}, res.Next)
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
	"failed":      "Signing in with that provider did not work. Please try again.",
	"denied":      "Sign-in with that provider was cancelled.",
	"not_linked":  "No account here is linked to that identity. Ask an administrator for access.",
	"unverified":  "That provider has not verified your email address, so an account could not be created.",
	"domain":      "Your email domain is not allowed to sign in to this organization.",
	"exists":      "An account with your email address already exists. Sign in the way you usually do; an administrator can link this provider.",
	"disabled":    "This sign-in method or account is disabled.",
	"factor_lost": msgFactorLost,
	"connect":     "Your account manages others, so it is not linked to a provider automatically. Sign in the usual way, then connect this provider on your account page.",
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
