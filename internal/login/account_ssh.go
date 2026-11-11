package login

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// SSH certificates on the account page (docs/design/ssh-ca.md): the tenants whose SSH the user may use, a key pasted
// in to be certified, and the user's own certificates, which they may revoke. The service decides everything and
// audits it; these handlers add what only a session knows (how it signed in, and when it last confirmed who it is).

type sshTenantItem struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Principals []string `json:"principals"`
	URL        string   `json:"url"`     // the discovery URL, for quisora ssh login
	Command    string   `json:"command"` // quisora ssh login <url>
	CertTTL    int      `json:"cert_ttl"`
}

// sshBlockedItem is a tenant with SSH on that the user may use but gets no certificate for, and why (service.SSHBlocked…).
type sshBlockedItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type sshCertItem struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Tenant      string    `json:"tenant"`
	Serial      string    `json:"serial"`
	Principals  []string  `json:"principals"`
	Fingerprint string    `json:"fingerprint"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
	Via         string    `json:"via"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
}

func tenantTitle(t *model.Tenant) string {
	if t.DisplayName != "" {
		return t.DisplayName
	}
	return t.Name
}

// sshSession is how the account page's session signed in, for the tenant's sign-in methods.
func sshSession(a acct) *service.SSHSession {
	return &service.SSHSession{AMR: a.sess.AMR, Provider: a.sess.Provider}
}

// getSSH handles GET /o/{org}/api-internal/account/ssh: the tenants the user may get certificates from, whether the
// session may (a second factor), and the user's certificates that have not expired.
func (m *Module) getSSH(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	// usable only where the tenant accepts how the session signed in; the others the user has access to, with why not
	uses, blocked, err := m.s.Svc.SSHAccountTenants(ctx, a.u, sshSession(a))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	base := strings.TrimRight(m.s.Cfg.Server.PublicURL, "/")
	tenants := make([]sshTenantItem, 0, len(uses))
	names := map[string]string{}
	for _, use := range uses {
		t := use.Tenant
		discovery := base + web.OrgPath(a.u.OrgID, "/ssh/"+t.ID)
		names[t.ID] = tenantTitle(t)
		tenants = append(tenants, sshTenantItem{ID: t.ID, Name: tenantTitle(t), Principals: use.Principals, URL: discovery,
			Command: "quisora ssh login " + discovery, CertTTL: t.SSH.CertTTL})
	}
	unavailable := make([]sshBlockedItem, 0, len(blocked))
	for _, b := range blocked {
		names[b.Tenant.ID] = tenantTitle(b.Tenant)
		unavailable = append(unavailable, sshBlockedItem{ID: b.Tenant.ID, Name: tenantTitle(b.Tenant), Reason: b.Reason})
	}
	certs := []sshCertItem{}
	if len(tenants)+len(unavailable) > 0 { // nothing of SSH is shown to a user with no tenant of it
		views, err := m.s.Svc.SSHCertsOf(ctx, a.u)
		if err != nil {
			web.WriteError(w, err)
			return
		}
		for _, v := range views {
			if v.Host {
				continue
			}
			name, ok := names[v.TenantID]
			if !ok { // a tenant the user may no longer use
				if t, err := m.s.Svc.Tenants.GetIn(ctx, a.u.OrgID, v.TenantID); err == nil {
					name = tenantTitle(t)
				}
				names[v.TenantID] = name
			}
			certs = append(certs, sshCertItem{ID: v.ID, TenantID: v.TenantID, Tenant: name, Serial: strconv.FormatUint(v.Serial, 10),
				Principals: v.Principals, Fingerprint: v.Fingerprint, ValidAfter: v.ValidAfter, ValidBefore: v.ValidBefore, Via: v.Via,
				Status: v.Status, Reason: v.Reason})
		}
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"tenants": tenants, "unavailable": unavailable, "certificates": certs,
		"mfa": model.MFA(a.sess.AMR)})
}

type sshSignReq struct {
	TenantID  string `json:"tenant_id"`
	PublicKey string `json:"public_key"`
}

// signSSH handles POST /o/{org}/api-internal/account/ssh/sign: {tenant_id, public_key}. A certificate is a sign-in of
// its own, so the session must have used a second factor and confirmed who it is a moment ago (as the API-token
// handlers ask); how old the sign-in may be is then the tenant's MaxAuthAge, which the service checks against the
// later of the sign-in and a re-authentication that used a second factor (authTime). The service also checks that the
// tenant's sign-in methods allow the way the session signed in, as for the sign endpoint, and the requests count
// against the same limits as that endpoint's.
func (m *Module) signSSH(w http.ResponseWriter, r *http.Request, a acct) {
	var in sshSignReq
	if !decode(w, r, &in) {
		return
	}
	if !model.MFA(a.sess.AMR) {
		writeErr(w, http.StatusForbidden, "SSH certificates need a second factor. Sign out and sign in again with a one-time code or a passkey.", "mfa")
		return
	}
	if !m.needReauth(w, r, a) {
		return
	}
	ctx := r.Context()
	within, err := m.s.SSHSignAllowed(ctx, r, a.u.ID)
	if err != nil {
		unavailableResponse(w)
		return
	}
	if !within {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "Too many certificate requests. Wait a minute and try again.", "")
		return
	}
	u, err := m.fresh(ctx, a) // not the per-node cache: a change on another node counts at once
	if err != nil {
		web.WriteError(w, err)
		return
	}
	// The certificate stands on the session: it takes the session's epoch and sign-out stamp, never the current ones.
	issued, err := m.s.Svc.SignUserSSH(ctx, service.SSHUserRequest{Actor: a.actor, User: u, TenantID: in.TenantID, PublicKey: in.PublicKey,
		AMR: a.sess.AMR, AuthTime: m.authTime(ctx, a), Via: "account", Session: sshSession(a),
		SessionEpoch: a.sess.Epoch, Stamp: a.sess.Stamp, Sources: a.sess.Sources, SignIn: a.sess.ID})
	var refusal *service.SSHRefusal
	if errors.As(err, &refusal) {
		writeErr(w, http.StatusForbidden, web.Capitalise(refusal.Msg)+".", "")
		return
	}
	if err != nil {
		web.WriteError(w, err)
		return
	}
	c := issued.Cert
	web.WriteJSON(w, http.StatusOK, map[string]any{"certificate": issued.Certificate, "id": c.ID, "tenant_id": c.TenantID,
		"serial": strconv.FormatUint(c.Serial, 10), "principals": c.Principals, "fingerprint": c.Fingerprint,
		"valid_after": c.ValidAfter, "valid_before": c.ValidBefore})
}

// revokeSSHCert handles POST /o/{org}/api-internal/account/ssh/certificates/{id}/revoke: one of the user's own
// certificates (never someone else's, even an administrator's: they use the management API). Rate limited per user
// (web.SSHRevokesPerUser), as signing is: each revoked certificate is on the tenant's revocation list until it expires.
func (m *Module) revokeSSHCert(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	within, err := m.s.SSHRevokeAllowed(ctx, a.u.ID)
	if err != nil {
		unavailableResponse(w)
		return
	}
	if !within {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "Too many certificates revoked. Wait a minute and try again.", "")
		return
	}
	c, err := m.s.Svc.SSHCerts.GetIn(ctx, a.u.OrgID, r.PathValue("id"))
	if err != nil || c.UserID != a.u.ID {
		writeErr(w, http.StatusNotFound, "Not found.", "")
		return
	}
	if err := m.s.Svc.RevokeSSHCert(ctx, a.actor, a.u.OrgID, c.ID); err != nil {
		web.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
