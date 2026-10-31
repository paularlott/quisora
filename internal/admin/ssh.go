package admin

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// The management API of a tenant's SSH certificate authority (docs/design/ssh-ca.md): settings, CA keys, issued
// certificates and host certificates. The service layer decides who may do what (administrators of the
// organization, and service accounts with the ssh scope, or ssh:host for signing host certificates).

// sshKeyView is a CA key as the management API shows it.
type sshKeyView struct {
	ID          string    `json:"id"`
	Purpose     string    `json:"purpose"`
	Alg         string    `json:"alg"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	RetireAt    time.Time `json:"retire_at,omitzero"`
	Expires     time.Time `json:"expires,omitzero"`
	// State is "next" (published, not signing yet), "active" (signs now) or "retired" (no longer signs).
	State string `json:"state"`
}

func sshKeyViewOf(k *model.SSHKey, fingerprint, state string) sshKeyView {
	return sshKeyView{ID: k.ID, Purpose: k.Purpose, Alg: k.Alg, PublicKey: k.PublicKey, Fingerprint: fingerprint,
		NotBefore: k.NotBefore, RetireAt: k.RetireAt, Expires: k.Expires, State: state}
}

// sshEndpoints are the addresses servers and people use: the discovery document that `quisora ssh` starts from, the
// CA key lists, the revocation list and where host certificates are signed.
type sshEndpoints struct {
	Discovery  string `json:"discovery"`
	CAPub      string `json:"ca_pub"`
	KnownHosts string `json:"known_hosts"`
	KRL        string `json:"krl"`
	HostSign   string `json:"host_sign"`
}

// sshView is a tenant's SSH settings (the same names the PATCH takes) with its CA keys and endpoints.
type sshView struct {
	model.TenantSSH
	Keys      []sshKeyView `json:"keys"`
	Endpoints sshEndpoints `json:"endpoints"`
}

func (m *Module) sshView(v *service.SSHView) sshView {
	t := v.Tenant
	pub := m.s.Cfg.Server.PublicURL
	disc := m.s.Cfg.OrgIssuer(t.OrgID) + "/ssh/" + t.ID
	out := sshView{TenantSSH: v.Settings, Keys: []sshKeyView{}, Endpoints: sshEndpoints{
		Discovery: disc, CAPub: disc + "/ca.pub", KnownHosts: disc + "/known_hosts", KRL: disc + "/krl",
		HostSign: pub + "/api/orgs/" + t.OrgID + "/tenants/" + t.ID + "/ssh/host-certificates"}}
	if out.SourceAddresses == nil {
		out.SourceAddresses = []string{}
	}
	if out.HostPatterns == nil {
		out.HostPatterns = []string{}
	}
	for _, k := range v.Keys {
		out.Keys = append(out.Keys, sshKeyViewOf(k.SSHKey, k.Fingerprint, k.State))
	}
	return out
}

// sshTenant resolves the organization and the tenant of a route, for the actor.
func (m *Module) sshTenant(w http.ResponseWriter, r *http.Request) (*model.Tenant, *service.Actor, bool) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return nil, nil, false
	}
	t, found := m.tenantFor(w, r, org, a)
	return t, a, found
}

// writeSSH answers with the tenant's current SSH settings, keys and endpoints.
func (m *Module) writeSSH(w http.ResponseWriter, r *http.Request, a *service.Actor, t *model.Tenant, status int) {
	v, err := m.s.Svc.GetTenantSSH(r.Context(), a, t.ID)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	web.WriteJSON(w, status, m.sshView(v))
}

func (m *Module) getSSH(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.sshTenant(w, r)
	if !found {
		return
	}
	m.writeSSH(w, r, a, t, http.StatusOK)
}

// updateSSH changes the settings the request names; the others keep their values.
func (m *Module) updateSSH(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.sshTenant(w, r)
	if !found {
		return
	}
	var in service.SSHSettingsInput
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	if _, err := m.s.Svc.UpdateTenantSSH(r.Context(), a, t.ID, in); err != nil {
		web.WriteError(w, err)
		return
	}
	m.writeSSH(w, r, a, t, http.StatusOK)
}

// rotateSSH makes the tenant's user or host CA key a successor. After a recent re-authentication, as for the signing
// keys: an immediate rotation cuts off every server that has not fetched the new key yet.
func (m *Module) rotateSSH(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.sshTenant(w, r)
	if !found || !m.stepUp(w, r) {
		return
	}
	var in struct {
		Purpose   string `json:"purpose"`
		Immediate bool   `json:"immediate"`
	}
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	k, err := m.s.Svc.RotateSSHKey(r.Context(), a, t.ID, in.Purpose, in.Immediate)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	state := service.SSHKeyActive
	if k.NotBefore.After(time.Now()) {
		state = service.SSHKeyNext
	}
	web.WriteJSON(w, http.StatusCreated, sshKeyViewOf(k, service.SSHKeyFingerprint(k), state))
}

// removeSSHKey removes a CA key that no longer signs: servers stop trusting the certificates it signed when they next
// fetch the key list. After a recent re-authentication.
func (m *Module) removeSSHKey(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.sshTenant(w, r)
	if !found || !m.stepUp(w, r) {
		return
	}
	if err := m.s.Svc.RemoveSSHKey(r.Context(), a, t.ID, r.PathValue("key")); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// listSSHCerts lists the tenant's certificates, newest first, a page at a time as the users are listed (total counts
// every match): ?q=<search>&offset=&limit=&user=<id>&status=active|revoked|expired|all&host=true|false. The search
// matches a user's username or name, a principal, the key's fingerprint, the serial and the key id by their start.
func (m *Module) listSSHCerts(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.sshTenant(w, r)
	if !found {
		return
	}
	v := r.URL.Query()
	q := listQuery(r)
	f := service.SSHCertFilter{UserID: v.Get("user"), Status: v.Get("status"), Search: q.Search, Offset: q.Offset, Limit: q.Limit}
	if h := v.Get("host"); h != "" {
		host, err := strconv.ParseBool(h)
		if err != nil {
			web.WriteError(w, service.Invalid("host", "true or false"))
			return
		}
		f.Host = &host
	}
	items, total, err := m.s.Svc.ListSSHCertsCounted(r.Context(), a, t.ID, f)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	writeList(w, items, total)
}

// userSSHCert is one of a user's certificates as the user's page lists it: the certificate, with its tenant's display
// name and address name (what the tenant's pages are under).
type userSSHCert struct {
	*service.SSHCertView
	Tenant     string `json:"tenant"`
	TenantName string `json:"tenant_name"`
}

// listUserSSHCerts handles GET /users/{id}/ssh-certificates: the user's certificates that have not expired, newest
// first, across the organization's tenants (every one, no paging: a user holds a handful at most).
func (m *Module) listUserSSHCerts(w http.ResponseWriter, r *http.Request) {
	org, a, found := m.orgFor(w, r)
	if !found {
		return
	}
	u, found := m.userFor(w, r, org, a)
	if !found {
		return
	}
	views, err := m.s.Svc.SSHCertsOfUser(r.Context(), a, u)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	tenants := map[string]*model.Tenant{}
	out := make([]userSSHCert, 0, len(views))
	for _, v := range views {
		t, seen := tenants[v.TenantID]
		if !seen {
			t, _ = m.s.Svc.Tenants.GetIn(r.Context(), org.ID, v.TenantID) // gone: nothing to name
			tenants[v.TenantID] = t
		}
		c := userSSHCert{SSHCertView: v}
		if t != nil {
			c.Tenant, c.TenantName = cmp.Or(t.DisplayName, t.Name), t.Name
		}
		out = append(out, c)
	}
	writeList(w, out, len(out))
}

func (m *Module) revokeSSHCert(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.sshTenant(w, r)
	if !found {
		return
	}
	id := r.PathValue("cert")
	// the certificate must be one of this tenant's (the service looks it up in the organization)
	if c, err := m.s.Svc.SSHCerts.GetIn(r.Context(), t.OrgID, id); err == nil && c.TenantID != t.ID {
		web.WriteError(w, service.ErrNotFound)
		return
	}
	if err := m.s.Svc.RevokeSSHCert(r.Context(), a, t.OrgID, id); err != nil {
		web.WriteError(w, err)
		return
	}
	ok(w)
}

// hostCertificate is a host certificate signed, as a person or script that asks for one gets it.
type hostCertificate struct {
	Certificate string    `json:"certificate"`
	Serial      string    `json:"serial"`
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

// signHostSSH signs a host certificate for the tenant: {"public_key", "principals", "ttl_days"?}.
func (m *Module) signHostSSH(w http.ResponseWriter, r *http.Request) {
	t, a, found := m.sshTenant(w, r)
	if !found {
		return
	}
	var in struct {
		PublicKey  string   `json:"public_key"`
		Principals []string `json:"principals"`
		TTLDays    int      `json:"ttl_days"`
	}
	if !web.DecodeJSON(w, r, &in) {
		return
	}
	if in.TTLDays < 0 {
		web.WriteError(w, service.Invalid("ttl_days", "a number of days, at least 1"))
		return
	}
	// Per administrator or service account, counted before anything is signed (what is refused counts too).
	actor := a.ClientID
	if actor == "" {
		actor = a.UserID
	}
	within, err := m.s.SSHHostSignAllowed(r.Context(), actor)
	switch {
	case err != nil:
		web.WriteError(w, fmt.Errorf("%w: %v", service.ErrUnavailable, err))
		return
	case !within:
		w.Header().Set("Retry-After", "60")
		web.WriteJSON(w, http.StatusTooManyRequests, web.ErrorBody{Error: "Too many host certificates were requested. Wait a minute and try again."})
		return
	}
	got, err := m.s.Svc.SignHostSSH(r.Context(), a, t.ID, service.SSHHostRequest{PublicKey: in.PublicKey,
		Principals: in.Principals, TTL: time.Duration(in.TTLDays) * 24 * time.Hour})
	if err != nil {
		var fe *service.FieldError
		var refusal *service.SSHRefusal
		switch {
		case errors.As(err, &fe) && fe.Field == "ttl":
			web.WriteError(w, service.Invalid("ttl_days", "between 1 day and the tenant's host certificate lifetime"))
		case errors.As(err, &refusal): // says why, which the person asking should be told
			web.WriteJSON(w, http.StatusForbidden, web.ErrorBody{Error: web.Capitalise(refusal.Msg) + "."})
		default:
			if !errors.Is(err, service.ErrForbidden) && !errors.Is(err, service.ErrNotFound) && !errors.Is(err, service.ErrInvalid) && !service.IsUnavailable(err) {
				m.s.Log.Error("admin: signing an SSH host certificate", "org", t.OrgID, "tenant", t.ID, "actor", a.Name, "error", err)
			}
			web.WriteError(w, err)
		}
		return
	}
	c := got.Cert
	web.WriteJSON(w, http.StatusOK, hostCertificate{Certificate: got.Certificate, Serial: strconv.FormatUint(c.Serial, 10),
		KeyID: c.KeyID, Principals: c.Principals, ValidAfter: c.ValidAfter, ValidBefore: c.ValidBefore})
}
