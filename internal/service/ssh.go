package service

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/store"
)

// The SSH certificate authority of a tenant (docs/design/ssh-ca.md): Quisora signs short-lived OpenSSH user
// certificates for people who signed in with a second factor, and longer-lived host certificates for servers. Servers
// trust the tenant's CA keys, and who may log in as which account is decided by the principals in the certificate (the
// user's username, groups and application roles). This file holds the tenant's settings and the SSH application;
// ssh_keys.go the CA keys, ssh_sign.go the signing and ssh_krl.go revocation.

// SSHSettingsInput is the editable part of a tenant's SSH settings; nil leaves a setting as it is.
type SSHSettingsInput struct {
	Enabled *bool `json:"enabled"`

	CertTTL               *int      `json:"cert_ttl"`
	MaxAuthAge            *int      `json:"max_auth_age"`
	PrincipalUsername     *bool     `json:"principal_username"`
	PrincipalGroups       *bool     `json:"principal_groups"`
	PrincipalRoles        *bool     `json:"principal_roles"`
	PermitPTY             *bool     `json:"permit_pty"`
	PermitUserRC          *bool     `json:"permit_user_rc"`
	PermitPortForwarding  *bool     `json:"permit_port_forwarding"`
	PermitAgentForwarding *bool     `json:"permit_agent_forwarding"`
	PermitX11Forwarding   *bool     `json:"permit_x11_forwarding"`
	SourceAddresses       *[]string `json:"source_addresses"`
	AllowPrivileged       *bool     `json:"allow_privileged"`
	RotationDays          *int      `json:"rotation_days"`

	HostCerts    *bool     `json:"host_certs"`
	HostTTLDays  *int      `json:"host_ttl_days"`
	HostPatterns *[]string `json:"host_patterns"`
}

// Limits of the settings.
const (
	sshMinCertTTL     = 300             // seconds
	sshMaxCertTTL     = 86400           // seconds: a day, which the CA's retirement grace (sshRetireGrace) counts on
	sshMinAuthAge     = 60              // seconds
	sshMaxAuthAge     = 86400           // seconds
	sshMaxRotation    = 3650            // days
	sshMaxHostTTLDays = 365             // days
	sshMaxAddresses   = 32              // source addresses
	sshMaxPatterns    = 32              // host patterns
	sshMaxPrincipals  = 32              // host principals of one certificate
	sshBackdate       = 5 * time.Minute // certificates are valid from this long before they are signed (clock skew)
)

// sshPrincipal is what a principal must look like to go into a certificate; others are left out, not refused.
var sshPrincipal = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// applySSH applies in to the settings cur (nil: never enabled, which starts from the defaults), each checked, and
// returns the result.
func applySSH(cur *model.TenantSSH, in SSHSettingsInput) (*model.TenantSSH, error) {
	var c model.TenantSSH
	if cur != nil {
		c = *cur
		c.SourceAddresses = slices.Clone(cur.SourceAddresses)
		c.HostPatterns = slices.Clone(cur.HostPatterns)
	} else {
		c = model.DefaultTenantSSH()
	}
	setB := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	setB(&c.Enabled, in.Enabled)
	setB(&c.PrincipalUsername, in.PrincipalUsername)
	setB(&c.PrincipalGroups, in.PrincipalGroups)
	setB(&c.PrincipalRoles, in.PrincipalRoles)
	setB(&c.PermitPTY, in.PermitPTY)
	setB(&c.PermitUserRC, in.PermitUserRC)
	setB(&c.PermitPortForwarding, in.PermitPortForwarding)
	setB(&c.PermitAgentForwarding, in.PermitAgentForwarding)
	setB(&c.PermitX11Forwarding, in.PermitX11Forwarding)
	setB(&c.AllowPrivileged, in.AllowPrivileged)
	setB(&c.HostCerts, in.HostCerts)
	if in.CertTTL != nil {
		if *in.CertTTL < sshMinCertTTL || *in.CertTTL > sshMaxCertTTL {
			return nil, Invalid("ssh.cert_ttl", "between 300 seconds (5 minutes) and 86400 seconds (24 hours)")
		}
		c.CertTTL = *in.CertTTL
	}
	if in.MaxAuthAge != nil {
		if *in.MaxAuthAge < sshMinAuthAge || *in.MaxAuthAge > sshMaxAuthAge {
			return nil, Invalid("ssh.max_auth_age", "between 60 seconds and 86400 seconds (24 hours)")
		}
		c.MaxAuthAge = *in.MaxAuthAge
	}
	if in.SourceAddresses != nil {
		// The size is checked first: what is checked and de-duplicated afterwards must not grow with what was sent.
		if len(*in.SourceAddresses) > sshMaxAddresses {
			return nil, Invalid("ssh.source_addresses", "at most 32 addresses")
		}
		list, err := sshca.ValidSourceAddresses(*in.SourceAddresses)
		if err != nil {
			return nil, Invalid("ssh.source_addresses", err.Error())
		}
		c.SourceAddresses = list
	}
	if in.RotationDays != nil {
		// A successor is published seven days before it signs (sshRotationLead), so a shorter period has no room.
		if d := *in.RotationDays; d != 0 && (d < 8 || d > sshMaxRotation) {
			return nil, Invalid("ssh.rotation_days", "0 (rotate by hand only), or 8 to 3650 days")
		}
		c.RotationDays = *in.RotationDays
	}
	if in.HostTTLDays != nil {
		if *in.HostTTLDays < 1 || *in.HostTTLDays > sshMaxHostTTLDays {
			return nil, Invalid("ssh.host_ttl_days", "between 1 and 365 days")
		}
		c.HostTTLDays = *in.HostTTLDays
	}
	if in.HostPatterns != nil {
		if len(*in.HostPatterns) > sshMaxPatterns { // before the loop: its de-duplication is quadratic
			return nil, Invalid("ssh.host_patterns", "at most 32 patterns")
		}
		var list []string
		for _, p := range *in.HostPatterns {
			p = strings.ToLower(strings.TrimSpace(p))
			switch {
			case p == "":
				continue
			case !sshca.ValidHostPattern(p):
				return nil, Invalid("ssh.host_patterns", p+" is not a host pattern: use lower-case letters, digits and . : _ - with * and ? as wildcards")
			case !slices.Contains(list, p):
				list = append(list, p)
			}
		}
		c.HostPatterns = list
	}
	if c.Enabled && !c.PrincipalUsername && !c.PrincipalGroups && !c.PrincipalRoles {
		return nil, Invalid("ssh.principal_username", "turn on at least one source of principals: the username, the names of the groups or the application roles")
	}
	if c.HostCerts && len(c.HostPatterns) == 0 {
		return nil, Invalid("ssh.host_patterns", "required when host certificates are on: say which host names may be certified, such as *.example.com")
	}
	return &c, nil
}

// sshAdmin reports whether a may administer SSH in org orgID: an administrator of it, and for a service account the
// scope.
func (s *Service) sshAdmin(a *Actor, orgID, scope string) bool {
	return s.canAdminOrg(a, orgID) && (a.ClientID == "" || a.HasScope(scope))
}

// tenantForSSH returns the tenant tenantID for an actor that administers its SSH (ErrForbidden when a may not,
// ErrNotFound when it is not a tenant of a's organization).
func (s *Service) tenantForSSH(ctx context.Context, a *Actor, tenantID string) (*model.Tenant, error) {
	t, err := s.Tenants.Get(ctx, tenantID)
	if err != nil {
		return nil, mapStore(err)
	}
	switch {
	case a.OrgID != t.OrgID && !a.IsSuper():
		return nil, ErrNotFound // another organization's tenant is not seen
	case !s.sshAdmin(a, t.OrgID, ScopeSSH):
		return nil, ErrForbidden
	}
	return t, nil
}

// UpdateTenantSSH changes a tenant's SSH settings (administrators of the organization, and service accounts with the
// ssh scope). While SSH is enabled it makes what is missing: the user CA key (and the host CA key when host
// certificates are on) and the SSH application, so enabling for the first time creates them, and enabling again, or
// changing a setting, creates nothing twice. The application's device_privileged_users follows AllowPrivileged.
func (s *Service) UpdateTenantSSH(ctx context.Context, a *Actor, tenantID string, in SSHSettingsInput) (*model.Tenant, error) {
	t, err := s.tenantForSSH(ctx, a, tenantID)
	if err != nil {
		return nil, err
	}
	defaults := model.DefaultTenantSSH()
	was := snapshot(&defaults)
	if t.SSH != nil {
		was = snapshot(t.SSH)
	}
	set, err := applySSH(t.SSH, in)
	if err != nil {
		return nil, err
	}
	t.SSH = set
	madeClient := false
	if set.Enabled {
		if madeClient, err = s.ensureSSHClient(ctx, t); err != nil {
			return nil, err
		}
	}
	if err := s.audited(ctx, a, t.OrgID, "ssh.settings.update", t.Name, addChanges(nil, was, set),
		func() error { return s.Tenants.Update(ctx, t) }); err != nil {
		if madeClient {
			s.dropSSHClient(ctx, set.ClientID, err)
		}
		return nil, tenantConflict(err)
	}
	s.InvalidateSSHKRL() // turning SSH off (or on) changes the list at once on this node
	if set.Enabled {
		if err := s.ensureSSHKeys(ctx, a, t); err != nil {
			return nil, err
		}
	}
	if set.ClientID != "" {
		if err := s.syncSSHClient(ctx, t); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// ensureSSHClient makes the tenant's SSH application when it has none (SSH never enabled, or the application was
// deleted), recording it in t.SSH.ClientID, and says whether it made one. It is made as the system: it is a first
// party application, which only super admins may make by hand, and marked as the tenant's (Client.SSHApp). One made
// in place of a deleted one has a new client id: its client.create event names the one it replaces, and it is logged,
// as access entries that name the old one by id do not cover the new one.
func (s *Service) ensureSSHClient(ctx context.Context, t *model.Tenant) (bool, error) {
	old := t.SSH.ClientID
	if old != "" {
		if c, err := s.Clients.Get(ctx, old); err == nil && c.TenantID == t.ID && c.OrgID == t.OrgID {
			return false, nil
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return false, mapStore(err)
		}
	}
	made := clientMade{sshApp: true, detail: map[string]string{"ssh_tenant": t.ID}}
	if old != "" {
		made.detail["replaces"] = old
		made.detail["reason"] = "the tenant's SSH application was deleted while SSH is on: made again, with a new client id"
	}
	c, _, err := s.createClient(ctx, System, t.OrgID, ClientInput{
		TenantID: &t.ID, Name: ptrString("SSH"), Description: ptrString("Signs in to get SSH certificates (quisora ssh login)"),
		AuthMethod: ptrString(model.AuthMethodNone), GrantTypes: &[]string{"authorization_code", GrantDeviceCode},
		RedirectURIs: &[]string{"http://127.0.0.1/callback"}, Scopes: &[]string{"openid", "profile"},
		FirstParty: ptrBool(true), DevicePrivileged: ptrBool(t.SSH.AllowPrivileged),
	}, made)
	if err != nil {
		return false, err
	}
	if old != "" {
		s.Log.Warn("ssh: the tenant's SSH application was deleted while SSH is on, and is made again with a new client id "+
			"(access entries that named the old one do not cover it; turn SSH off to stop certificates instead)",
			"org", t.OrgID, "tenant", t.ID, "old_client", old, "client", c.ID)
	}
	t.SSH.ClientID = c.ID
	return true, nil
}

// removeSSHApps deletes, as the system (audited client.delete), the SSH applications of tenant t (Client.SSHApp) other
// than keep and older than minAge, and says whether the tenant has any application that is not one of its SSH
// applications. Housekeeping removes those left by an enabling whose tenant write failed and was not rolled back (its
// outcome unknown) or whose rollback failed; younger ones may be an enabling's under way. A tenant being deleted
// (keep "") has every one removed, unless another application keeps it (then none is).
func (s *Service) removeSSHApps(ctx context.Context, t *model.Tenant, keep string, minAge time.Duration) (others bool, err error) {
	cs, n, err := s.Clients.List(ctx, store.ListQuery{Scope: t.OrgID, Limit: 100,
		Filters: []store.Filter{{Field: "tenant_id", Value: t.ID}}})
	if err != nil {
		return false, mapStore(err)
	}
	others = n > len(cs) // more than a page: not all of them are SSH applications
	var drop []string
	now := time.Now()
	for _, c := range cs {
		switch {
		case !c.SSHApp:
			others = true
		case c.ID != keep && now.Sub(c.Created) >= minAge:
			drop = append(drop, c.ID)
		}
	}
	if others && keep == "" {
		return true, nil
	}
	for _, id := range drop {
		if err := s.DeleteClient(ctx, System, id); err != nil && !errors.Is(err, ErrNotFound) {
			return others, err
		}
	}
	return others, nil
}

// dropSSHClient deletes the SSH application clientID, made for a change of a tenant whose write then failed with err,
// as the system (audited client.delete): only when the write certainly did not land. One that may have (unavailable,
// or of unknown outcome) keeps it, since the tenant may name it now.
func (s *Service) dropSSHClient(ctx context.Context, clientID string, err error) {
	if IsUnavailable(mapStore(err)) || outcomeUnknown(err) {
		return
	}
	if err := s.DeleteClient(ctx, System, clientID); err != nil && !errors.Is(err, ErrNotFound) {
		s.Log.Warn("the SSH application made for a tenant change that failed could not be deleted", "client", clientID, "error", err)
	}
}

// syncSSHClient keeps the SSH application in step with the settings: enabled while SSH is on and disabled while it is
// off (no one signs in to it for nothing), and its device_privileged_users following AllowPrivileged. An application
// that is gone is left to the next enabling.
func (s *Service) syncSSHClient(ctx context.Context, t *model.Tenant) error {
	c, err := s.Clients.Get(ctx, t.SSH.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return mapStore(err)
	}
	var in ClientInput
	if c.Enabled != t.SSH.Enabled {
		in.Enabled = ptrBool(t.SSH.Enabled)
	}
	if c.DevicePrivileged != t.SSH.AllowPrivileged {
		in.DevicePrivileged = ptrBool(t.SSH.AllowPrivileged)
	}
	if in.Enabled == nil && in.DevicePrivileged == nil {
		return nil
	}
	_, err = s.UpdateClient(ctx, System, c.ID, in)
	return err
}

func ptrString(v string) *string { return &v }

// SSHKeyView is a CA key as the management API shows it.
type SSHKeyView struct {
	*model.SSHKey
	Fingerprint string `json:"fingerprint"`
	// State is "next" (published, not signing yet), "active" (the key that signs now) or "retired" (no longer signs).
	State string `json:"state"`
}

// Key states.
const (
	SSHKeyNext    = "next"
	SSHKeyActive  = "active"
	SSHKeyRetired = "retired"
)

// SSHView is a tenant's SSH settings with its published CA keys.
type SSHView struct {
	Tenant   *model.Tenant
	Settings model.TenantSSH // the defaults for a tenant that never enabled SSH (Enabled false)
	Keys     []*SSHKeyView   // oldest first
}

// GetTenantSSH returns a tenant's SSH settings and published CA keys, to administrators (and service accounts with the
// ssh scope).
func (s *Service) GetTenantSSH(ctx context.Context, a *Actor, tenantID string) (*SSHView, error) {
	t, err := s.tenantForSSH(ctx, a, tenantID)
	if err != nil {
		return nil, err
	}
	v := &SSHView{Tenant: t, Settings: model.DefaultTenantSSH()}
	if t.SSH != nil {
		v.Settings = *t.SSH
	}
	keys, err := s.sshKeysIn(ctx, t, "")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, purpose := range []string{model.SSHPurposeUser, model.SSHPurposeHost} {
		of := sshOfPurpose(keys, purpose)
		signer := sshSigning(of, now)
		for _, k := range of {
			v.Keys = append(v.Keys, &SSHKeyView{SSHKey: k, Fingerprint: SSHKeyFingerprint(k), State: sshKeyState(k, signer, now)})
		}
	}
	return v, nil
}

// SSHTenantByRef returns the tenant of organization orgID that ref names (its id or its name) when SSH is enabled on
// it, for the endpoints that sign: ErrNotFound for an unknown tenant and for one with SSH off, which look alike.
func (s *Service) SSHTenantByRef(ctx context.Context, orgID, ref string) (*model.Tenant, error) {
	t, err := s.SSHTenantPublished(ctx, orgID, ref)
	if err != nil {
		return nil, err
	}
	if !t.SSH.Enabled {
		return nil, ErrNotFound
	}
	return t, nil
}

// SSHTenantPublished returns the tenant of organization orgID that ref names (its id or its name) when it has
// published SSH keys: SSH is enabled on it, or was (its SSH application is made when SSH is first enabled). With SSH
// off the servers go on fetching its CA keys and revocation list, which then revokes everything (SSHKRL), so that
// turning SSH off reaches them. ErrNotFound for an unknown tenant and for one that never had SSH.
func (s *Service) SSHTenantPublished(ctx context.Context, orgID, ref string) (*model.Tenant, error) {
	var t *model.Tenant
	if model.IsID(ref) {
		if got, err := s.Tenants.GetIn(ctx, orgID, ref); err == nil {
			t = got
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, mapStore(err)
		}
	}
	if t == nil {
		got, err := s.Tenants.GetByUnique(ctx, model.TenantNameKey(orgID, ref))
		if err != nil {
			return nil, mapStore(err)
		}
		t = got
	}
	if t.OrgID != orgID || t.SSH == nil || !t.SSH.Enabled && t.SSH.ClientID == "" {
		return nil, ErrNotFound
	}
	return t, nil
}

// SSHTenantUse is a tenant with SSH enabled that a user may get certificates for, and the principals they would get.
type SSHTenantUse struct {
	Tenant     *model.Tenant
	Principals []string
}

// SSHTenantBlocked is a tenant with SSH enabled whose SSH application the user may use, where a certificate would still
// be refused, and why: SSHBlockedRole (managers and administrators get none there), SSHBlockedMethod (not after the way
// the session signed in) or SSHBlockedPrincipals (the settings give the user no principal).
type SSHTenantBlocked struct {
	Tenant *model.Tenant
	Reason string
}

const (
	SSHBlockedRole       = "role"
	SSHBlockedMethod     = "sign_in_method"
	SSHBlockedPrincipals = "no_principals"
)

// SSHTenantsFor returns the tenants of u's organization with SSH enabled that u may use, for the account page: the
// ones where signing a certificate for u would not be refused for want of access, role or principals, and, for a
// session ss (nil: any), where the tenant's sign-in methods allow the way it signed in.
func (s *Service) SSHTenantsFor(ctx context.Context, u *model.User, ss *SSHSession) ([]*SSHTenantUse, error) {
	uses, _, err := s.SSHAccountTenants(ctx, u, ss)
	return uses, err
}

// SSHAccountTenants returns what SSHTenantsFor does and, so that the account page can say why, the tenants with SSH
// enabled where u has access but would be refused a certificate. A tenant u has no access to is in neither list.
func (s *Service) SSHAccountTenants(ctx context.Context, u *model.User, ss *SSHSession) ([]*SSHTenantUse, []*SSHTenantBlocked, error) {
	if ok, err := s.UserUsable(ctx, u); err != nil || !ok {
		return nil, nil, err
	}
	tenants, err := s.Tenants.All(ctx, u.OrgID)
	if err != nil {
		return nil, nil, mapStore(err)
	}
	var out []*SSHTenantUse
	var blocked []*SSHTenantBlocked
	for _, t := range tenants {
		if t.SSH == nil || !t.SSH.Enabled {
			continue
		}
		d, err := s.sshDecide(ctx, t, u)
		if err != nil {
			return nil, nil, err
		}
		if !d.Allowed {
			continue
		}
		reason := ""
		switch {
		case sshRoleBlocked(t, u):
			reason = SSHBlockedRole
		case ss != nil:
			if ok, err := s.sshMethodAllowed(ctx, t, ss); err != nil {
				return nil, nil, err
			} else if !ok {
				reason = SSHBlockedMethod
			}
		}
		if reason == "" && len(d.Principals) == 0 {
			reason = SSHBlockedPrincipals
		}
		if reason != "" {
			blocked = append(blocked, &SSHTenantBlocked{Tenant: t, Reason: reason})
			continue
		}
		out = append(out, &SSHTenantUse{Tenant: t, Principals: d.Principals})
	}
	return out, blocked, nil
}
