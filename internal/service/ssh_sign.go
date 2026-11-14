package service

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/store"
)

// SSHRefusal is a certificate refused for a reason the person asking should be told (errors.Is(err, ErrForbidden)):
// Msg is fit to show them.
type SSHRefusal struct{ Msg string }

func (e *SSHRefusal) Error() string { return e.Msg }
func (e *SSHRefusal) Unwrap() error { return ErrForbidden }

// SSHUserRequest asks for a user certificate.
type SSHUserRequest struct {
	Actor    *Actor // who asks, for the audit log (nil: the user)
	User     *model.User
	TenantID string
	// ClientID is the client of the access token the request came with (the sign endpoint); it must be the tenant's
	// SSH application. "" from the account page.
	ClientID   string
	PublicKey  string        // an authorized_keys line
	Principals []string      // optional: some of the principals the user is allowed
	TTL        time.Duration // optional, at most the tenant's CertTTL
	AMR        []string      // how the user signed in
	AuthTime   time.Time     // when
	Via        string        // "cli" (the sign endpoint) or "account" (the account page)
	// Session, when set, is the session the request comes from: the way it signed in must be one the tenant's
	// sign-in methods allow (the account page; the sign endpoint's token was issued under that rule already).
	Session *SSHSession
	// SessionEpoch and Stamp are the session epoch and sign-out counters of what the request stands on: the access
	// token's grant (the sign endpoint) or the session (the account page). The certificate records them, never the
	// current ones, so that a request whose sign-in has ended cannot get what that sign-in lost (the KRL revokes a
	// certificate once they no longer hold); one that has already ended is refused.
	SessionEpoch uint64
	Stamp        model.SignOutStamp
	// Sources are the accounts a guest's sign-in stands on (model.Session.Sources), of what the request stands on: the
	// certificate records them, and counts only while they stand (SourcesHold).
	Sources []model.GuestSource
	// SignIn is the session (the account page, ClientID "") or the access token's grant (the sign endpoint) the request
	// stands on: the certificate is revoked when it is ended (RevokeSSHCertsFrom), and it is read again once the
	// certificate is stored.
	SignIn string
}

// SSHSession is how a session signed in, for the check of the tenant's sign-in methods.
type SSHSession struct {
	AMR      []string
	Provider string // the identity provider of a federated sign-in
}

// sshMaxLive is how many user certificates a user may have at once for a tenant that have not expired, revoked ones
// included: each stays on the revocation list until it expires, so revoking does not make room for more.
const sshMaxLive = 100

// sshMethodAllowed reports whether tenant t's sign-in methods allow the way session ss signed in, as the
// authorization endpoint decides it for a sign-in to the tenant's applications.
func (s *Service) sshMethodAllowed(ctx context.Context, t *model.Tenant, ss *SSHSession) (bool, error) {
	org, err := s.Org(ctx, t.OrgID)
	if err != nil {
		return false, err
	}
	eff, err := s.EffectiveSignIn(ctx, org, t)
	if err != nil {
		return false, err
	}
	return eff.AllowsSession(ss.AMR, ss.Provider), nil
}

// SSHIssued is a certificate made.
type SSHIssued struct {
	Certificate string // authorized_keys form: ssh-ed25519-cert-v01@openssh.com AAAA…
	Cert        *model.SSHCert
}

// SSHHostRequest asks for a host certificate.
type SSHHostRequest struct {
	PublicKey  string
	Principals []string      // host names the certificate is for: 1 to 32, each matching one of the tenant's HostPatterns
	TTL        time.Duration // optional: at most HostTTLDays
}

// sshDecision is what a user would get from a tenant's SSH now: whether they have access to its SSH application (the
// rule of signing in to the tenant's applications), and the principals that would go into a certificate.
// Unavailable says the application itself is gone or disabled, which is nobody's access taken away: the revocation it
// makes is not written down (SSHReasonAppUnavailable), so enabling the application again brings the certificates back.
type sshDecision struct {
	Allowed     bool
	Unavailable bool
	Principals  []string
}

// Prefixes of the principals of a user's groups and application roles: "group:ops", "role:deploy". A username never
// holds a colon, so no user can be given a name that is a group's or a role's principal.
const (
	SSHGroupPrefix = "group:"
	SSHRolePrefix  = "role:"
)

// sshDecide decides user u's access to tenant t's SSH application as a sign-in to it would (ClientAccess: members-only
// tenants, the access list, its end dates), and the principals from that: the username, and "group:" with the name of
// each of the user's groups and "role:" with each application role the access carries, as the tenant's settings
// choose. An application that is gone or disabled gives no access (Unavailable), except that while SSH is off the
// application is disabled by that (syncSSHClient), and access and principals are still decided, so that what the
// revocation list writes down while SSH is off is right. An error is a read that failed: no verdict.
func (s *Service) sshDecide(ctx context.Context, t *model.Tenant, u *model.User) (sshDecision, error) {
	by, err := s.sshDecideAll(ctx, t, []*model.User{u})
	return by[u.ID], err
}

// sshDecideAll is sshDecide for each of users, by user id: what does not depend on the user (the application, the
// groups' pending changes) is read once for all of them, and what they share (their groups, the groups' access
// entries) once too. An evaluation of the revocation list decides for every user with a certificate at once.
func (s *Service) sshDecideAll(ctx context.Context, t *model.Tenant, users []*model.User) (map[string]sshDecision, error) {
	out := make(map[string]sshDecision, len(users))
	in := make([]*model.User, 0, len(users)) // those of the tenant's organization: no access for any other
	for _, u := range users {
		if u.OrgID == t.OrgID {
			in = append(in, u)
		} else {
			out[u.ID] = sshDecision{}
		}
	}
	if len(in) == 0 {
		return out, nil
	}
	unavailable := func() (map[string]sshDecision, error) {
		for _, u := range in {
			out[u.ID] = sshDecision{Unavailable: true}
		}
		return out, nil
	}
	if t.SSH == nil || t.SSH.ClientID == "" {
		return unavailable()
	}
	c, err := s.Clients.Get(ctx, t.SSH.ClientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return unavailable()
		}
		return nil, mapStore(err)
	}
	if !c.Enabled && t.SSH.Enabled || c.TenantID != t.ID || c.OrgID != t.OrgID {
		return unavailable()
	}
	groupsOf, err := s.UserGroupsOf(ctx, in)
	if err != nil {
		return nil, err
	}
	entries := map[string]*model.TenantAccess{}
	for _, u := range in {
		groups := groupsOf[u.ID]
		ids := make([]string, len(groups))
		for i, g := range groups {
			ids[i] = g.ID
		}
		app, err := s.clientAccess(ctx, t, c, u, ids, entries)
		if err != nil {
			return nil, mapStore(err)
		}
		if !app.Allowed {
			out[u.ID] = sshDecision{}
			continue
		}
		// Only names OpenSSH principals can be and that are safe in an AuthorizedPrincipalsFile; others are left out.
		// The name is checked, and the prefix added after.
		var list []string
		add := func(prefix, name string) {
			if sshPrincipal.MatchString(name) {
				list = append(list, prefix+name)
			}
		}
		if t.SSH.PrincipalUsername {
			add("", u.Username)
		}
		if t.SSH.PrincipalGroups {
			for _, g := range groups {
				add(SSHGroupPrefix, g.DisplayName)
			}
		}
		if t.SSH.PrincipalRoles {
			for _, r := range app.Roles {
				add(SSHRolePrefix, r)
			}
		}
		slices.Sort(list)
		out[u.ID] = sshDecision{Allowed: true, Principals: slices.Compact(list)}
	}
	return out, nil
}

// sshExtensions are the names of the OpenSSH extensions a user certificate of the settings set grants, sorted.
func sshExtensions(set *model.TenantSSH) []string {
	return slices.Sorted(maps.Keys(sshca.UserExtensions(set.PermitPTY, set.PermitUserRC, set.PermitPortForwarding,
		set.PermitAgentForwarding, set.PermitX11Forwarding)))
}

// SSHPrincipals returns the principals user u would get in a certificate of tenant t now, sorted: none when u has no
// access to the tenant's SSH application.
func (s *Service) SSHPrincipals(ctx context.Context, t *model.Tenant, u *model.User) ([]string, error) {
	d, err := s.sshDecide(ctx, t, u)
	return d.Principals, err
}

// sshRoleBlocked reports whether u is a manager or above and the tenant does not issue them certificates.
func sshRoleBlocked(t *model.Tenant, u *model.User) bool {
	return u.Role.Privileged() && (t.SSH == nil || !t.SSH.AllowPrivileged)
}

// sshLiveCerts counts the user certificates of user userID for tenant t that have not expired, revoked or not (a
// revoked one is on the revocation list until it expires: counted, signing and revoking cannot grow the list without
// bound), and says when the first of them expires.
func (s *Service) sshLiveCerts(ctx context.Context, t *model.Tenant, userID string, now time.Time) (int, time.Time, error) {
	certs, err := s.sshUserCerts(ctx, t, userID)
	if err != nil {
		return 0, time.Time{}, err
	}
	n, first := 0, time.Time{}
	for _, c := range certs {
		if now.Before(c.ValidBefore) {
			n++
			if first.IsZero() || c.ValidBefore.Before(first) {
				first = c.ValidBefore
			}
		}
	}
	return n, first, nil
}

// sshRefuse records a refused request for a certificate (throttled: ssh.cert.refused, one per user, tenant and reason a
// minute) and returns err.
func (s *Service) sshRefuse(ctx context.Context, req SSHUserRequest, t *model.Tenant, reason string, err error) error {
	a := req.Actor
	if a == nil {
		a = ActorForUser(req.User, "")
	}
	s.auditRefusal(t.OrgID, "ssh|"+req.User.ID+"|"+t.ID+"|"+reason, func(detail map[string]string) {
		detail["reason"], detail["tenant"], detail["via"] = reason, t.Name, req.Via
		s.AuditUser(ctx, a, req.User, "ssh.cert.refused", detail)
	})
	return err
}

// SignUserSSH signs a user certificate for req.PublicKey: for a user who signed in with a second factor not longer ago
// than the tenant's MaxAuthAge, who may use the tenant's SSH application, with the principals the tenant's settings
// give them. Every refusal is audited as ssh.cert.refused with its reason; the certificate is audited ssh.cert.issue
// once its record is stored (the record is what the revocation list is made from).
func (s *Service) SignUserSSH(ctx context.Context, req SSHUserRequest) (*SSHIssued, error) {
	u := req.User
	if u == nil {
		return nil, ErrNotFound
	}
	t, err := s.Tenants.GetIn(ctx, u.OrgID, req.TenantID)
	if err != nil {
		return nil, mapStore(err)
	}
	if t.SSH == nil || !t.SSH.Enabled {
		return nil, s.sshRefuse(ctx, req, t, "not_enabled", &SSHRefusal{"SSH certificates are not enabled for this tenant"})
	}
	set := t.SSH
	ca, signer, err := s.sshSigner(ctx, t, model.SSHPurposeUser)
	switch {
	case errors.Is(err, errNoSSHKey):
		return nil, s.sshRefuse(ctx, req, t, "no_user_key", &SSHRefusal{"this tenant has no SSH CA key that signs certificates"})
	case err != nil:
		return nil, err
	}
	now := time.Now()
	switch {
	case req.ClientID != "" && req.ClientID != set.ClientID:
		return nil, s.sshRefuse(ctx, req, t, "wrong_client", &SSHRefusal{"this access token is not for the tenant's SSH application"})
	case !model.MFA(req.AMR):
		return nil, s.sshRefuse(ctx, req, t, "mfa_required", &SSHRefusal{"a second factor is required: sign in with a one-time code or a passkey"})
	case req.AuthTime.IsZero() || now.Sub(req.AuthTime) > time.Duration(set.MaxAuthAge)*time.Second:
		return nil, s.sshRefuse(ctx, req, t, "auth_too_old", &SSHRefusal{"the sign-in is too old to get a certificate: sign in again"})
	}
	if req.Session != nil {
		if ok, err := s.sshMethodAllowed(ctx, t, req.Session); err != nil {
			return nil, err
		} else if !ok {
			return nil, s.sshRefuse(ctx, req, t, "method_not_allowed", &SSHRefusal{"this tenant does not accept the way you signed in: sign in with a method it allows"})
		}
	}
	if ok, err := s.UserUsable(ctx, u); err != nil {
		return nil, err
	} else if !ok {
		return nil, s.sshRefuse(ctx, req, t, "user_unusable", &SSHRefusal{"this account cannot get certificates"})
	}
	want, err := s.SessionStamp(ctx, u.OrgID)
	if err != nil {
		return nil, err
	}
	sourced, err := s.SourcesHold(ctx, req.Sources, s.storeUser)
	if err != nil {
		return nil, err
	}
	if !u.SessionHolds(req.SessionEpoch) || !req.Stamp.Current(want) || !sourced {
		return nil, s.sshRefuse(ctx, req, t, "session_ended", &SSHRefusal{"the sign-in this request comes from has ended: sign in again"})
	}
	dec, err := s.sshDecide(ctx, t, u)
	switch {
	case err != nil:
		return nil, err
	case dec.Unavailable:
		return nil, s.sshRefuse(ctx, req, t, "app_unavailable", &SSHRefusal{"this tenant's SSH application is disabled or missing"})
	case !dec.Allowed:
		return nil, s.sshRefuse(ctx, req, t, "no_access", &SSHRefusal{"this account has no access to this tenant's SSH"})
	case sshRoleBlocked(t, u):
		return nil, s.sshRefuse(ctx, req, t, "privileged", &SSHRefusal{"managers and administrators cannot get SSH certificates from this tenant"})
	}
	pub, _, err := sshca.ParsePublicKey(req.PublicKey)
	if err != nil {
		s.sshRefuse(ctx, req, t, "bad_key", err)
		return nil, Invalid("public_key", err.Error())
	}
	if len(dec.Principals) == 0 {
		return nil, s.sshRefuse(ctx, req, t, "no_principals", &SSHRefusal{"there is no principal to put in a certificate for this account"})
	}
	if n, first, err := s.sshLiveCerts(ctx, t, u.ID, now); err != nil {
		return nil, err
	} else if n >= sshMaxLive {
		return nil, s.sshRefuse(ctx, req, t, "too_many", &SSHRefusal{"you have " + strconv.Itoa(n) + " certificates for this tenant " +
			"that have not expired, the most it allows (revoked ones count until they expire): wait until the first expires, at " +
			first.UTC().Format(time.RFC3339)})
	}
	principals := dec.Principals
	if len(req.Principals) > 0 {
		principals = nil
		for _, p := range req.Principals {
			p = strings.TrimSpace(p)
			if !slices.Contains(dec.Principals, p) {
				err := Invalid("principals", strconv.Quote(p)+" is not one of yours; you may use "+strings.Join(dec.Principals, ", "))
				return nil, s.sshRefuse(ctx, req, t, "bad_principal", err)
			}
			if !slices.Contains(principals, p) {
				principals = append(principals, p)
			}
		}
	}
	ttl := time.Duration(set.CertTTL) * time.Second
	if req.TTL != 0 {
		if req.TTL < time.Minute || req.TTL > ttl {
			return nil, s.sshRefuse(ctx, req, t, "bad_ttl", Invalid("ttl", "between 60 seconds and "+strconv.Itoa(set.CertTTL)+" seconds"))
		}
		ttl = req.TTL
	}
	validBefore := now.Add(ttl)
	if u.ValidUntil != nil && u.ValidUntil.Before(validBefore) {
		validBefore = *u.ValidUntil // never beyond the account's end
	}
	org, err := s.Org(ctx, u.OrgID)
	if err != nil {
		return nil, err
	}
	serial, err := sshca.RandomSerial()
	if err != nil {
		return nil, err
	}
	keyID := u.Username + "@" + org.Name + "/" + u.ID
	cert, line, err := sshca.SignCert(signer, sshca.CertSpec{
		Key: pub, Serial: serial, KeyID: keyID, Principals: principals,
		ValidAfter: now.Add(-sshBackdate), ValidBefore: validBefore,
		Extensions:      sshca.UserExtensions(set.PermitPTY, set.PermitUserRC, set.PermitPortForwarding, set.PermitAgentForwarding, set.PermitX11Forwarding),
		SourceAddresses: set.SourceAddresses,
	})
	if err != nil {
		return nil, err
	}
	rec := &model.SSHCert{OrgID: u.OrgID, TenantID: t.ID, UserID: u.ID, Serial: serial, KeyID: keyID, CAKeyID: ca.ID,
		Principals: slices.Clone(cert.ValidPrincipals), Fingerprint: sshca.Fingerprint(pub),
		ValidAfter: time.Unix(int64(cert.ValidAfter), 0).UTC(), ValidBefore: time.Unix(int64(cert.ValidBefore), 0).UTC(),
		Extensions: slices.Sorted(maps.Keys(cert.Permissions.Extensions)), SourceAddresses: slices.Clone(set.SourceAddresses),
		SessionEpoch: req.SessionEpoch, Stamp: req.Stamp, Sources: req.Sources, SignIn: req.SignIn, Via: req.Via}
	actor := req.Actor
	if actor == nil {
		actor = ActorForUser(u, "")
	}
	detail := map[string]string{"serial": strconv.FormatUint(serial, 10), "principals": strings.Join(rec.Principals, ","),
		"fingerprint": rec.Fingerprint, "valid_before": rec.ValidBefore.Format(time.RFC3339), "via": req.Via,
		"amr": strings.Join(req.AMR, ","), "tenant": t.Name}
	if err := s.AuditedUser(ctx, actor, u, "ssh.cert.issue", detail, func() error { return s.SSHCerts.Create(ctx, rec) }); err != nil {
		return nil, mapStore(err)
	}
	// The sign-in may have been ended since it was checked (this node may hold a cached copy of the session or grant
	// for a few seconds), and its revocation may have listed the user's certificates before this one was stored. Its
	// end deletes it first and lists the certificates after (endSessions, revokeGrant); this stores the certificate
	// first and reads the sign-in after, from the store. On a shared database, or a single node, whichever comes second
	// sees the other: found here, it was deleted after this certificate was stored, and the listing that follows the
	// deletion revokes it; gone, this revokes it, and the certificate is not handed out. In a gossip cluster each node
	// reads its own copy, so the two can still miss each other while the deletion and the certificate are replicating:
	// the certificate is handed out, and the listing does not mark it. That converges once they have replicated: the
	// end recorded the sign-in as taken back (model.SSHRevokedSignIn) before its listing, and the revocation lists
	// revoke every certificate issued under it (sshEval.reason), on each node within the 30 s it keeps a list. A read
	// that fails decides nothing: the certificate is revoked as well, and not handed out.
	if req.SignIn != "" {
		var err error
		if req.ClientID == "" {
			_, err = s.Sessions.Get(ctx, req.SignIn) // the account page: the session
		} else {
			_, err = s.Grants.Get(ctx, req.SignIn) // the sign endpoint: the access token's grant
		}
		if err != nil {
			if _, rerr := s.sshRevokeSignInEnded(ctx, u.OrgID, rec); rerr != nil {
				s.Log.WithError(rerr).Error("an SSH certificate whose sign-in ended could not be revoked", "serial", rec.Serial)
			}
			if errors.Is(err, store.ErrNotFound) {
				return nil, s.sshRefuse(ctx, req, t, "session_ended", &SSHRefusal{"the sign-in this request comes from has ended: sign in again"})
			}
			return nil, mapStore(err)
		}
	}
	return &SSHIssued{Certificate: line, Cert: rec}, nil
}

// sshHostRefuse records a refused request for a host certificate (ssh.host.refused, throttled per caller and reason)
// and returns err.
func (s *Service) sshHostRefuse(ctx context.Context, a *Actor, t *model.Tenant, reason string, err error) error {
	s.auditRefusal(t.OrgID, "sshhost|"+a.UserID+"|"+a.ClientID+"|"+t.ID+"|"+reason, func(detail map[string]string) {
		detail["reason"] = reason
		s.Audit(ctx, a, t.OrgID, "ssh.host.refused", t.Name, detail)
	})
	return err
}

// SignHostSSH signs a host certificate for the public key in in, for the host names in in.Principals (administrators of
// the organization, and service accounts with the ssh:host scope). Refused unless SSH and host certificates are on,
// and every name must match one of the tenant's HostPatterns. It lasts TTL, at most HostTTLDays days (the default).
func (s *Service) SignHostSSH(ctx context.Context, a *Actor, tenantID string, in SSHHostRequest) (*SSHIssued, error) {
	t, err := s.Tenants.Get(ctx, tenantID)
	if err != nil {
		return nil, mapStore(err)
	}
	switch {
	case a.OrgID != t.OrgID && !a.IsSuper():
		return nil, ErrNotFound // another organization's tenant is not seen
	case !s.sshAdmin(a, t.OrgID, ScopeSSHHost):
		return nil, ErrForbidden
	case t.SSH == nil || !t.SSH.Enabled || !t.SSH.HostCerts:
		return nil, s.sshHostRefuse(ctx, a, t, "host_certs_off", &SSHRefusal{"host certificates are not enabled for this tenant"})
	}
	set := t.SSH
	ca, signer, err := s.sshSigner(ctx, t, model.SSHPurposeHost)
	switch {
	case errors.Is(err, errNoSSHKey):
		return nil, s.sshHostRefuse(ctx, a, t, "no_host_key", &SSHRefusal{"this tenant has no SSH host CA key that signs certificates"})
	case err != nil:
		return nil, err
	}
	pub, _, err := sshca.ParsePublicKey(in.PublicKey)
	if err != nil {
		s.sshHostRefuse(ctx, a, t, "bad_key", err)
		return nil, Invalid("public_key", err.Error())
	}
	if len(in.Principals) > sshMaxPrincipals { // before the loop below, whose de-duplication is quadratic
		return nil, s.sshHostRefuse(ctx, a, t, "bad_principals", Invalid("principals", "give 1 to 32 host names"))
	}
	var principals []string
	for _, p := range in.Principals {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" && !slices.Contains(principals, p) {
			principals = append(principals, p)
		}
	}
	if len(principals) == 0 || len(principals) > sshMaxPrincipals {
		return nil, s.sshHostRefuse(ctx, a, t, "bad_principals", Invalid("principals", "give 1 to 32 host names"))
	}
	for _, p := range principals {
		switch {
		case !sshca.ValidHostName(p):
			return nil, s.sshHostRefuse(ctx, a, t, "bad_principals", Invalid("principals", strconv.Quote(p)+" is not a host name or address (no wildcards)"))
		case !sshca.MatchHost(set.HostPatterns, p):
			return nil, s.sshHostRefuse(ctx, a, t, "pattern", Invalid("principals", p+" does not match the tenant's host patterns ("+strings.Join(set.HostPatterns, ", ")+")"))
		}
	}
	maxTTL := time.Duration(set.HostTTLDays) * 24 * time.Hour
	ttl := maxTTL
	if in.TTL != 0 {
		if in.TTL < time.Hour || in.TTL > maxTTL {
			return nil, s.sshHostRefuse(ctx, a, t, "bad_ttl", Invalid("ttl", "between 1 hour and "+strconv.Itoa(set.HostTTLDays)+" days"))
		}
		ttl = in.TTL
	}
	org, err := s.Org(ctx, t.OrgID)
	if err != nil {
		return nil, err
	}
	serial, err := sshca.RandomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	keyID := "host:" + principals[0] + "@" + org.Name
	cert, line, err := sshca.SignCert(signer, sshca.CertSpec{Host: true, Key: pub, Serial: serial, KeyID: keyID, Principals: principals,
		ValidAfter: now.Add(-sshBackdate), ValidBefore: now.Add(ttl)})
	if err != nil {
		return nil, err
	}
	rec := &model.SSHCert{OrgID: t.OrgID, TenantID: t.ID, Host: true, Serial: serial, KeyID: keyID, CAKeyID: ca.ID,
		Principals: slices.Clone(cert.ValidPrincipals), Fingerprint: sshca.Fingerprint(pub),
		ValidAfter: time.Unix(int64(cert.ValidAfter), 0).UTC(), ValidBefore: time.Unix(int64(cert.ValidBefore), 0).UTC(),
		Via: "api", IssuedBy: a.Name}
	detail := map[string]string{"serial": strconv.FormatUint(serial, 10), "principals": strings.Join(rec.Principals, ","),
		"fingerprint": rec.Fingerprint, "valid_before": rec.ValidBefore.Format(time.RFC3339), "key_id": keyID}
	if err := s.audited(ctx, a, t.OrgID, "ssh.host.issue", t.Name, detail, func() error { return s.SSHCerts.Create(ctx, rec) }); err != nil {
		return nil, mapStore(err)
	}
	return &SSHIssued{Certificate: line, Cert: rec}, nil
}
