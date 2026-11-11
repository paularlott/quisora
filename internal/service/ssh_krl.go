package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/store"
)

// Revocation. The KRL of a tenant lists every certificate it issued that has not expired and would not be issued
// now: revoked by hand, or its user gone, disabled, signed out or no longer allowed what it carries, or granting more
// than the tenant's settings now would. No hook tells the list when access ends: it is worked out when asked for (kept
// 30 s per tenant on a node, and dropped on every node when a certificate, CA key or tenant changes), so everything
// that ends a user's access in Quisora reaches the servers within that time plus their fetch interval. When the access
// that ends is a lost access, role or principal, the revocation is also written to the certificate, so that getting the
// access back does not bring old certificates back. CA keys removed by hand are revoked themselves (their tombstones,
// sshTombstoneFor), and with SSH turned off every CA key of the tenant is (the servers go on fetching the list), which
// turning SSH on again undoes.

// Why a certificate is on the revocation list (SSHRevokedCert.Reason).
const (
	SSHReasonRevoked        = "revoked"            // revoked by hand
	SSHReasonCAKeyRemoved   = "ca_key_removed"     // its CA key was removed: servers stop trusting the key itself
	SSHReasonUserDeleted    = "user_deleted"       // the user was deleted
	SSHReasonUserDisabled   = "user_disabled"      // disabled, locked out, past the end date, or the organization is gone
	SSHReasonSessionsEnded  = "sessions_ended"     // the user's sessions were ended (sign out everywhere, a credential reset)
	SSHReasonSignInEnded    = "sign_in_ended"      // the session or grant it was issued under was taken back (RevokeSSHCertsFrom)
	SSHReasonSignedOut      = "signed_out"         // an emergency sign-out of the organization or the server came after it
	SSHReasonRoleNotAllowed = "role_not_allowed"   // the user is a manager or above and the tenant does not allow it
	SSHReasonAccessRemoved  = "access_removed"     // the user lost access to the tenant's SSH application
	SSHReasonAppUnavailable = "app_unavailable"    // the tenant's SSH application is disabled or gone: until it is back
	SSHReasonPrincipals     = "principals_changed" // a principal in it is not one the user would get now
	SSHReasonOff            = "ssh_off"            // SSH is turned off for the tenant: every certificate is revoked until it is on again
	// SSHReasonSettingsChanged: it grants more than the tenant's settings now would (a lifetime over CertTTL, an
	// extension no longer permitted, source addresses other than those the tenant now restricts certificates to).
	SSHReasonSettingsChanged = "settings_changed"
)

// Statuses of a listed certificate (SSHCertView.Status).
const (
	SSHCertActive  = "active"
	SSHCertExpired = "expired"
	SSHCertRevoked = "revoked"
)

// sshKRLTTL is how long a node keeps the revocation list it made for a tenant.
const sshKRLTTL = 30 * time.Second

// sshKRLGrace is how long a revoked certificate stays on the list after it expires: a server whose clock is slow
// still sees it as valid, and must still see it revoked. (The records are kept an hour past the end.)
const sshKRLGrace = 10 * time.Minute

// sshPersistPerBuild bounds the revocations one build of the list writes down (sshPersist), after the list is kept:
// the request that made it answers once they are written. The rest are written by the builds that follow.
const sshPersistPerBuild = 50

// sshStickyReasons are the reasons that are written to the certificate (SSHCert.RevokedReason) once found: the user
// lost something a certificate carried, which is not undone by their getting it back, or the sign-in it was issued
// under was taken back (found by its record, model.SSHRevokedSignIn, which expires). Others follow the user's state (a
// disabled account that is enabled again), or the tenant's (SSH turned off and on).
var sshStickyReasons = []string{SSHReasonAccessRemoved, SSHReasonPrincipals, SSHReasonRoleNotAllowed, SSHReasonSignInEnded}

// sshRevokedSignInFor is how long the record of a sign-in taken back (model.SSHRevokedSignIn) is kept: the longest
// certificate signed under it and its time on the list past its end (sshKRLGrace), with an hour from its making to
// cover a certificate signed on another node until the end of the sign-in replicated there.
const sshRevokedSignInFor = sshMaxCertTTL*time.Second + time.Hour

// sshKRLIdle is how long a node keeps the entry of a tenant whose list nobody asks for (sshKRLSweep): a list is never
// served past sshKRLTTL, so an entry left that long holds nothing of use, and the entries of tenants deleted, turned off
// or asked for once do not pile up.
const sshKRLIdle = 2 * sshKRLTTL

// sshKRLEntry is a node's revocation list of one tenant. One request at a time builds it (flight); those that come
// meanwhile wait for it, each for as long as it is there to be answered, and take what it made. gen counts the
// invalidations (InvalidateSSHKRLOf): a list is kept only while gen is what it was when its build began, and a request
// takes a build under way only when no invalidation came since it began, so a change made before a request, or during
// a build, is never hidden by it. While the build's sticky revocations are written down (persisting), the
// invalidations they cause, and any other, are held back (missed) and counted once the writing ends: the list kept
// already revokes those certificates, and the requests meanwhile take it instead of each making it again.
type sshKRLEntry struct {
	persist sync.Mutex // one sshPersist at a time

	// under sshState.krlMu
	gen        uint64
	persisting bool
	missed     bool
	org        string        // the tenant's organization, once a build has read it
	asked      time.Time     // when a request last asked for the list, or a build made it
	flight     *sshKRLFlight // the build under way, if any

	built uint64 // gen when the kept list's build began
	at    time.Time
	data  []byte
	tag   string // sshca.KRLTag of data
}

// sshKRLFlight is a build of a tenant's revocation list under way: its outcome is set once done is closed.
type sshKRLFlight struct {
	gen  uint64 // the entry's gen when it began
	done chan struct{}
	data []byte
	tag  string
	err  error
}

// SSHRevokedCert is a certificate on the revocation list and why.
type SSHRevokedCert struct {
	Cert   *model.SSHCert
	Reason string
}

// sshUser is a certificate's user as an evaluation found them.
type sshUser struct {
	u      *model.User
	gone   bool
	usable bool
	dec    sshDecision
}

// sshEval works out which certificates of a tenant would not be issued now.
type sshEval struct {
	s     *Service
	t     *model.Tenant
	off   bool // SSH is turned off: every certificate counts as revoked
	keys  map[string]*model.SSHKey
	want  model.SignOutStamp
	ext   []string // the extensions a user certificate gets now (sshExtensions)
	users map[string]*sshUser
	// signIns are the sign-ins read (SSHCert.SignIn): true for one taken back (model.SSHRevokedSignIn).
	signIns map[string]bool
}

func (s *Service) newSSHEval(ctx context.Context, t *model.Tenant) (*sshEval, error) {
	keys, err := s.sshKeysIn(ctx, t, "")
	if err != nil {
		return nil, err
	}
	want, err := s.SessionStamp(ctx, t.OrgID)
	if err != nil {
		return nil, err
	}
	ev := &sshEval{s: s, t: t, off: t.SSH != nil && !t.SSH.Enabled, keys: map[string]*model.SSHKey{}, want: want, users: map[string]*sshUser{},
		signIns: map[string]bool{}}
	if t.SSH != nil {
		ev.ext = sshExtensions(t.SSH)
	}
	for _, k := range keys {
		ev.keys[k.ID] = k
	}
	return ev, nil
}

// user returns certificate user id as it stands now (read once per evaluation: load).
func (ev *sshEval) user(ctx context.Context, id string) (*sshUser, error) {
	if x := ev.users[id]; x != nil {
		return x, nil
	}
	if err := ev.loadUsers(ctx, []string{id}); err != nil {
		return nil, err
	}
	return ev.users[id], nil
}

// load reads what reason needs of certificates certs that the evaluation has not read yet, together: their users
// (loadUsers), then, in one read, the sign-ins the user certificates not revoked were issued under that were taken
// back (model.SSHRevokedSignIn). The callers load the certificates they evaluate before the first, so that an
// evaluation reads the application and the groups once, however many users it meets, and the sign-ins once; reason
// loads what a certificate needs that is not read yet (after a load that failed).
func (ev *sshEval) load(ctx context.Context, certs []*model.SSHCert) error {
	if err := ev.loadUsers(ctx, sshCertUsers(certs)); err != nil {
		return err
	}
	var ids []string
	for _, c := range certs {
		if _, read := ev.signIns[c.SignIn]; c.SignIn != "" && !c.Host && !c.Revoked && !read {
			ids = append(ids, c.SignIn)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	ids = slices.Compact(slices.Sorted(slices.Values(ids)))
	found, err := ev.s.SSHRevokedSignIns.GetMany(ctx, ids)
	if err != nil {
		return mapStore(err)
	}
	for _, id := range ids {
		ev.signIns[id] = false
	}
	for _, r := range found {
		ev.signIns[r.ID] = r.OrgID == ev.t.OrgID // of another organization: none
	}
	return nil
}

// loadUsers reads the users ids name that the evaluation has not read yet, together: the users in one read, and their
// access to the tenant's SSH application in one decision (sshDecideAll), which reads what they share once.
func (ev *sshEval) loadUsers(ctx context.Context, ids []string) error {
	ids = slices.DeleteFunc(slices.Compact(slices.Sorted(slices.Values(ids))), func(id string) bool { return ev.users[id] != nil })
	if len(ids) == 0 {
		return nil
	}
	found, err := ev.s.Users.GetMany(ctx, ids)
	if err != nil {
		return mapStore(err)
	}
	read := make(map[string]*sshUser, len(ids))
	for _, id := range ids {
		read[id] = &sshUser{gone: true}
	}
	var usable []*model.User
	for _, u := range found {
		if u.OrgID != ev.t.OrgID {
			continue // of another organization: none, as a read of the organization's users finds it
		}
		x := &sshUser{u: u}
		if x.usable, err = ev.s.UserUsable(ctx, u); err != nil {
			return err
		}
		if x.usable {
			usable = append(usable, u)
		}
		read[u.ID] = x
	}
	decs, err := ev.s.sshDecideAll(ctx, ev.t, usable)
	if err != nil {
		return err
	}
	for _, u := range usable {
		read[u.ID].dec = decs[u.ID]
	}
	maps.Copy(ev.users, read)
	return nil
}

// sshCertUsers returns the ids of the users of certs (none for a host certificate).
func sshCertUsers(certs []*model.SSHCert) []string {
	ids := make([]string, 0, len(certs))
	for _, c := range certs {
		if c.UserID != "" {
			ids = append(ids, c.UserID)
		}
	}
	return ids
}

// reason says why certificate c would not be issued now ("": it would be, or it has expired). The reasons that follow
// the user come before ssh_off, so that those that are sticky are found, and written down, while SSH is off too:
// turning SSH on again must not revive a certificate whose user lost access meanwhile.
func (ev *sshEval) reason(ctx context.Context, c *model.SSHCert) (string, error) {
	switch {
	case c.Revoked && c.RevokedReason != "":
		return c.RevokedReason, nil // found by an evaluation and written down (sshPersist)
	case c.Revoked:
		return SSHReasonRevoked, nil
	case ev.keys[c.CAKeyID] == nil:
		return SSHReasonCAKeyRemoved, nil
	case c.Host && ev.off:
		return SSHReasonOff, nil
	case c.Host:
		return "", nil
	}
	if err := ev.load(ctx, []*model.SSHCert{c}); err != nil { // what the caller's load did not read
		return "", err
	}
	x, err := ev.user(ctx, c.UserID)
	switch {
	case err != nil:
		return "", err
	case x.gone:
		return SSHReasonUserDeleted, nil
	case !x.usable:
		return SSHReasonUserDisabled, nil
	case !x.u.SessionHolds(c.SessionEpoch):
		return SSHReasonSessionsEnded, nil
	case ev.signIns[c.SignIn]:
		return SSHReasonSignInEnded, nil
	case !c.Stamp.Current(ev.want):
		return SSHReasonSignedOut, nil
	case sshRoleBlocked(ev.t, x.u):
		return SSHReasonRoleNotAllowed, nil
	case x.dec.Unavailable:
		return SSHReasonAppUnavailable, nil
	case !x.dec.Allowed:
		return SSHReasonAccessRemoved, nil
	}
	for _, p := range c.Principals {
		if !slices.Contains(x.dec.Principals, p) {
			return SSHReasonPrincipals, nil
		}
	}
	switch {
	case ev.off:
		return SSHReasonOff, nil
	case ev.grantsMore(c):
		return SSHReasonSettingsChanged, nil
	}
	return "", nil
}

// grantsMore reports whether user certificate c grants more than one signed under the tenant's settings now would: a
// longer lifetime than CertTTL, an extension no longer permitted, or source addresses other than those the tenant now
// restricts certificates to. (Fewer extensions, or a restriction the tenant has since lifted, grant less.)
func (ev *sshEval) grantsMore(c *model.SSHCert) bool {
	set := ev.t.SSH
	if c.ValidBefore.Sub(c.ValidAfter) > sshBackdate+time.Duration(set.CertTTL)*time.Second {
		return true
	}
	for _, e := range c.Extensions {
		if !slices.Contains(ev.ext, e) {
			return true
		}
	}
	if len(set.SourceAddresses) > 0 {
		had, now := slices.Sorted(slices.Values(c.SourceAddresses)), slices.Sorted(slices.Values(set.SourceAddresses))
		return !slices.Equal(had, now)
	}
	return false
}

// sshCertsWhere returns the certificates of organization orgID that match filters, expired ones too (they stay an
// hour), a page at a time. The first filter is the one an index serves: the most selective goes first.
func (s *Service) sshCertsWhere(ctx context.Context, orgID string, filters ...store.Filter) ([]*model.SSHCert, error) {
	return s.sshCertsSearch(ctx, orgID, "", filters...)
}

// sshCertsSearch is sshCertsWhere for those whose key id, key fingerprint or serial starts with search (the store's
// search, a prefix, ignoring case; "": every one).
func (s *Service) sshCertsSearch(ctx context.Context, orgID, search string, filters ...store.Filter) ([]*model.SSHCert, error) {
	var out []*model.SSHCert
	for after := ""; ; {
		page, _, err := s.SSHCerts.List(ctx, store.ListQuery{Scope: orgID, Search: search, Filters: filters, After: after, Limit: 500})
		if err != nil {
			return nil, mapStore(err)
		}
		out = append(out, page...)
		if len(page) < 500 {
			return out, nil
		}
		after = page[len(page)-1].ID
	}
}

// sshUserCerts returns the user certificates of tenant t, of one user when userID is set.
func (s *Service) sshUserCerts(ctx context.Context, t *model.Tenant, userID string) ([]*model.SSHCert, error) {
	if userID != "" {
		return s.sshCertsWhere(ctx, t.OrgID, store.Filter{Field: "user_id", Value: userID}, store.Filter{Field: "tenant_id", Value: t.ID})
	}
	return s.sshCertsWhere(ctx, t.OrgID, store.Filter{Field: "tenant_id", Value: t.ID})
}

// sshHostCerts returns the host certificates of tenant t; only those revoked by hand when revoked is set.
func (s *Service) sshHostCerts(ctx context.Context, t *model.Tenant, revoked bool) ([]*model.SSHCert, error) {
	if revoked {
		return s.sshCertsWhere(ctx, t.OrgID, store.Filter{Field: "revoked", Value: true}, store.Filter{Field: "host_tenant_id", Value: t.ID})
	}
	return s.sshCertsWhere(ctx, t.OrgID, store.Filter{Field: "host_tenant_id", Value: t.ID})
}

// tenantCerts returns every certificate of tenant t, user and host.
func (s *Service) tenantCerts(ctx context.Context, t *model.Tenant) ([]*model.SSHCert, error) {
	users, err := s.sshUserCerts(ctx, t, "")
	if err != nil {
		return nil, err
	}
	hosts, err := s.sshHostCerts(ctx, t, false)
	if err != nil {
		return nil, err
	}
	return append(users, hosts...), nil
}

// SSHRevoked returns the certificates of tenant tenantID that have not expired and would not be issued now, each with
// its reason, and those that expired less than sshKRLGrace ago. SSHKRL lists their serials, except those it revokes
// by their CA key (a removed key, and every key while SSH is off), for which it reads only the user certificates.
func (s *Service) SSHRevoked(ctx context.Context, tenantID string) ([]SSHRevokedCert, error) {
	t, err := s.Tenants.Get(ctx, tenantID)
	if err != nil {
		return nil, mapStore(err)
	}
	if t.SSH == nil {
		return nil, ErrNotFound
	}
	certs, err := s.tenantCerts(ctx, t)
	if err != nil {
		return nil, err
	}
	return s.sshRevokedOf(ctx, t, certs)
}

// sshRevokedOf evaluates certs, certificates of tenant t, into those revoked.
func (s *Service) sshRevokedOf(ctx context.Context, t *model.Tenant, certs []*model.SSHCert) ([]SSHRevokedCert, error) {
	ev, err := s.newSSHEval(ctx, t)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	// what reason reads: of the user certificates on the list's span, not revoked, whose CA key is kept
	var live []*model.SSHCert
	for _, c := range certs {
		if c.UserID != "" && !c.Host && !c.Revoked && ev.keys[c.CAKeyID] != nil && !now.After(c.ValidBefore.Add(sshKRLGrace)) {
			live = append(live, c)
		}
	}
	if err := ev.load(ctx, live); err != nil {
		return nil, err
	}
	var out []SSHRevokedCert
	for _, c := range certs {
		if now.After(c.ValidBefore.Add(sshKRLGrace)) {
			continue
		}
		reason, err := ev.reason(ctx, c)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			out = append(out, SSHRevokedCert{Cert: c, Reason: reason})
		}
	}
	return out, nil
}

// sshPersist writes down the revocations of revoked that are sticky (sshStickyReasons) and not yet written, as made by
// the system and audited as such (ssh.cert.revoke, with the reason): a certificate found revoked for a lost access
// stays revoked when the access comes back. Once per certificate, as it is then revoked for good. Best effort, and
// bounded, since the request that made the list waits for it: at most sshPersistPerBuild a build, and none after the
// store fails to answer or a write's outcome is unknown (the list revokes them all the same; the next build writes the
// rest). Any other failure is logged.
func (s *Service) sshPersist(ctx context.Context, revoked []SSHRevokedCert) {
	now := time.Now().UTC()
	written := 0
	for _, r := range revoked {
		if r.Cert.Revoked || !slices.Contains(sshStickyReasons, r.Reason) {
			continue
		}
		if written == sshPersistPerBuild {
			return
		}
		written++
		c := *r.Cert
		c.Revoked, c.RevokedAt, c.RevokedBy, c.RevokedReason = true, now, System.Name, r.Reason
		detail := map[string]string{"serial": strconv.FormatUint(c.Serial, 10), "tenant_id": c.TenantID, "key_id": c.KeyID,
			"user_id": c.UserID, "reason": r.Reason}
		err := s.audited(ctx, System, c.OrgID, "ssh.cert.revoke", c.KeyID, detail, func() error { return s.SSHCerts.Update(ctx, &c) })
		switch {
		case err == nil:
			*r.Cert = c
		case errors.Is(err, store.ErrStale): // changed meanwhile (revoked by hand, say): nothing to add
		case IsUnavailable(mapStore(err)) || outcomeUnknown(err):
			s.Log.Warn("revocations found could not be written down: the store did not answer", "tenant", c.TenantID, "error", err)
			return
		default:
			s.Log.Warn("a certificate found revoked could not be marked revoked", "certificate", c.ID, "reason", r.Reason, "error", err)
		}
	}
}

// SSHKRL returns the OpenSSH key revocation list of a tenant that has or had SSH (SSHKRLTagged).
func (s *Service) SSHKRL(ctx context.Context, tenantID string) ([]byte, error) {
	data, _, err := s.SSHKRLTagged(ctx, tenantID)
	return data, err
}

// SSHKRLTagged returns the OpenSSH key revocation list of a tenant that has or had SSH, and a tag of what it revokes
// (sshca.KRLTag: the same for two lists made at different times that revoke the same, for an HTTP ETag). The list has
// one certificates section for each CA key ca.pub and known_hosts publish (user keys; host keys while host
// certificates are on) with the serials of the certificates SSHRevoked finds, sorted, and revokes outright the CA keys removed by hand whose tombstones are kept, and, while SSH is off,
// every CA key of the tenant: sshd checks a certificate's CA key against the list as well, so these are distrusted by
// a server whose CA file still lists them. Of the host certificates only those revoked by hand are read: the others
// can be revoked only with their key. Its version is the time it was made, in unix seconds. An empty list is a valid
// answer, and the one a tenant with nothing revoked gets; ErrNotFound for a tenant that never had SSH. Made by one
// request at a time for a tenant: the others wait, until it is made or they hang up, and take what it made. Kept for 30
// seconds on the node (any change of a certificate, CA key or tenant clears it: InvalidateSSHKRL).
func (s *Service) SSHKRLTagged(ctx context.Context, tenantID string) ([]byte, string, error) {
	s.ssh.krlMu.Lock()
	now := time.Now()
	s.sshKRLSweep(now)
	e := s.ssh.krl[tenantID]
	if e == nil {
		e = &sshKRLEntry{}
		s.ssh.krl[tenantID] = e
	}
	e.asked = now
	if e.data != nil && e.built == e.gen && now.Sub(e.at) < sshKRLTTL {
		data, tag := e.data, e.tag
		s.ssh.krlMu.Unlock()
		return data, tag, nil
	}
	if f := e.flight; f != nil && f.gen == e.gen {
		s.ssh.krlMu.Unlock()
		select {
		case <-f.done:
			return f.data, f.tag, f.err
		case <-ctx.Done(): // the build goes on for the others
			return nil, "", ctx.Err()
		}
	}
	f := &sshKRLFlight{gen: e.gen, done: make(chan struct{})}
	e.flight = f // a build begun before an invalidation is left to its own waiters
	s.ssh.krlMu.Unlock()
	// The build is not this request's own: it goes on if this one hangs up, for those waiting for it, bounded by the
	// store's own limits.
	bctx := context.WithoutCancel(ctx)
	data, tag, revoked, err := s.sshBuildKRL(bctx, e, tenantID)
	f.data, f.tag, f.err = data, tag, err
	s.ssh.krlMu.Lock()
	if e.flight == f {
		e.flight = nil
	}
	e.asked = time.Now()
	switch {
	case err == nil && e.gen == f.gen:
		e.data, e.tag, e.at, e.built = data, tag, e.asked, f.gen
	case errors.Is(err, ErrNotFound) && s.ssh.krl[tenantID] == e && e.flight == nil && !e.persisting:
		delete(s.ssh.krl, tenantID) // the tenant is gone or never had SSH: nothing to keep
	}
	s.ssh.krlMu.Unlock()
	close(f.done)
	if err != nil {
		return nil, "", err
	}
	// The sticky revocations are written down once the list is kept and its waiters have it: their writes invalidate it
	// (every node's change hook), and the requests that come meanwhile take it. A build that finds another one writing
	// leaves the writing to it; the list revokes them either way.
	if e.persist.TryLock() {
		s.sshKRLPersisting(e, true)
		s.sshPersist(bctx, revoked)
		s.sshKRLPersisting(e, false)
		e.persist.Unlock()
	}
	return data, tag, nil
}

// sshKRLSweep drops, at most once every sshKRLTTL, the entries of the tenants whose lists nobody has asked for in
// sshKRLIdle, unless one is being built or its revocations written down (under sshState.krlMu). A tenant asked for again
// gets a new entry, and its list made afresh.
func (s *Service) sshKRLSweep(now time.Time) {
	if s.ssh.krl == nil {
		s.ssh.krl = map[string]*sshKRLEntry{}
	}
	if now.Sub(s.ssh.krlSwept) < sshKRLTTL {
		return
	}
	s.ssh.krlSwept = now
	for id, e := range s.ssh.krl {
		if e.flight == nil && !e.persisting && now.Sub(e.asked) >= sshKRLIdle {
			delete(s.ssh.krl, id)
		}
	}
}

// sshKRLPersisting marks e's writing down of revocations begun or ended; at its end an invalidation held back meanwhile
// counts.
func (s *Service) sshKRLPersisting(e *sshKRLEntry, on bool) {
	s.ssh.krlMu.Lock()
	defer s.ssh.krlMu.Unlock()
	e.persisting = on
	if !on && e.missed {
		e.gen++
		e.missed = false
	}
}

// sshKRLInvalidate counts an invalidation of e (under sshState.krlMu).
func sshKRLInvalidate(e *sshKRLEntry) {
	if e.persisting {
		e.missed = true
		return
	}
	e.gen++
}

// sshBuildKRL makes the revocation list of tenant tenantID (SSHKRLTagged), and returns with it what it found revoked.
func (s *Service) sshBuildKRL(ctx context.Context, e *sshKRLEntry, tenantID string) ([]byte, string, []SSHRevokedCert, error) {
	t, err := s.Tenants.Get(ctx, tenantID)
	if err != nil {
		return nil, "", nil, mapStore(err)
	}
	if t.SSH == nil || !t.SSH.Enabled && t.SSH.ClientID == "" {
		return nil, "", nil, ErrNotFound
	}
	s.ssh.krlMu.Lock()
	e.org = t.OrgID
	s.ssh.krlMu.Unlock()
	certs, err := s.sshUserCerts(ctx, t, "")
	if err != nil {
		return nil, "", nil, err
	}
	hosts, err := s.sshHostCerts(ctx, t, true)
	if err != nil {
		return nil, "", nil, err
	}
	revoked, err := s.sshRevokedOf(ctx, t, append(certs, hosts...))
	if err != nil {
		return nil, "", nil, err
	}
	keys, err := s.sshKeyRecords(ctx, t)
	if err != nil {
		return nil, "", nil, err
	}
	org, err := s.Org(ctx, t.OrgID)
	if err != nil {
		return nil, "", nil, err
	}
	now := time.Now()
	krl := sshca.NewKRL(uint64(now.Unix()), now, "quisora "+org.Name+"/"+t.Name)
	for _, k := range keys {
		pub, err := parseSSHKey(k.PublicKey)
		if err != nil {
			continue
		}
		if !k.Removed.IsZero() || !t.SSH.Enabled {
			krl.RevokeKey(pub)
		}
		// A certificates section only for a key ca.pub or known_hosts publishes, and goes on publishing for as long as
		// the list may be kept (quisora ssh fetch refuses a list naming no published key): a removed key is revoked
		// whole, and the serials of its certificates add nothing; a retired key that expires within sshKRLTTL signed
		// nothing that is still valid; the host keys of a tenant whose host certificates are off are not published.
		if !k.Removed.IsZero() || !k.Expires.IsZero() && k.Expires.Before(now.Add(sshKRLTTL)) ||
			k.Purpose == model.SSHPurposeHost && !t.SSH.HostCerts {
			continue
		}
		var serials []uint64
		for _, r := range revoked {
			if r.Cert.CAKeyID == k.ID {
				serials = append(serials, r.Cert.Serial)
			}
		}
		krl.Add(pub, serials...)
	}
	data := krl.Marshal()
	return data, sshca.KRLTag(data), revoked, nil
}

// InvalidateSSHKRL drops the revocation lists this node kept, so the next request makes them afresh. It is called on
// every node for every change of a certificate, a CA key or a tenant, made there or replicated to it, so a revocation
// counts at once everywhere.
func (s *Service) InvalidateSSHKRL() { s.InvalidateSSHKRLOf("") }

// InvalidateSSHKRLOf drops the revocation list this node kept for tenant tenantID ("": every tenant's), so the next
// request makes it afresh. A build under way gives what it makes to its own request and those already waiting for it,
// and does not keep it. While the list's sticky revocations are being written down it counts once they are.
func (s *Service) InvalidateSSHKRLOf(tenantID string) {
	s.ssh.krlMu.Lock()
	defer s.ssh.krlMu.Unlock()
	for id, e := range s.ssh.krl {
		if tenantID == "" || id == tenantID {
			sshKRLInvalidate(e)
		}
	}
}

// InvalidateSSHKRLIn drops the revocation lists this node kept for the tenants of organization orgID ("": every
// tenant's): for a change whose tenant is not known, only its organization (a change notice of a node sharing the
// database carries no index fields).
func (s *Service) InvalidateSSHKRLIn(orgID string) {
	s.ssh.krlMu.Lock()
	defer s.ssh.krlMu.Unlock()
	for _, e := range s.ssh.krl {
		if orgID == "" || e.org == orgID || e.org == "" {
			sshKRLInvalidate(e)
		}
	}
}

// RevokeSSHCert revokes a certificate of organization orgID by hand: an administrator of the organization (or a service
// account with the ssh scope) may revoke any, and a user their own (the account page). It lands on the revocation list
// within 30 seconds. Revoking one already revoked changes nothing.
func (s *Service) RevokeSSHCert(ctx context.Context, a *Actor, orgID, certID string) error {
	for attempt := 0; ; attempt++ {
		c, err := s.SSHCerts.GetIn(ctx, orgID, certID)
		if err != nil {
			return mapStore(err)
		}
		own := c.UserID != "" && c.UserID == a.UserID && a.ClientID == "" && a.OrgID == orgID
		if !own && !s.sshAdmin(a, orgID, ScopeSSH) {
			return ErrForbidden
		}
		if c.Revoked {
			return nil
		}
		c.Revoked, c.RevokedAt, c.RevokedBy = true, time.Now().UTC(), a.Name
		detail := map[string]string{"serial": strconv.FormatUint(c.Serial, 10), "tenant_id": c.TenantID, "key_id": c.KeyID}
		if c.UserID != "" {
			detail["user_id"] = c.UserID
		}
		err = s.audited(ctx, a, orgID, "ssh.cert.revoke", c.KeyID, detail, func() error { return s.SSHCerts.Update(ctx, c) })
		if errors.Is(err, store.ErrStale) && attempt < 3 {
			continue // changed meanwhile: read it again
		}
		if err != nil {
			return mapStore(err)
		}
		s.InvalidateSSHKRLOf(c.TenantID)
		return nil
	}
}

// RevokeSSHCertsFrom revokes for good the certificates of user userID (of organization orgID) issued under one of the
// sessions or grants in from (SSHCert.SignIn), which are being taken back: revoked, ended from elsewhere, or ended as a
// refresh token was replayed (never the user's own sign-out: SignOutSession). A certificate goes with the sign-in it
// was issued under, as the session's applications do; its expiry is not an ending. Each sign-in is recorded as taken
// back first (model.SSHRevokedSignIn, whatever the organization's SSH: a tenant with SSH off keeps its certificates
// for when it is on again), and the revocation lists revoke every certificate issued under it from then on; then the
// user's certificates are listed, and those of the sign-ins marked revoked at once, the already revoked and the
// expired left as they are. In a gossip cluster the listing can miss a certificate being signed on another node (its
// signer still read the sign-in as there, SignUserSSH): the record revokes it once both have replicated. Each marked is
// audited as the system's revocation (ssh.cert.revoke, reason sign_in_ended), as is, when the revocation list finds
// it, one the listing missed (sshPersist).
func (s *Service) RevokeSSHCertsFrom(ctx context.Context, orgID, userID string, from map[string]bool) error {
	if len(from) == 0 || userID == "" {
		return nil
	}
	var errs []error
	expires := time.Now().UTC().Add(sshRevokedSignInFor)
	for _, id := range slices.Sorted(maps.Keys(from)) {
		r := &model.SSHRevokedSignIn{Meta: model.Meta{ID: id}, OrgID: orgID, UserID: userID, Expires: expires}
		if err := s.SSHRevokedSignIns.Put(ctx, r); err != nil {
			errs = append(errs, fmt.Errorf("record sign-in %s as revoked: %w", id, mapStore(err)))
		}
	}
	all, _, err := s.SSHCerts.List(ctx, store.ListQuery{Scope: orgID, Filters: []store.Filter{{Field: "user_id", Value: userID}}})
	if err != nil {
		return errors.Join(append(errs, mapStore(err))...)
	}
	for _, c := range all {
		if c.Revoked || c.SignIn == "" || !from[c.SignIn] || !time.Now().Before(c.ValidBefore) {
			continue
		}
		if _, err := s.sshRevokeSignInEnded(ctx, orgID, c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// carrySSHCerts re-stamps to session epoch epoch the live certificates of user userID issued under one of the
// sessions or grants in from (SSHCert.SignIn): those of the session kept when the user's other sessions end
// (carryOver), which stand on its epoch as it does. The revocation lists of their tenants are dropped on this node: one
// made since the epoch moved revokes them.
func (s *Service) carrySSHCerts(ctx context.Context, orgID, userID string, from map[string]bool, epoch uint64) error {
	all, _, err := s.SSHCerts.List(ctx, store.ListQuery{Scope: orgID, Filters: []store.Filter{{Field: "user_id", Value: userID}}})
	if err != nil {
		return mapStore(err)
	}
	var errs []error
	carried := map[string]bool{} // by tenant
	for _, c := range all {
		if c.Revoked || c.SignIn == "" || !from[c.SignIn] || !time.Now().Before(c.ValidBefore) {
			continue
		}
		for attempt := 0; ; attempt++ {
			c.SessionEpoch = epoch
			err := s.SSHCerts.Update(ctx, c)
			if err == nil {
				carried[c.TenantID] = true
				break
			}
			if !errors.Is(err, store.ErrStale) || attempt == 4 {
				errs = append(errs, mapStore(err))
				break
			}
			if c, err = s.SSHCerts.GetIn(ctx, orgID, c.ID); err != nil || c.Revoked {
				break
			}
		}
	}
	for id := range carried {
		s.InvalidateSSHKRLOf(id)
	}
	return errors.Join(errs...)
}

// sshRevokeSignInEnded marks certificate listed (as just read or stored) revoked by the system for the end of its
// sign-in, unless it is revoked already, and drops its tenant's revocation list on this node; it reports whether it
// marked it. It is read again only when it changed since.
func (s *Service) sshRevokeSignInEnded(ctx context.Context, orgID string, listed *model.SSHCert) (bool, error) {
	c := new(model.SSHCert)
	*c = *listed
	for attempt := 0; ; attempt++ {
		if c.Revoked {
			return false, nil
		}
		c.Revoked, c.RevokedAt, c.RevokedBy, c.RevokedReason = true, time.Now().UTC(), System.Name, SSHReasonSignInEnded
		detail := map[string]string{"serial": strconv.FormatUint(c.Serial, 10), "tenant_id": c.TenantID, "key_id": c.KeyID,
			"user_id": c.UserID, "reason": SSHReasonSignInEnded}
		err := s.audited(ctx, System, orgID, "ssh.cert.revoke", c.KeyID, detail, func() error { return s.SSHCerts.Update(ctx, c) })
		if errors.Is(err, store.ErrStale) && attempt < 3 {
			if c, err = s.SSHCerts.GetIn(ctx, orgID, listed.ID); err != nil { // changed meanwhile: read it again
				return false, mapStore(err)
			}
			continue
		}
		if err != nil {
			return false, mapStore(err)
		}
		s.InvalidateSSHKRLOf(c.TenantID)
		return true, nil
	}
}

// SSHCertFilter narrows ListSSHCerts.
type SSHCertFilter struct {
	UserID string // one user's certificates
	// Status is "active", "expired" or "revoked"; "" and "all": every one.
	Status string
	Host   *bool // only host certificates (true) or only user certificates (false)
	// Search keeps the certificates whose key id (it starts with the username as issued), key fingerprint or serial
	// starts with it, that carry it as a principal, or whose user's username or name starts with it (as the other
	// lists search: a prefix, ignoring case).
	Search string
	Offset int // the first certificate listed, of those that match, newest first
	Limit  int // at most this many (default and most: 1000)
}

// SSHCertView is a certificate as listed, with where it stands.
type SSHCertView struct {
	*model.SSHCert
	Status string `json:"status"`
	// Reason is why a revoked certificate is (the SSHReason… values).
	Reason   string `json:"reason,omitempty"`
	Username string `json:"username,omitempty"` // the user, as now named
}

// sshViews evaluates certs (of tenant t) into listed certificates.
func (s *Service) sshViews(ctx context.Context, ev *sshEval, certs []*model.SSHCert) ([]*SSHCertView, error) {
	// A read that fails here is made again for each certificate below: an expired one is listed without its username,
	// as before, and the status of another fails the listing.
	_ = ev.load(ctx, certs)
	now := time.Now()
	out := make([]*SSHCertView, 0, len(certs))
	for _, c := range certs {
		v := &SSHCertView{SSHCert: c, Status: SSHCertActive}
		if c.UserID != "" {
			if x, err := ev.user(ctx, c.UserID); err == nil && x.u != nil {
				v.Username = x.u.Username
			}
		}
		if !now.Before(c.ValidBefore) {
			v.Status = SSHCertExpired
		} else if reason, err := ev.reason(ctx, c); err != nil {
			return nil, err
		} else if reason != "" {
			v.Status, v.Reason = SSHCertRevoked, reason
		}
		out = append(out, v)
	}
	return out, nil
}

// ListSSHCerts lists the certificates of a tenant, newest first, each with whether it is active, expired or revoked and
// why (administrators of the organization, and service accounts with the ssh scope): ListSSHCertsCounted without the
// count.
func (s *Service) ListSSHCerts(ctx context.Context, a *Actor, tenantID string, f SSHCertFilter) ([]*SSHCertView, error) {
	views, _, err := s.ListSSHCertsCounted(ctx, a, tenantID, f)
	return views, err
}

// ListSSHCertsCounted lists the certificates of a tenant that match f, newest first, each with whether it is active,
// expired or revoked and why, from f.Offset at most f.Limit of them, and says how many match in all (as the other
// listings count: every match, not those returned).
func (s *Service) ListSSHCertsCounted(ctx context.Context, a *Actor, tenantID string, f SSHCertFilter) ([]*SSHCertView, int, error) {
	t, err := s.tenantForSSH(ctx, a, tenantID)
	if err != nil {
		return nil, 0, err
	}
	switch f.Status {
	case "", "all", SSHCertActive, SSHCertExpired, SSHCertRevoked:
	default:
		return nil, 0, Invalid("status", "must be active, expired, revoked or all")
	}
	if t.SSH == nil {
		return []*SSHCertView{}, 0, nil
	}
	certs, err := s.sshCertsMatching(ctx, t, f)
	if err != nil {
		return nil, 0, err
	}
	slices.SortFunc(certs, func(x, y *model.SSHCert) int {
		if c := y.Created.Compare(x.Created); c != 0 {
			return c
		}
		return strings.Compare(y.ID, x.ID)
	})
	// A status is worked out only for the certificates that need it: none for "all" or "expired" (the end time says),
	// of which only the page is evaluated, and every unexpired one for "active" and "revoked" (their count needs it).
	now := time.Now()
	switch f.Status {
	case SSHCertExpired:
		certs = slices.DeleteFunc(certs, func(c *model.SSHCert) bool { return now.Before(c.ValidBefore) })
	case SSHCertActive, SSHCertRevoked:
		certs = slices.DeleteFunc(certs, func(c *model.SSHCert) bool { return !now.Before(c.ValidBefore) })
	}
	ev, err := s.newSSHEval(ctx, t)
	if err != nil {
		return nil, 0, err
	}
	var views []*SSHCertView
	if f.Status == SSHCertActive || f.Status == SSHCertRevoked {
		if views, err = s.sshViews(ctx, ev, certs); err != nil {
			return nil, 0, err
		}
		views = slices.DeleteFunc(views, func(v *SSHCertView) bool { return v.Status != f.Status })
	} else {
		limit, offset := sshPage(f, len(certs))
		if views, err = s.sshViews(ctx, ev, certs[offset:min(offset+limit, len(certs))]); err != nil {
			return nil, 0, err
		}
		return views, len(certs), nil
	}
	total := len(views)
	limit, offset := sshPage(f, total)
	return views[offset:min(offset+limit, total)], total, nil
}

// sshPage is the page f asks of n certificates: its limit (at most 1000) and its offset, no further than the end.
func sshPage(f SSHCertFilter, n int) (limit, offset int) {
	limit = f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	return limit, min(max(f.Offset, 0), n)
}

// sshSearchUsers is how many users a search of certificates takes a username or name to be (the first by the store's
// order); a prefix that names more is too short to be read as a person.
const sshSearchUsers = 50

// sshCertsMatching returns the certificates of tenant t that f selects by user, host and search, whatever their status.
func (s *Service) sshCertsMatching(ctx context.Context, t *model.Tenant, f SSHCertFilter) ([]*model.SSHCert, error) {
	host := f.Host != nil && *f.Host
	needle := strings.TrimSpace(f.Search)
	if needle == "" {
		switch {
		case host && f.UserID != "": // a user has no host certificates
			return nil, nil
		case host:
			return s.sshHostCerts(ctx, t, false)
		case f.Host != nil || f.UserID != "":
			return s.sshUserCerts(ctx, t, f.UserID)
		}
		return s.tenantCerts(ctx, t)
	}
	users := f.Host == nil || !*f.Host
	hosts := f.UserID == "" && (f.Host == nil || host)
	// one set of filters per kind of certificate: the tenant's user certificates (of one user, when asked), and the
	// tenant's host certificates
	var kinds [][]store.Filter
	if users {
		fl := []store.Filter{{Field: "tenant_id", Value: t.ID}}
		if f.UserID != "" {
			fl = append([]store.Filter{{Field: "user_id", Value: f.UserID}}, fl...)
		}
		kinds = append(kinds, fl)
	}
	if hosts {
		kinds = append(kinds, []store.Filter{{Field: "host_tenant_id", Value: t.ID}})
	}
	seen := map[string]bool{}
	var out []*model.SSHCert
	add := func(certs []*model.SSHCert) {
		for _, c := range certs {
			if !seen[c.ID] {
				seen[c.ID] = true
				out = append(out, c)
			}
		}
	}
	for _, fl := range kinds {
		certs, err := s.sshCertsSearch(ctx, t.OrgID, needle, fl...) // key id, fingerprint, serial
		if err != nil {
			return nil, err
		}
		add(certs)
		if !strings.ContainsAny(needle, " \t\n") { // a principal, whole
			certs, err = s.sshCertsWhere(ctx, t.OrgID, append(slices.Clone(fl), store.Filter{Field: "principals", Value: needle})...)
			if err != nil {
				return nil, err
			}
			add(certs)
		}
	}
	if users { // the user's name, which a certificate does not carry, and the username they have now
		found, _, err := s.Users.List(ctx, store.ListQuery{Scope: t.OrgID, Search: needle, Limit: sshSearchUsers})
		if err != nil {
			return nil, mapStore(err)
		}
		for _, u := range found {
			if f.UserID != "" && u.ID != f.UserID {
				continue
			}
			certs, err := s.sshUserCerts(ctx, t, u.ID)
			if err != nil {
				return nil, err
			}
			add(certs)
		}
	}
	return out, nil
}

// SSHCertsOf lists u's own certificates that have not expired (active and revoked), newest first, across the
// organization's tenants: for the account page, whose user may see and revoke them.
func (s *Service) SSHCertsOf(ctx context.Context, u *model.User) ([]*SSHCertView, error) {
	all, _, err := s.SSHCerts.List(ctx, store.ListQuery{Scope: u.OrgID, Filters: []store.Filter{{Field: "user_id", Value: u.ID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	now := time.Now()
	byTenant := map[string][]*model.SSHCert{}
	for _, c := range all {
		if now.Before(c.ValidBefore) {
			byTenant[c.TenantID] = append(byTenant[c.TenantID], c)
		}
	}
	out := []*SSHCertView{}
	for id, certs := range byTenant {
		t, err := s.Tenants.GetIn(ctx, u.OrgID, id)
		if errors.Is(err, store.ErrNotFound) {
			continue // the tenant is gone: so are its servers' trust in it
		}
		if err != nil {
			return nil, mapStore(err)
		}
		ev, err := s.newSSHEval(ctx, t)
		if err != nil {
			return nil, err
		}
		views, err := s.sshViews(ctx, ev, certs)
		if err != nil {
			return nil, err
		}
		out = append(out, views...)
	}
	slices.SortFunc(out, func(x, y *SSHCertView) int { return strings.Compare(y.ID, x.ID) })
	return out, nil
}

// SSHCertsOfUser lists user u's certificates that have not expired, across the organization's tenants, for the user's
// page in the console: SSHCertsOf, for those who administer SSH in u's organization (its administrators, and service
// accounts with the ssh scope). ErrForbidden for anyone else, managers included.
func (s *Service) SSHCertsOfUser(ctx context.Context, a *Actor, u *model.User) ([]*SSHCertView, error) {
	if !s.sshAdmin(a, u.OrgID, ScopeSSH) {
		return nil, ErrForbidden
	}
	return s.SSHCertsOf(ctx, u)
}
