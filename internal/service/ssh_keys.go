package service

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/store"
)

// The CA keys of a tenant. A user CA key is published from the moment it is made, signs from NotBefore until RetireAt,
// and stays published until Expires: long enough that a server that fetches ca.pub once a day has seen it before it
// signs, and still trusts it while the certificates it signed are valid. Host CA keys are kept until removed by hand.
const (
	// sshRotationLead is how long a user CA key's successor is published before it signs.
	sshRotationLead = 7 * 24 * time.Hour
	// sshRetireGrace is how long a retired user CA key is still published: the longest certificate it signed (a day)
	// and an hour for a server's clock and its next fetch.
	sshRetireGrace = 25 * time.Hour
)

// sshState is what a node keeps for SSH: a lock for changing keys, and the revocation lists made lately.
type sshState struct {
	mu    sync.Mutex // making, rotating and removing CA keys on this node
	krlMu sync.Mutex
	krl   map[string]*sshKRLEntry
}

// parseSSHKey parses a stored public key (authorized_keys form).
func parseSSHKey(line string) (ssh.PublicKey, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return k, err
}

// SSHKeyFingerprint is the SHA256:… fingerprint of CA key k's public key ("" for one that cannot be read).
func SSHKeyFingerprint(k *model.SSHKey) string {
	pub, err := parseSSHKey(k.PublicKey)
	if err != nil {
		return ""
	}
	return sshca.Fingerprint(pub)
}

// sshKeyRecords returns the CA key records of tenant t that have not expired: the published keys and the tombstones of
// removed ones (Removed set).
func (s *Service) sshKeyRecords(ctx context.Context, t *model.Tenant) ([]*model.SSHKey, error) {
	all, _, err := s.SSHCAKeys.List(ctx, store.ListQuery{Scope: t.OrgID, Filters: []store.Filter{{Field: "tenant_id", Value: t.ID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	now := time.Now()
	return slices.DeleteFunc(all, func(k *model.SSHKey) bool { return !k.Expires.IsZero() && !now.Before(k.Expires) }), nil
}

// sshKeysIn returns the published CA keys of tenant t (not removed, Expires zero or still to come), oldest first;
// purpose "" for both purposes.
func (s *Service) sshKeysIn(ctx context.Context, t *model.Tenant, purpose string) ([]*model.SSHKey, error) {
	all, err := s.sshKeyRecords(ctx, t)
	if err != nil {
		return nil, err
	}
	keys := all[:0]
	for _, k := range all {
		if (purpose == "" || k.Purpose == purpose) && k.Removed.IsZero() {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b *model.SSHKey) int {
		if c := a.NotBefore.Compare(b.NotBefore); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return keys, nil
}

// SSHKeys returns the published CA keys of a tenant (those that have not expired), oldest first, for the public
// endpoints: purpose "user" or "host", or "" for both.
func (s *Service) SSHKeys(ctx context.Context, tenantID, purpose string) ([]*model.SSHKey, error) {
	t, err := s.Tenants.Get(ctx, tenantID)
	if err != nil {
		return nil, mapStore(err)
	}
	return s.sshKeysIn(ctx, t, purpose)
}

// SSHKeysOf is SSHKeys for a tenant already read (SSHTenantByRef).
func (s *Service) SSHKeysOf(ctx context.Context, t *model.Tenant, purpose string) ([]*model.SSHKey, error) {
	return s.sshKeysIn(ctx, t, purpose)
}

func sshOfPurpose(keys []*model.SSHKey, purpose string) []*model.SSHKey {
	var out []*model.SSHKey
	for _, k := range keys {
		if k.Purpose == purpose {
			out = append(out, k)
		}
	}
	return out
}

// sshSigning is the key of keys (all of one purpose) that signs at now: the newest that has started and not retired.
func sshSigning(keys []*model.SSHKey, now time.Time) *model.SSHKey {
	var best *model.SSHKey
	for _, k := range keys {
		if k.NotBefore.After(now) || (!k.RetireAt.IsZero() && !now.Before(k.RetireAt)) {
			continue
		}
		if best == nil || k.NotBefore.After(best.NotBefore) {
			best = k
		}
	}
	return best
}

// sshKeyState is the state of key k at now, given the key that signs (sshSigning).
func sshKeyState(k, signer *model.SSHKey, now time.Time) string {
	switch {
	case k.NotBefore.After(now):
		return SSHKeyNext
	case k == signer:
		return SSHKeyActive
	}
	return SSHKeyRetired
}

// newSSHKey makes a CA key for tenant t that starts signing at notBefore; nothing is written.
func (s *Service) newSSHKey(t *model.Tenant, purpose string, notBefore time.Time) (*model.SSHKey, error) {
	pub, priv, err := sshca.GenerateCA()
	if err != nil {
		return nil, err
	}
	id := model.NewID()
	return &model.SSHKey{Meta: model.Meta{ID: id}, OrgID: t.OrgID, TenantID: t.ID, Purpose: purpose, Alg: model.SSHAlgEd25519,
		PublicKey: pub, PrivateKey: s.Sealer.SealFor(SSHKeyBinding(id), priv), NotBefore: notBefore.UTC()}, nil
}

func sshKeyDetail(k *model.SSHKey) map[string]string {
	d := map[string]string{"key_id": k.ID, "purpose": k.Purpose, "not_before": k.NotBefore.Format(time.RFC3339)}
	if pub, err := parseSSHKey(k.PublicKey); err == nil {
		d["fingerprint"] = sshca.Fingerprint(pub)
	}
	return d
}

// ensureSSHKeys makes the CA keys SSH needs while it is enabled on tenant t, when it has none that signs or is about
// to: the user key, and the host key when host certificates are on. Under the node's key lock and checking the store
// first, so enabling twice makes one (two nodes enabling at the very same moment may each make one: both are published
// and the newer signs).
func (s *Service) ensureSSHKeys(ctx context.Context, a *Actor, t *model.Tenant) error {
	s.ssh.mu.Lock()
	defer s.ssh.mu.Unlock()
	keys, err := s.sshKeysIn(ctx, t, "")
	if err != nil {
		return err
	}
	now := time.Now()
	for _, purpose := range []string{model.SSHPurposeUser, model.SSHPurposeHost} {
		if purpose == model.SSHPurposeHost && !t.SSH.HostCerts {
			continue
		}
		of := sshOfPurpose(keys, purpose)
		if sshSigning(of, now) != nil || slices.ContainsFunc(of, func(k *model.SSHKey) bool { return k.NotBefore.After(now) }) {
			continue
		}
		k, err := s.newSSHKey(t, purpose, now)
		if err != nil {
			return err
		}
		if err := s.audited(ctx, a, t.OrgID, "ssh.ca.create", t.Name, sshKeyDetail(k),
			func() error { return s.SSHCAKeys.Create(ctx, k) }); err != nil {
			return mapStore(err)
		}
	}
	return nil
}

// errNoSSHKey: the tenant has no CA key that signs now.
var errNoSSHKey = errors.New("no SSH CA key signs for this tenant")

// sshSigner returns the key of tenant t that signs for purpose now, with its private half opened.
func (s *Service) sshSigner(ctx context.Context, t *model.Tenant, purpose string) (*model.SSHKey, ssh.Signer, error) {
	keys, err := s.sshKeysIn(ctx, t, purpose)
	if err != nil {
		return nil, nil, err
	}
	k := sshSigning(keys, time.Now())
	if k == nil {
		return nil, nil, errNoSSHKey
	}
	der, err := s.Sealer.OpenFor(SSHKeyBinding(k.ID), k.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	signer, err := sshca.ParseCA(der)
	if err != nil {
		return nil, nil, err
	}
	return k, signer, nil
}

// RotateSSHKey makes the tenant's purpose ("user" or "host") CA key a successor (administrators of the organization,
// and service accounts with the ssh scope). A user key's successor is published at once and signs in seven days, so
// servers that fetch ca.pub daily have it first; a host key's signs at once and the old one stays published until
// removed. immediate retires the old key now whatever the purpose: the successor signs at once, and a user key's
// predecessor is published for one more day (the longest certificate it signed) and then goes. A rotation under way
// (a successor that has not started) is replaced by an immediate one.
func (s *Service) RotateSSHKey(ctx context.Context, a *Actor, tenantID, purpose string, immediate bool) (*model.SSHKey, error) {
	t, err := s.tenantForSSH(ctx, a, tenantID)
	if err != nil {
		return nil, err
	}
	if purpose != model.SSHPurposeUser && purpose != model.SSHPurposeHost {
		return nil, Invalid("purpose", "must be user or host")
	}
	if t.SSH == nil {
		return nil, Invalid("ssh", "SSH has not been set up on this tenant: enable it first")
	}
	return s.rotateSSH(ctx, a, t, purpose, immediate, false)
}

// rotateSSH makes the successor for RotateSSHKey, or (scheduled) for EnsureSSHKeys, which only does it when the newest
// user key is due: nil, nil when it is not (another node did it first).
func (s *Service) rotateSSH(ctx context.Context, a *Actor, t *model.Tenant, purpose string, immediate, scheduled bool) (*model.SSHKey, error) {
	s.ssh.mu.Lock()
	defer s.ssh.mu.Unlock()
	keys, err := s.sshKeysIn(ctx, t, purpose)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var pending, signing []*model.SSHKey // successors that have not started, keys that sign (or are due to)
	for _, k := range keys {
		switch {
		case k.NotBefore.After(now):
			pending = append(pending, k)
		case k.RetireAt.IsZero() || now.Before(k.RetireAt):
			signing = append(signing, k)
		}
	}
	if purpose == model.SSHPurposeHost && !t.SSH.HostCerts && len(keys) == 0 {
		return nil, Invalid("purpose", "host certificates are off")
	}
	notBefore := now
	if purpose == model.SSHPurposeUser && !immediate {
		if scheduled {
			if len(keys) == 0 { // a tenant with no key is made one by ensureSSHKeys
				return nil, nil
			}
			newest := keys[len(keys)-1]
			if len(pending) > 0 || now.Before(newest.NotBefore.Add(time.Duration(t.SSH.RotationDays)*24*time.Hour-sshRotationLead)) {
				return nil, nil
			}
		} else if len(pending) > 0 {
			return nil, Invalid("immediate", "a rotation is already under way: the next key starts signing at "+
				pending[len(pending)-1].NotBefore.Format(time.RFC3339)+"; rotate immediately to replace it")
		}
		notBefore = now.Add(sshRotationLead)
	}
	nk, err := s.newSSHKey(t, purpose, notBefore)
	if err != nil {
		return nil, err
	}
	detail := sshKeyDetail(nk)
	detail["immediate"] = strconv.FormatBool(immediate)
	if scheduled {
		detail["scheduled"] = "true"
	}
	var retired []string
	for _, k := range signing {
		retired = append(retired, k.ID)
	}
	if len(retired) > 0 {
		detail["retires"] = strings.Join(retired, ",")
	}
	err = s.audited(ctx, a, t.OrgID, "ssh.ca.rotate", t.Name, detail, func() error {
		if err := s.SSHCAKeys.Create(ctx, nk); err != nil {
			return err
		}
		for _, k := range pending { // a rotation under way, replaced: its key never signed anything
			if err := s.SSHCAKeys.Delete(ctx, k.ID); err != nil {
				return err
			}
		}
		for _, k := range signing {
			k.RetireAt = notBefore
			if purpose == model.SSHPurposeUser {
				k.Expires = notBefore.Add(sshRetireGrace)
			}
			if err := s.SSHCAKeys.Update(ctx, k); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, mapStore(err)
	}
	s.InvalidateSSHKRL()
	return nk, nil
}

// sshTombstoneFor is how long the tombstone of a removed CA key of purpose is kept: the longest certificate it can have
// signed (it signed none after its removal) and the revocation list's grace, so that the list revokes the key itself
// for as long as any of them could be presented.
func sshTombstoneFor(purpose string) time.Duration {
	if purpose == model.SSHPurposeHost {
		return sshMaxHostTTLDays*24*time.Hour + sshKRLGrace
	}
	return sshMaxCertTTL*time.Second + sshKRLGrace
}

// RemoveSSHKey removes a CA key that no longer signs (administrators of the organization, and service accounts with the
// ssh scope), at once rather than when it expires: it is no longer published, and the revocation list revokes the key
// itself (a server whose ca.pub or known_hosts is stale still lists it) until every certificate it signed has expired:
// its record is kept that long without its private half (sshTombstoneFor). For a key that may have been exposed: rotate
// immediately first, then remove it.
func (s *Service) RemoveSSHKey(ctx context.Context, a *Actor, tenantID, keyID string) error {
	t, err := s.tenantForSSH(ctx, a, tenantID)
	if err != nil {
		return err
	}
	s.ssh.mu.Lock()
	defer s.ssh.mu.Unlock()
	k, err := s.SSHCAKeys.Get(ctx, keyID)
	if err != nil || k.TenantID != t.ID || k.OrgID != t.OrgID || !k.Removed.IsZero() {
		return ErrNotFound
	}
	keys, err := s.sshKeysIn(ctx, t, k.Purpose)
	if err != nil {
		return err
	}
	now := time.Now()
	switch {
	case k.NotBefore.After(now):
		return Invalid("id", "this key has not started signing yet; only a key that no longer signs can be removed")
	case sshSigning(keys, now) != nil && sshSigning(keys, now).ID == k.ID:
		return Invalid("id", "this key signs certificates now: rotate first, then remove it")
	}
	now = now.UTC()
	k.PrivateKey, k.Removed, k.Expires = "", now, now.Add(sshTombstoneFor(k.Purpose))
	if err := s.audited(ctx, a, t.OrgID, "ssh.ca.remove", t.Name, sshKeyDetail(k),
		func() error { return s.SSHCAKeys.Update(ctx, k) }); err != nil {
		return mapStore(err)
	}
	s.InvalidateSSHKRL()
	return nil
}

// EnsureSSHKeys is the housekeeping of SSH, run by the leader and safe to repeat: for every tenant with SSH on it makes
// what is missing (sshHousekeep), so an enabling that failed after the tenant was written is finished within a minute,
// and for those with a RotationDays it makes the user CA key's successor once the newest key is RotationDays minus a
// week old (published at once, signing a week later). Keys that have expired, and the tombstones of removed ones, leave
// the store by themselves.
func (s *Service) EnsureSSHKeys(ctx context.Context) error {
	var errs []error
	for after := ""; ; {
		page, _, err := s.Tenants.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "ssh_enabled", Value: true}}, After: after, Limit: 500})
		if err != nil {
			return errors.Join(append(errs, mapStore(err))...)
		}
		for _, t := range page {
			if t.SSH == nil || !t.SSH.Enabled {
				continue
			}
			if err := s.sshHousekeep(ctx, t); err != nil {
				errs = append(errs, err)
			}
		}
		if len(page) < 500 {
			break
		}
		after = page[len(page)-1].ID
	}
	return errors.Join(errs...)
}

// sshHousekeep makes, as the system, what SSH needs on tenant t (which has it on) and is missing: the SSH application
// (recorded on the tenant; one made again in place of a deleted one is logged), the CA keys (ensureSSHKeys) and the
// application's device_privileged_users in step; it removes SSH applications of the tenant other than its own that an
// hour has left behind (removeSSHApps); then the user CA key's scheduled rotation when it is due. UpdateTenantSSH makes all of it when SSH is turned on; a failure
// after it wrote the tenant (a CA key not made, which refuses every certificate) is made good here.
func (s *Service) sshHousekeep(ctx context.Context, t *model.Tenant) error {
	was := snapshot(t.SSH)
	made, err := s.ensureSSHClient(ctx, t)
	if err != nil {
		return err
	}
	if made {
		if err := s.audited(ctx, System, t.OrgID, "ssh.settings.update", t.Name, addChanges(nil, was, t.SSH),
			func() error { return s.Tenants.Update(ctx, t) }); err != nil {
			s.dropSSHClient(ctx, t.SSH.ClientID, err)
			return tenantConflict(err)
		}
	}
	if err := s.ensureSSHKeys(ctx, System, t); err != nil {
		return err
	}
	if err := s.syncSSHClient(ctx, t); err != nil {
		return err
	}
	if _, err := s.removeSSHApps(ctx, t, t.SSH.ClientID, sweepMinAge); err != nil {
		return err
	}
	if t.SSH.RotationDays > 0 {
		if _, err := s.rotateSSH(ctx, System, t, model.SSHPurposeUser, false, true); err != nil {
			return err
		}
	}
	return nil
}
