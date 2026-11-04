package service

import (
	"context"
	"errors"
	"github.com/paularlott/quisora/internal/store"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// What a user is connected to: the applications they granted access to and the sign-in providers linked to their
// account. The user sees and ends both from the account page; managers and up see and end them on the admin user page
// for the users they manage (to sort things out for someone in a mess) and for themselves.

// AppGrant is an application the user granted access to: their live refresh grants for one client and the consent
// remembered for it (model.Consent), together.
type AppGrant struct {
	ClientID string    `json:"client_id"`
	Name     string    `json:"name"`
	Scopes   []string  `json:"scopes"`
	Since    time.Time `json:"since"`
	LastUsed time.Time `json:"last_used"`
	Grants   int       `json:"grants"`
	// Remembered: the user's consent is remembered, so the application signs them in without asking again.
	Remembered bool `json:"remembered"`
}

// ConnectedApps lists the applications the user granted access to (live refresh grants and remembered consent,
// grouped by client), by name.
func (s *Service) ConnectedApps(ctx context.Context, userID string) ([]AppGrant, error) {
	grants, err := s.Grants.All(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	consents, err := s.Consents.All(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	now := time.Now()
	by := map[string]*AppGrant{}
	clients := map[string]*model.Client{} // read once each; nil: removed (or unreadable)
	client := func(id string) *model.Client {
		c, ok := clients[id]
		if !ok {
			c, _ = s.Clients.Get(ctx, id)
			clients[id] = c
		}
		return c
	}
	app := func(clientID string, since time.Time) *AppGrant {
		it := by[clientID]
		if it == nil {
			it = &AppGrant{ClientID: clientID, Name: "Removed application", Scopes: []string{}, Since: since}
			if c := client(clientID); c != nil {
				it.Name = c.Name
			}
			by[clientID] = it
		}
		if since.Before(it.Since) {
			it.Since = since
		}
		return it
	}
	addScopes := func(it *AppGrant, scopes []string) {
		for _, sc := range scopes {
			if !slices.Contains(it.Scopes, sc) {
				it.Scopes = append(it.Scopes, sc)
			}
		}
	}
	for _, c := range consents {
		// one the client no longer honours (it stopped remembering: forgetConsents) is left out; one of a removed
		// client is shown, as a grant of one is, until the sweep removes it
		if cl := client(c.ClientID); cl != nil && !RemembersConsent(cl) {
			continue
		}
		it := app(c.ClientID, c.Created)
		it.Remembered = true
		if c.Updated.After(it.LastUsed) {
			it.LastUsed = c.Updated
		}
		for _, set := range c.Allowed {
			addScopes(it, set.Scopes)
		}
	}
	for _, g := range grants {
		if !g.Expires.IsZero() && now.After(g.Expires) {
			continue
		}
		it := app(g.ClientID, g.Created)
		it.Grants++
		if g.Updated.After(it.LastUsed) {
			it.LastUsed = g.Updated
		}
		addScopes(it, g.Scopes)
	}
	out := make([]AppGrant, 0, len(by))
	for _, it := range by {
		slices.Sort(it.Scopes)
		out = append(out, *it)
	}
	slices.SortFunc(out, func(a, b AppGrant) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, nil
}

// ProviderLink is a sign-in provider account linked to the user.
type ProviderLink struct {
	ProviderID string    `json:"provider_id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Enabled    bool      `json:"enabled"`         // the provider is on (a link to a disabled one signs nothing in)
	Email      string    `json:"email,omitempty"` // the address the provider gave when it was linked
	Via        string    `json:"via,omitempty"`   // how it was linked: email, provision, connect or admin
	Linked     time.Time `json:"linked"`
}

// LinkedProviders lists the sign-in providers linked to the user (one entry per provider, the latest link), by name.
func (s *Service) LinkedProviders(ctx context.Context, userID string) ([]ProviderLink, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	ids, err := s.CurrentIdentities(ctx, u)
	if err != nil {
		return nil, err
	}
	by := map[string]*ProviderLink{}
	for _, id := range ids {
		if l := by[id.ProviderID]; l != nil && !id.Created.After(l.Linked) {
			continue
		}
		l := &ProviderLink{ProviderID: id.ProviderID, Name: "Removed provider", Email: id.Email, Via: id.Via, Linked: id.Created}
		if p, err := s.Providers.Get(ctx, id.ProviderID); err == nil {
			l.Name, l.Type, l.Enabled = p.Name, p.Type, p.Enabled
		}
		by[id.ProviderID] = l
	}
	out := make([]ProviderLink, 0, len(by))
	for _, l := range by {
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b ProviderLink) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, nil
}

// manageConnections checks that a may end u's connections: someone who can manage u, or u themselves self-service
// (the caller checked a recent re-authentication where the change needs one).
func (s *Service) manageConnections(ctx context.Context, a *Actor, u *model.User) error {
	if a == nil {
		a = System
	}
	if a != System && a.UserID == u.ID {
		if !isSelfService(ctx) {
			return ErrForbidden
		}
		return nil
	}
	if a != System && !s.canManageUser(a, u) {
		return s.denied(a, u)
	}
	return nil
}

// RemoveUserApp ends a user's access to one application for them (RevokeAppAccess: the application is told to sign
// the user out, then the grants go). It returns how many grants it removed; 0 means none.
func (s *Service) RemoveUserApp(ctx context.Context, a *Actor, userID, clientID string) (int, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return 0, mapStore(err)
	}
	if err := s.manageConnections(ctx, a, u); err != nil {
		return 0, err
	}
	n, err := s.RevokeAppAccess(ctx, userID, clientID)
	if n == 0 && !outcomeUnknown(err) {
		return 0, err // nothing was revoked, and nothing may have been
	}
	name := clientID
	if c, err := s.Clients.Get(ctx, clientID); err == nil {
		name = c.Name
	}
	rec := err
	if n > 0 {
		rec = nil // some grants did go (the error is the rest that did not): recorded as done
	}
	s.auditOutcome(ctx, a, rec, userChange(u, "user.app.revoke", map[string]string{"client": name, "client_id": clientID}))
	return n, err
}

// DisconnectProvider unlinks every identity the user has at one provider (removeWay). It returns how many links it
// removed.
func (s *Service) DisconnectProvider(ctx context.Context, a *Actor, userID, providerID string) (int, error) {
	n := 0
	err := s.removeWay(ctx, a, userID, way{provider: providerID}, func(u *model.User, gone []model.Credential) (string, map[string]string) {
		n = len(gone)
		name := providerID
		if p, err := s.Providers.Get(ctx, providerID); err == nil {
			name = p.Name
		}
		return selfOr(a, u, "account.provider.disconnect", "user.provider.disconnect"), map[string]string{"provider": name}
	}, nil)
	return n, err
}

// UserPasskeys returns the user's passkeys, oldest first, for whoever may manage their connections.
func (s *Service) UserPasskeys(ctx context.Context, a *Actor, userID string) ([]*model.Passkey, error) {
	u, err := s.Users.Get(ctx, userID)
	if err != nil {
		return nil, mapStore(err)
	}
	if err := s.manageConnections(ctx, a, u); err != nil {
		return nil, err
	}
	list, err := s.CurrentPasskeys(ctx, u)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(list, func(x, y *model.Passkey) int { return x.Created.Compare(y.Created) })
	return list, nil
}

// RemovePasskey deletes one of the user's passkeys (a lost or replaced device, a suspected copy; removeWay) and ends
// the sessions that signed in with it, with their refresh grants (applications are told by back-channel logout), but
// keepSession (the one removing it, which has just confirmed it is the user). It returns how many sessions ended; an
// error with a count is a passkey removed whose sessions did not all end.
func (s *Service) RemovePasskey(ctx context.Context, a *Actor, userID, passkeyID, keepSession string) (int, error) {
	ended := 0
	err := s.removeWay(ctx, a, userID, way{passkey: passkeyID}, func(u *model.User, gone []model.Credential) (string, map[string]string) {
		return selfOr(a, u, "account.passkey.delete", "user.passkey.remove"), map[string]string{"name": gone[0].(*model.Passkey).Name}
	}, func(u *model.User, gone []model.Credential, detail map[string]string) ([]store.Op, error) {
		// The sessions the passkey signed in, and their refresh grants, end in the transaction that removes it.
		ids, ops, err := s.passkeySessionEnds(ctx, u.ID, gone[0].GetMeta().ID, keepSession)
		if err != nil {
			return nil, err
		}
		ended = len(ids)
		detail["sessions_ended"] = strconv.Itoa(ended)
		return ops, nil
	})
	if err != nil {
		ended = 0
	}
	return ended, err
}

// RemoveTOTP removes the user's authenticator app (removeWay: done to yourself, not your last second factor where
// one is required).
func (s *Service) RemoveTOTP(ctx context.Context, a *Actor, userID string) error {
	return s.removeWay(ctx, a, userID, way{totp: true}, func(u *model.User, _ []model.Credential) (string, map[string]string) {
		return selfOr(a, u, "account.totp.disable", "user.totp.remove"), nil
	}, nil)
}

// Creds is what an account holds, read once: its passkeys and provider links that count (model.User.Counts; links
// only to providers that still exist), able to sign in or not, and whether each linked provider is on. Listings show
// these; what can sign the user in is worked out from them (Ways).
type Creds struct {
	Passkeys   []*model.Passkey
	Links      []*model.Identity
	ProviderOn map[string]bool // by provider id
}

// Ways is what can sign a user in: the password, the authenticator app, the passkeys that can sign in
// (model.Passkey.Usable) and the links to providers that are on. It is the one definition of a usable way in: the
// last-way guards and the second-factor checks all take it from here (sign-in takes the same passkeys:
// passkey.Service).
type Ways struct {
	Password, TOTP bool
	Passkeys       []*model.Passkey
	Providers      []*model.Identity
}

// Ways returns what of c, with u's password and authenticator app, can sign u in.
func (c *Creds) Ways(u *model.User) *Ways {
	w := &Ways{Password: u.PasswordHash != "", TOTP: u.HasTOTP()}
	for _, p := range c.Passkeys {
		if p.Usable() {
			w.Passkeys = append(w.Passkeys, p)
		}
	}
	for _, i := range c.Links {
		if c.ProviderOn[i.ProviderID] {
			w.Providers = append(w.Providers, i)
		}
	}
	return w
}

// UserWays returns u's ways in, from this node's copies.
func (s *Service) UserWays(ctx context.Context, u *model.User) (*Ways, error) {
	c, err := s.UserCreds(ctx, u)
	if err != nil {
		return nil, err
	}
	return c.Ways(u), nil
}

// UserCreds reads u's credentials: their passkeys and provider links that count (model.User.Counts; links only to
// providers that still exist), as this node holds them (the store's bound: a copy current within StaleAfter, or a
// refusal). A removal decided on them is a compare-and-swap of u, so one decided on copies another removal has since
// changed is refused and decided again.
func (s *Service) UserCreds(ctx context.Context, u *model.User) (*Creds, error) {
	pks, err := s.Passkeys.All(ctx, u.ID)
	if err != nil {
		return nil, mapStore(err)
	}
	links, err := s.Identities.All(ctx, u.ID)
	if err != nil {
		return nil, mapStore(err)
	}
	c := &Creds{ProviderOn: map[string]bool{}}
	c.Passkeys = slices.DeleteFunc(pks, func(p *model.Passkey) bool { return !u.Counts(p) })
	links = slices.DeleteFunc(links, func(i *model.Identity) bool { return !u.Counts(i) })
	var provIDs []string
	for _, i := range links {
		if !slices.Contains(provIDs, i.ProviderID) {
			provIDs = append(provIDs, i.ProviderID)
		}
	}
	provs, err := s.Providers.GetMany(ctx, provIDs)
	if err != nil {
		return nil, mapStore(err)
	}
	exists := map[string]bool{}
	for _, p := range provs {
		exists[p.ID], c.ProviderOn[p.ID] = true, p.Enabled
	}
	c.Links = slices.DeleteFunc(links, func(i *model.Identity) bool { return !exists[i.ProviderID] }) // a deleted provider: the sweep removes the link
	return c, nil
}

// CurrentPasskeys returns u's passkeys that count (model.User.Counts), able to sign in or not (a disabled one is
// listed, to be removed): what every listing of passkeys shows, and what sign-in offers.
func (s *Service) CurrentPasskeys(ctx context.Context, u *model.User) ([]*model.Passkey, error) {
	l, err := s.Passkeys.All(ctx, u.ID)
	if err != nil {
		return nil, mapStore(err)
	}
	return slices.DeleteFunc(l, func(p *model.Passkey) bool { return !u.Counts(p) }), nil
}

// CurrentIdentities returns u's links to sign-in providers that count (to a provider that still exists, on or off):
// what every listing of connected providers shows.
func (s *Service) CurrentIdentities(ctx context.Context, u *model.User) ([]*model.Identity, error) {
	c, err := s.UserCreds(ctx, u)
	if err != nil {
		return nil, err
	}
	return c.Links, nil
}

// way names what a removal takes: a passkey (id), the links to a provider (id), or the authenticator app.
type way struct {
	passkey, provider string
	totp              bool
}

// field is the input field a refusal of x names.
func (x way) field() string {
	switch {
	case x.totp:
		return "totp"
	case x.provider != "":
		return "provider"
	}
	return "passkey"
}

// of returns the credentials of c that x names.
func (x way) of(c *Creds) []model.Credential {
	var out []model.Credential
	for _, p := range c.Passkeys {
		if x.passkey != "" && p.ID == x.passkey {
			out = append(out, p)
		}
	}
	for _, i := range c.Links {
		if x.provider != "" && i.ProviderID == x.provider {
			out = append(out, i)
		}
	}
	return out
}

// without returns w less the way x.
func (w *Ways) without(x way) *Ways {
	out := *w
	out.TOTP = w.TOTP && !x.totp
	out.Passkeys = slices.DeleteFunc(slices.Clone(w.Passkeys), func(p *model.Passkey) bool { return p.ID == x.passkey })
	out.Providers = slices.DeleteFunc(slices.Clone(w.Providers), func(i *model.Identity) bool { return i.ProviderID == x.provider })
	return &out
}

// any reports whether something still signs the user in; secondFactor whether a second factor is left.
func (w *Ways) any() bool          { return w.Password || len(w.Passkeys) > 0 || len(w.Providers) > 0 }
func (w *Ways) secondFactor() bool { return w.TOTP || len(w.Passkeys) > 0 }

// MFARequired reports whether u must use a second factor: managers and above always, others where their organization
// requires it.
func (s *Service) MFARequired(ctx context.Context, u *model.User) bool {
	if u.Role.Privileged() {
		return true
	}
	org, err := s.Orgs.Get(ctx, u.OrgID)
	return err == nil && org.Settings.RequireMFA
}

// removeWay is the one way a passkey, a connected provider or the authenticator app is removed, by an administrator
// or by the user on the account page: who may (manageConnections; on someone else's established manager or
// administrator account, a super admin only: mayResetSignIn, as for removing a password), what may go (done to yourself, your last way in
// stays, and so does your last second factor where one is required; someone else may take them, and send an
// invitation), and what follows (after: ending sessions, the audit).
//
// The removal is one compare-and-swap of the user record, on the copy the owner holds, decided on the credentials
// the owners hold (UserCreds): it lists the passkeys and links taken (model.User.Removed: they stop counting at that
// write), clears the authenticator app, drops the recovery codes with the last second factor and moves the security
// generation on (what is in flight for the account ends). Two removals at once, on any nodes, however long either
// stalls, cannot both commit on the copy they decided on: the second is refused (store.ErrStale), decides again on
// the account as the first left it, and so never takes the last way in. The credentials' records are deleted in the
// same transaction (writeUser).
//
// The removal is audited (audited) as the event says (what it is called, and its detail, from the account and the
// credentials taken); also, when given, returns what the removal ends with it (the sessions a passkey signed in), as
// writes of the same transaction, and may add to the detail what it found.
func (s *Service) removeWay(ctx context.Context, a *Actor, userID string, x way,
	event func(u *model.User, gone []model.Credential) (action string, detail map[string]string),
	also func(u *model.User, gone []model.Credential, detail map[string]string) ([]store.Op, error)) error {
	for attempt := 0; ; attempt++ {
		u, err := s.getUser(ctx, userID)
		if err != nil {
			return err
		}
		if err := s.manageConnections(ctx, a, u); err != nil {
			return err
		}
		if a != nil && a.UserID != u.ID {
			if err := s.mayResetSignIn(ctx, a, u, x.field()); err != nil {
				return err
			}
		}
		c, err := s.UserCreds(ctx, u)
		if err != nil {
			return err
		}
		gone := x.of(c)
		switch {
		case x.totp && !u.HasTOTP():
			return &conflictErr{Invalid("totp", "No Authenticator App is set up.")}
		case !x.totp && len(gone) == 0:
			return ErrNotFound
		}
		w := c.Ways(u)
		left := w.without(x)
		if a != nil && a != System && a.UserID == u.ID {
			what, other := "passkey", "Set up an Authenticator App first."
			switch {
			case x.provider != "":
				what = "provider"
			case x.totp:
				what, other = "totp", "Add a passkey first."
			}
			switch {
			case !left.any():
				return &conflictErr{Invalid(what, "This is your only way to sign in. Add another way in, or ask an administrator for an invitation first.")}
			case w.secondFactor() && !left.secondFactor() && s.MFARequired(ctx, u):
				return &conflictErr{Invalid(what, "You need a second factor. "+other)}
			}
		}
		now := time.Now().UTC()
		u.Removed = s.liveRemovals(ctx, u.Removed, now)
		for _, g := range gone {
			u.Removed = append(u.Removed, model.Removal{Kind: g.Kind(), ID: g.GetMeta().ID, At: now})
		}
		if x.totp {
			u.TOTPSecret, u.MFAEnrolledAt = "", nil
		}
		if w.secondFactor() && !left.secondFactor() {
			u.RecoveryCodes, u.RecoveryCreated = nil, nil
		}
		u.BumpSecurity()
		action, detail := event(u, gone)
		if detail == nil {
			detail = map[string]string{}
		}
		var extra []store.Op
		if also != nil {
			if extra, err = also(u, gone, detail); err != nil {
				return err
			}
		}
		for _, g := range gone {
			extra = append(extra, store.Op{Rec: store.Tombstone(g.Kind(), g.GetMeta().ID)})
		}
		err = s.AuditedUser(ctx, a, u, action, detail, func() error { return s.writeUser(ctx, u, extra) })
		if (errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound)) && attempt < 7 {
			// changed meanwhile (another removal, a grant made on a session it ends, a session that expired since it
			// was listed): decided again on the newer copies
			continue
		}
		return mapStore(err)
	}
}

// liveRemovals returns rs less the entries whose record has been gone for RemovalRetention (no node can hand it
// back any more), so the list stays as short as the removals still being tidied.
func (s *Service) liveRemovals(ctx context.Context, rs []model.Removal, now time.Time) []model.Removal {
	return slices.DeleteFunc(rs, func(r model.Removal) bool {
		if now.Sub(r.At) < model.RemovalRetention {
			return false
		}
		_, err := s.Store.Get(ctx, r.Kind, r.ID)
		return errors.Is(err, store.ErrNotFound)
	})
}

// selfOr is the audit action for a change a made to u: self when a is u (the account page), other otherwise.
func selfOr(a *Actor, u *model.User, self, other string) string {
	if a != nil && a != System && a.UserID == u.ID {
		return self
	}
	return other
}

// SetTOTP gives u, as read, the authenticator app with secret, whose code at step was just checked against it: one
// compare-and-swap of that version of the user that moves its security generation on (a factor set meanwhile, from
// another browser or at a sign-in, is never overwritten unseen: store.ErrStale), then the step is recorded, so the code
// just used cannot sign in again. Both MFA enrolment at sign-in and the account page set it up this way.
func (s *Service) SetTOTP(ctx context.Context, u *model.User, secret []byte, step int64) error {
	now := time.Now().UTC()
	u.TOTPSecret, u.MFAEnrolledAt = s.Sealer.SealFor(TOTPBinding(u.ID), secret), &now
	u.BumpSecurity()
	if err := s.Users.Update(ctx, u); err != nil {
		u.SecurityGen--
		return err
	}
	return s.NoteTOTPStep(ctx, u, step)
}

// Remembered consent (model.Consent): what a user allowed an application on its consent screen, kept until they or an
// administrator remove the application's access (RevokeAppAccess). Only the consent of a confidential,
// administrator-registered application set to remember it is remembered (RemembersConsent).

// maxConsentSets bounds the sets of one consent record: the oldest go first. An application asking for ever new
// combinations of scopes and resources is asked again for an old one, nothing worse.
const maxConsentSets = 16

// RemembersConsent reports whether c's consent is remembered past signing out: when it is set to
// (Client.RememberConsent), never for a public client, whose identity is not proven (another app can send its client_id
// and redirect to it), nor a self-registered one. Not remembered, a confidential client asks once per sign-in (while a
// grant of it lives: oidc hasConsent) and a public one at every authorization.
func RemembersConsent(c *model.Client) bool {
	return c.RememberConsent && !c.Public() && !c.SelfRegistered
}

// ConsentCovers reports whether user userID has allowed client clientID everything in scopes for resources, in one
// approval. A failed read answers false: the user is asked.
func (s *Service) ConsentCovers(ctx context.Context, userID, clientID string, scopes, resources []string) bool {
	c, err := s.Consents.Get(ctx, model.ConsentID(userID, clientID))
	if err != nil {
		return false
	}
	want := model.ConsentSet{Scopes: scopes, Resources: resources}
	for _, set := range c.Allowed {
		if setCovers(set, want) {
			return true
		}
	}
	return false
}

// setCovers reports whether set holds every scope and resource of want.
func setCovers(set, want model.ConsentSet) bool {
	for _, sc := range want.Scopes {
		if !slices.Contains(set.Scopes, sc) {
			return false
		}
	}
	for _, r := range want.Resources {
		if !slices.Contains(set.Resources, r) {
			return false
		}
	}
	return true
}

// RememberConsent records that user u allowed client clientID scopes for resources: added to their consent for it
// (made if they have none), dropping the approvals it covers. Already covered, nothing is written.
func (s *Service) RememberConsent(ctx context.Context, u *model.User, clientID string, scopes, resources []string) error {
	set := model.ConsentSet{Scopes: sortedSet(scopes), Resources: sortedSet(resources)}
	id := model.ConsentID(u.ID, clientID)
	for attempt := 0; ; attempt++ {
		c, err := s.Consents.Get(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			c = &model.Consent{Meta: model.Meta{ID: id}, UserID: u.ID, OrgID: u.OrgID, ClientID: clientID,
				Allowed: []model.ConsentSet{set}}
			err = s.Consents.Create(ctx, c)
		case err != nil:
			return mapStore(err)
		default:
			if slices.ContainsFunc(c.Allowed, func(have model.ConsentSet) bool { return setCovers(have, set) }) {
				return nil
			}
			kept := slices.DeleteFunc(c.Allowed, func(have model.ConsentSet) bool { return setCovers(set, have) })
			if len(kept) >= maxConsentSets {
				kept = kept[len(kept)-maxConsentSets+1:]
			}
			c.Allowed = append(kept, set)
			err = s.Consents.Update(ctx, c)
		}
		if !errors.Is(err, store.ErrStale) || attempt == 4 {
			return mapStore(err)
		}
	}
}

// forgetConsents removes every user's remembered consent for client clientID (a record id): the client stopped
// remembering consent. Every removal is tried; the failures are returned together.
func (s *Service) forgetConsents(ctx context.Context, clientID string) error {
	cs, _, err := s.Consents.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "client_id", Value: clientID}}})
	if err != nil {
		return mapStore(err)
	}
	var errs []error
	for _, c := range cs {
		if err := s.Consents.Delete(ctx, c.ID); err != nil && !errors.Is(err, store.ErrStale) {
			errs = append(errs, mapStore(err))
		}
	}
	return errors.Join(errs...)
}

// sortedSet is v sorted with duplicates dropped (nil for none).
func sortedSet(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	out := slices.Clone(v)
	slices.Sort(out)
	return slices.Compact(out)
}
