package login

import (
	"errors"
	"net/http"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/upstream"
	"github.com/paularlott/quisora/internal/web"
)

// Connecting sign-in providers to one's own account (account page, "Sign-in providers"). This is how a manager or
// administrator links a provider (they are never linked by email), and how anyone links one deliberately. Both
// directions need a recent re-authentication.

type providerItem struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Connected bool   `json:"connected"`
	Email     string `json:"email,omitempty"` // the address the provider gave when it was connected
}

// listProviders handles GET /o/{org}/api-internal/account/providers: the organization's enabled providers and which are connected.
func (m *Module) listProviders(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	ps, err := m.s.Svc.EnabledProviders(ctx, a.u.OrgID)
	if err != nil {
		m.internalError(w, r, "list providers", err)
		return
	}
	ids, _ := m.s.Svc.CurrentIdentities(ctx, a.u)
	out := make([]providerItem, 0, len(ps))
	for _, p := range ps {
		it := providerItem{ID: p.ID, Name: p.Name, Type: p.Type}
		for _, id := range ids {
			if id.ProviderID == p.ID {
				it.Connected, it.Email = true, id.Email
			}
		}
		out = append(out, it)
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// connectProvider handles POST /o/{org}/api-internal/account/providers/{id}/connect: answers {url}, the provider's address to send
// the browser to; the callback attaches the identity (connectFinish).
func (m *Module) connectProvider(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.needReauth(w, r, a) {
		return
	}
	ctx := r.Context()
	org := web.Org(r)
	p, err := m.s.Svc.Providers.Get(ctx, r.PathValue("id"))
	if err != nil || p.OrgID != org.ID || !p.Enabled {
		writeErr(w, http.StatusNotFound, "Not found.", "")
		return
	}
	authURL, state, err := m.Upstream.BeginConnect(ctx, org, p, a.u, web.OrgPath(org.ID, "/account#providers"))
	if err != nil {
		m.s.Log.Warn("upstream connect", "provider", p.Name, "error", err)
		writeErr(w, http.StatusBadGateway, "The provider could not be reached. Try again later.", "")
		return
	}
	setStateCookie(w, state)
	web.WriteJSON(w, http.StatusOK, map[string]string{"url": authURL})
}

// connectFinish completes a connection on the provider's callback: the browser must still be signed in as the user
// who started it; an identity already linked to someone else is refused.
func (m *Module) connectFinish(w http.ResponseWriter, r *http.Request, res *upstream.Result) {
	ctx := r.Context()
	back := func(result string) {
		http.Redirect(w, r, web.OrgPath(res.Org.ID, "/account?provider="+result+"#providers"), http.StatusSeeOther)
	}
	sess, u := m.s.Sessions.Current(r)
	if u == nil || u.ID != res.Connect || u.OrgID != res.Org.ID {
		back("failed")
		return
	}
	if !upstream.DomainAllowed(res.Provider, res.Claims) {
		m.audit(r, "account.provider.connect_refused", res.Org, u, u.Username, map[string]string{"provider": res.Provider.Name,
			"reason": "email domain not allowed"})
		back("domain")
		return
	}
	if ok, err := m.Upstream.GroupAllowed(ctx, res.Provider, res.Claims); err != nil || !ok {
		reason, result := "not in an allowed group", "group"
		if err != nil {
			m.s.Log.Error("provider groups", "error", err)
			reason, result = "groups could not be read", "failed"
		}
		m.audit(r, "account.provider.connect_refused", res.Org, u, u.Username, map[string]string{"provider": res.Provider.Name,
			"reason": reason})
		back(result)
		return
	}
	key := model.IdentityKey(res.Provider.ID, res.Claims.Subject)
	if id, err := m.s.Svc.Identities.GetByUnique(ctx, key); err == nil && id.Authority == model.ProviderAuthority(res.Provider) {
		switch {
		case id.UserID == u.ID && u.Counts(id):
			m.Upstream.KeepConnected(ctx, res) // connected again: the provider's newer token
			back("connected")
			return
		case id.UserID == u.ID:
			// this account's link of an epoch it has moved past (its sign-in was reset): replaced below
		default:
			// Another account's: refused, unless it counts for nothing (its account or organization was deleted),
			// when it goes and this one is made.
			if freed, err := m.s.Svc.ReleaseUnique(ctx, model.KindIdentity, key); err != nil || !freed {
				m.audit(r, "account.provider.connect_refused", res.Org, u, u.Username, map[string]string{"provider": res.Provider.Name,
					"reason": "linked to another account"})
				back("taken")
				return
			}
		}
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		m.internalError(w, r, "identity", err)
		return
	} else if err == nil {
		_ = m.s.Svc.Identities.Delete(ctx, id.ID) // a stale link from before the provider changed
	}
	// one identity per provider and user: a new one replaces the old
	if ids, err := m.s.Svc.Identities.All(ctx, u.ID); err == nil {
		for _, id := range ids {
			if id.ProviderID == res.Provider.ID {
				_ = m.s.Svc.Identities.Delete(ctx, id.ID)
			}
		}
	}
	id := model.NewIdentity(u, res.Provider, res.Claims.Subject, res.Claims.Email, "connect")
	if err := m.s.Svc.Identities.Create(ctx, id); err != nil {
		if errors.Is(err, store.ErrConflict) {
			back("taken")
			return
		}
		m.internalError(w, r, "identity", err)
		return
	}
	m.Upstream.KeepConnected(ctx, res)
	// A connected provider is a new way in: the account's security generation moves on (ending what was in flight
	// for it), and the re-authentication this session gave to connect it carries over to the new generation.
	if fresh, err := m.s.Svc.AdvanceSecurity(ctx, u.ID); err == nil {
		m.refreshReauth(ctx, sess.ID, fresh.SecurityGen)
	}
	m.changed(acct{u: u})
	m.audit(r, "account.provider.connect", res.Org, u, u.Username, map[string]string{"provider": res.Provider.Name})
	back("connected")
}

// disconnectProvider handles DELETE /o/{org}/api-internal/account/providers/{id}, as the service disconnects any
// (service.DisconnectProvider): it refuses to remove the last way to sign in.
func (m *Module) disconnectProvider(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.needReauth(w, r, a) {
		return
	}
	ctx := r.Context()
	n, err := m.s.Svc.DisconnectProvider(service.SelfService(ctx), a.actor, a.u.ID, r.PathValue("id"))
	if err != nil {
		web.WriteError(w, err)
		return
	}
	if n == 0 {
		writeErr(w, http.StatusNotFound, "Not found.", "")
		return
	}
	m.afterCredentialChange(ctx, a)
	w.WriteHeader(http.StatusNoContent)
}
