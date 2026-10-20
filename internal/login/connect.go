package login

import (
	"errors"
	"net/http"
	"slices"

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

// listProviders handles GET /api-internal/account/providers: the organization's enabled providers and which are connected.
func (m *Module) listProviders(w http.ResponseWriter, r *http.Request, a acct) {
	ctx := r.Context()
	ps, err := m.s.Svc.EnabledProviders(ctx, a.u.OrgID)
	if err != nil {
		m.internalError(w, r, "list providers", err)
		return
	}
	ids, _ := m.s.Svc.Identities.All(ctx, a.u.ID)
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

// connectProvider handles POST /api-internal/account/providers/{id}/connect: answers {url}, the provider's address to send
// the browser to; the callback attaches the identity (connectFinish).
func (m *Module) connectProvider(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.needReauth(w, r, a) {
		return
	}
	ctx := r.Context()
	org, err := m.s.Svc.Orgs.Get(ctx, a.u.OrgID)
	if err != nil {
		m.internalError(w, r, "org", err)
		return
	}
	p, err := m.s.Svc.Providers.Get(ctx, r.PathValue("id"))
	if err != nil || p.OrgID != org.ID || !p.Enabled {
		writeErr(w, http.StatusNotFound, "Not found.", "")
		return
	}
	authURL, state, err := m.Upstream.BeginConnect(ctx, org, p, a.u, "/account#providers")
	if err != nil {
		m.s.Log.Warn("upstream connect", "provider", p.Name, "error", err)
		writeErr(w, http.StatusBadGateway, "The provider could not be reached. Try again later.", "")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(upstream.StateTTL.Seconds())})
	web.WriteJSON(w, http.StatusOK, map[string]string{"url": authURL})
}

// connectFinish completes a connection on the provider's callback: the browser must still be signed in as the user
// who started it; an identity already linked to someone else is refused.
func (m *Module) connectFinish(w http.ResponseWriter, r *http.Request, res *upstream.Result) {
	ctx := r.Context()
	back := func(result string) {
		http.Redirect(w, r, "/account?provider="+result+"#providers", http.StatusSeeOther)
	}
	_, u := m.s.Sessions.Current(r)
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
	key := model.IdentityKey(res.Provider.ID, res.Claims.Subject)
	if id, err := m.s.Svc.Identities.GetByUnique(ctx, key); err == nil && id.Authority == model.ProviderAuthority(res.Provider) {
		if id.UserID == u.ID {
			back("connected")
		} else {
			m.audit(r, "account.provider.connect_refused", res.Org, u, u.Username, map[string]string{"provider": res.Provider.Name,
				"reason": "linked to another account"})
			back("taken")
		}
		return
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		m.internalError(w, r, "identity", err)
		return
	} else if err == nil {
		_ = m.s.Svc.Identities.Delete(service.Durable(ctx), id.ID) // a stale link from before the provider changed
	}
	// one identity per provider and user: a new one replaces the old
	if ids, err := m.s.Svc.Identities.All(ctx, u.ID); err == nil {
		for _, id := range ids {
			if id.ProviderID == res.Provider.ID {
				_ = m.s.Svc.Identities.Delete(service.Durable(ctx), id.ID)
			}
		}
	}
	id := model.NewIdentity(u, res.Provider, res.Claims.Subject, res.Claims.Email, "connect")
	if err := m.s.Svc.Identities.Create(service.Durable(ctx), id); err != nil {
		if errors.Is(err, store.ErrConflict) {
			back("taken")
			return
		}
		m.internalError(w, r, "identity", err)
		return
	}
	m.audit(r, "account.provider.connect", res.Org, u, u.Username, map[string]string{"provider": res.Provider.Name})
	back("connected")
}

// disconnectProvider handles DELETE /api-internal/account/providers/{id}; it refuses to remove the last way to sign in.
func (m *Module) disconnectProvider(w http.ResponseWriter, r *http.Request, a acct) {
	if !m.needReauth(w, r, a) {
		return
	}
	ctx := r.Context()
	pid := r.PathValue("id")
	ids, err := m.s.Svc.Identities.All(ctx, a.u.ID)
	if err != nil {
		m.internalError(w, r, "identities", err)
		return
	}
	mine := slices.DeleteFunc(slices.Clone(ids), func(id *model.Identity) bool { return id.ProviderID != pid })
	if len(mine) == 0 {
		writeErr(w, http.StatusNotFound, "Not found.", "")
		return
	}
	u, err := m.fresh(ctx, a)
	if err != nil {
		web.WriteError(w, err)
		return
	}
	pk, _ := m.s.Svc.UsablePasskeys(ctx, u.ID, "")
	if u.PasswordHash == "" && pk == 0 && len(ids) == len(mine) {
		writeErr(w, http.StatusConflict, "This is your only way to sign in. Add a passkey or ask an administrator for an invitation first.", "")
		return
	}
	for _, id := range mine {
		if err := m.s.Svc.Identities.Delete(service.Durable(ctx), id.ID); err != nil {
			web.WriteError(w, err)
			return
		}
	}
	name := pid
	if p, err := m.s.Svc.Providers.Get(ctx, pid); err == nil {
		name = p.Name
	}
	m.auditSelf(r, a, "account.provider.disconnect", map[string]string{"provider": name})
	w.WriteHeader(http.StatusNoContent)
}
