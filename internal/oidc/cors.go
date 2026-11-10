package oidc

import (
	"context"
	"net/http"
	"net/url"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// CORS for browser-based public clients: the token, revocation and userinfo endpoints answer for the
// origins of a public client's https and loopback redirect URIs, and for nobody else. No credentials are allowed.

type originSet struct {
	exact    map[string]bool // https://app.example.com
	loopback map[string]bool // http://127.0.0.1 (any port)
}

// originsOf lists the CORS origins a client's redirect URIs imply.
func originsOf(c *model.Client, set *originSet) {
	for _, ru := range c.RedirectURIs {
		u, err := url.Parse(ru)
		if err != nil || u.Host == "" {
			continue
		}
		switch {
		case u.Scheme == "https":
			set.exact["https://"+u.Host] = true
		case u.Scheme == "http" && isLoopbackHost(u.Hostname()):
			set.loopback["http://"+u.Hostname()] = true
		}
	}
}

func (s *originSet) allows(origin string) bool {
	if s.exact[origin] {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "http" && isLoopbackHost(u.Hostname()) && s.loopback["http://"+u.Hostname()]
}

// publicOrigins returns the (cached) origins of the enabled public clients of the request's organization: a client
// of one organization has no say over another's endpoints. A self-registered application nobody has let sign in yet
// is left out: it has no browser origin to allow yet, and anyone may register one (the read skips them in the store's
// index, so registrations do not make it longer). A store that cannot be read allows nobody, and the set is not
// kept: the next request reads again.
//
// The preflight is unauthenticated, so a miss reads at most once per organization at a time: requests that miss
// while a read begun since the last change is under way wait for its answer. The read is not the requester's own (it
// goes on if that one hangs up), and a request that hangs up while waiting is answered as allowing nobody.
func (p *Provider) publicOrigins(r *http.Request) *originSet {
	orgID := web.Org(r).ID
	if s, ok := p.origins.Get(orgID); ok {
		return s
	}
	p.originsMu.Lock()
	tok := p.origins.Token(orgID)
	if l := p.originsLoads[orgID]; l != nil && l.tok == tok {
		p.originsMu.Unlock()
		select {
		case <-l.done:
			return l.set
		case <-r.Context().Done():
			return newOriginSet()
		}
	}
	l := &originsLoad{tok: tok, done: make(chan struct{})}
	p.originsLoads[orgID] = l
	p.originsMu.Unlock()
	defer func() {
		p.originsMu.Lock()
		if p.originsLoads[orgID] == l { // a later read (after a change) may have taken the slot
			delete(p.originsLoads, orgID)
		}
		p.originsMu.Unlock()
		close(l.done)
	}()
	l.set = newOriginSet()
	cs, _, err := p.svc.Clients.List(context.WithoutCancel(r.Context()), store.ListQuery{Scope: orgID,
		Filters: []store.Filter{{Field: "auth_method", Value: model.AuthMethodNone}, {Field: "unused_self_registered", Value: false}}})
	if err != nil {
		return l.set
	}
	for _, c := range cs {
		if c.Enabled {
			originsOf(c, l.set)
		}
	}
	p.origins.PutIf(orgID, l.set, tok)
	return l.set
}

// originsLoad is a read of an organization's origins under way (publicOrigins).
type originsLoad struct {
	tok  uint64        // the origins cache's token for the organization when it began
	done chan struct{} // closed once set is complete
	set  *originSet
}

func newOriginSet() *originSet {
	return &originSet{exact: map[string]bool{}, loopback: map[string]bool{}}
}

func setAllowOrigin(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	varyOrigin(w)
}

// varyOrigin adds "Vary: Origin" once.
func varyOrigin(w http.ResponseWriter) {
	for _, v := range w.Header().Values("Vary") {
		if v == "Origin" {
			return
		}
	}
	w.Header().Add("Vary", "Origin")
}

func (p *Provider) handleCORSPreflight(w http.ResponseWriter, r *http.Request) {
	varyOrigin(w)
	if o := r.Header.Get("Origin"); o != "" && p.publicOrigins(r).allows(o) {
		setAllowOrigin(w, o)
		h := w.Header()
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP")
		h.Set("Access-Control-Max-Age", "600")
	}
	w.WriteHeader(http.StatusNoContent)
}

// corsActual provisionally allows a request from any public client's origin; corsRestrict narrows it to the
// authenticated client's own origins once that client is known.
func (p *Provider) corsActual(w http.ResponseWriter, r *http.Request) {
	o := r.Header.Get("Origin")
	if o == "" {
		return
	}
	varyOrigin(w)
	if p.publicOrigins(r).allows(o) {
		setAllowOrigin(w, o)
		w.Header().Add("Access-Control-Expose-Headers", "WWW-Authenticate, DPoP-Nonce")
	}
}

func (p *Provider) corsRestrict(w http.ResponseWriter, r *http.Request, clientID string) {
	o := r.Header.Get("Origin")
	if o == "" || w.Header().Get("Access-Control-Allow-Origin") == "" {
		return
	}
	ce, err := p.client(r.Context(), web.Org(r).ID, clientID)
	if err == nil && ce.c.Public() {
		set := newOriginSet()
		originsOf(ce.c, set)
		if set.allows(o) {
			return
		}
	}
	h := w.Header()
	h.Del("Access-Control-Allow-Origin")
	h.Del("Access-Control-Expose-Headers")
}
