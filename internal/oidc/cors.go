package oidc

import (
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
// of one organization has no say over another's endpoints. A store that cannot be read allows nobody, and the set
// is not kept: the next request reads again.
func (p *Provider) publicOrigins(r *http.Request) *originSet {
	orgID := web.Org(r).ID
	if s, ok := p.origins.get(orgID); ok {
		return s
	}
	tok := p.origins.token(orgID)
	set := &originSet{exact: map[string]bool{}, loopback: map[string]bool{}}
	cs, _, err := p.svc.Clients.List(r.Context(), store.ListQuery{Scope: orgID,
		Filters: []store.Filter{{Field: "auth_method", Value: model.AuthMethodNone}}})
	if err != nil {
		return set
	}
	for _, c := range cs {
		if c.Enabled {
			originsOf(c, set)
		}
	}
	p.origins.putIf(orgID, set, tok)
	return set
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
		set := &originSet{exact: map[string]bool{}, loopback: map[string]bool{}}
		originsOf(ce.c, set)
		if set.allows(o) {
			return
		}
	}
	h := w.Header()
	h.Del("Access-Control-Allow-Origin")
	h.Del("Access-Control-Expose-Headers")
}
