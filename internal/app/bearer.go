package app

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// bearer resolves management-API bearer tokens: personal API tokens (the user's role still limits each call).
// OAuth access tokens are not accepted by the management API; SCIM takes provisioning clients' (scimVerifier).
func bearer(svc *service.Service) web.BearerFunc {
	return func(ctx context.Context, r *http.Request, tok string) (*service.Actor, error) {
		if !service.IsAPIToken(tok) {
			return nil, service.ErrBadToken
		}
		t, u, err := svc.ValidateAPIToken(ctx, tok)
		if err != nil {
			return nil, err
		}
		return service.ActorForToken(t, u, web.ClientIP(r)), nil
	}
}

// scimVerifier accepts OAuth client_credentials access tokens carrying the scim scope from an enabled client with
// SCIM provisioning turned on; the client acts as an admin of its own organization (never granting admin roles).
func scimVerifier(a *App) func(r *http.Request, scheme, tok string) (*service.Actor, error) {
	return func(r *http.Request, scheme, tok string) (*service.Actor, error) {
		ctx := r.Context()
		cl, err := a.OIDC.VerifyRequestToken(r, scheme, tok)
		if err != nil {
			return nil, err
		}
		if cl.ClientID == "" || cl.Sub != cl.ClientID || !slices.Contains(strings.Fields(cl.Scope), service.ScopeSCIM) {
			return nil, service.ErrBadToken // user tokens and tokens without the scim scope are not provisioning tokens
		}
		c, err := a.Svc.Clients.Get(ctx, cl.ClientID)
		if err != nil || !c.Enabled || !c.SCIM {
			return nil, service.ErrBadToken
		}
		return service.ActorForClient(c, ""), nil
	}
}
