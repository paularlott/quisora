package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/paularlott/quisora/internal/mcpapi"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// bearer resolves management-API bearer tokens: personal API tokens (the user's role still limits each call) and
// service accounts' access tokens (serviceAccount). Other OAuth access tokens are not accepted.
func bearer(a *App) web.BearerFunc {
	return func(ctx context.Context, r *http.Request, tok string) (*service.Actor, error) {
		if !service.IsAPIToken(tok) {
			return serviceAccount(a, r, "Bearer", tok)
		}
		t, u, err := a.Svc.ValidateAPIToken(ctx, tok)
		if err != nil {
			return nil, err
		}
		return service.ActorForToken(t, u, web.ClientIP(r)), nil
	}
}

// serviceAccount resolves an OAuth client_credentials access token of an enabled service account to its actor (the
// management API and SCIM; each checks the scope it needs). The account is read for every request, so one disabled,
// deleted or given fewer scopes is refused at once, not when its token expires.
func serviceAccount(a *App, r *http.Request, scheme, tok string) (*service.Actor, error) {
	cl, err := a.OIDC.VerifyRequestToken(r, scheme, tok)
	if err != nil {
		return nil, err
	}
	if cl.ClientID == "" || cl.Sub != cl.ClientID {
		return nil, service.ErrBadToken // a user's token: applications act for their users, never as Quisora's administrators
	}
	c, err := a.Svc.Clients.Get(r.Context(), cl.ClientID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		// The read failed, not the token: answered 503 (as for a personal API token), not 401, so the caller retries
		// instead of treating its token as revoked.
		return nil, fmt.Errorf("%w: the service account could not be read: %v", service.ErrUnavailable, err)
	}
	if err != nil || !c.Enabled || !c.ServiceAccount {
		return nil, service.ErrBadToken
	}
	return service.ActorForServiceAccount(c, strings.Fields(cl.Scope), web.ClientIP(r)), nil
}

// scimVerifier accepts service accounts' access tokens for SCIM (which then requires the scim scope).
func scimVerifier(a *App) func(r *http.Request, scheme, tok string) (*service.Actor, error) {
	return func(r *http.Request, scheme, tok string) (*service.Actor, error) {
		return serviceAccount(a, r, scheme, tok)
	}
}

// mcpVerifier accepts, for Quisora's own MCP server, a user's access token issued for its address: the tools run as
// that user, acting through the application the token was issued to.
func mcpVerifier(a *App) mcpapi.Verifier {
	return func(r *http.Request, tok, resource string) (*service.Actor, bool, error) {
		cl, u, err := a.OIDC.VerifyResourceToken(r, "Bearer", tok, resource)
		if err != nil {
			return nil, false, err
		}
		return service.ActorForApp(u, cl.ClientID, web.ClientIP(r)), model.MFA(cl.AMR), nil
	}
}
