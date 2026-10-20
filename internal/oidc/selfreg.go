package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// Self-registered applications (service/selfreg.go): dynamic client registration (RFC 7591) at /oauth/register,
// and clients whose client_id is the https URL of their Client ID Metadata Document, read on first use. Neither
// belongs to an organization; forResources places one in the tenant that owns the resources a request names.

// registerPerIPMin bounds registrations per address and minute (registration is unauthenticated).
const registerPerIPMin = 10

// forResources returns the client as the request sees it: itself for an administrator's client; for a
// self-registered one, a copy in the tenant that owns resources (service.InTenant), with that tenant. An error
// means the resources accept no self-registered application (none named, not one tenant's, or the tenant does not
// allow them).
func (p *Provider) forResources(ctx context.Context, c *model.Client, resources []string) (*model.Client, *model.Tenant, error) {
	if !c.SelfRegistered {
		return c, nil, nil
	}
	t, err := p.svc.TenantForResources(ctx, resources)
	if err != nil {
		return nil, nil, err
	}
	return service.InTenant(c, t), t, nil
}

// metadataURL reports whether id is a Client ID Metadata Document URL: https, with a path, no fragment, query or
// credentials, and short enough to be a client id everywhere.
func metadataURL(id string) bool {
	if !strings.HasPrefix(id, "https://") || len(id) > service.MaxMetadataURL {
		return false
	}
	u, err := url.Parse(id)
	return err == nil && u.Host != "" && u.User == nil && u.Fragment == "" && u.RawQuery == "" && u.Path != "" && u.Path != "/"
}

// nsCIMD holds a metadata document read for a sign-in in progress (keyed by its URL) until the application is
// stored, at its first authorization: requests naming made-up documents cost a short-lived entry, never a stored
// client.
const nsCIMD = "oauth.cimd"

// metadataPerIPMin bounds the metadata documents read per address and minute for applications not stored yet.
const metadataPerIPMin = 20

// appClient is the client of a sign-in (authorize, resume, consent). A client_id that is a metadata document URL is
// the stored application when one has been authorized before (its document read again once MetadataRefresh old),
// else the application the document describes, read now or earlier in this sign-in, not stored.
func (p *Provider) appClient(ctx context.Context, r *http.Request, id string) (*clientEntry, error) {
	if !metadataURL(id) {
		return p.client(ctx, id)
	}
	if ce, err := p.client(ctx, id); err == nil {
		if !ce.c.SelfRegistered || time.Since(ce.c.MetadataFetched) < service.MetadataRefresh {
			return ce, nil
		}
		if fresh := p.readMetadata(ctx, r, id, false); fresh != nil {
			if c, err := p.svc.RefreshMetadataClient(ctx, fresh); err == nil {
				p.clients.del(id)
				return &clientEntry{c: c}, nil
			}
		}
		if time.Since(ce.c.MetadataFetched) < service.MetadataStale {
			return ce, nil // the document cannot be read now: the copy kept is good for a while
		}
		return nil, store.ErrNotFound
	}
	if doc, err := p.s.Eph.Get(ctx, nsCIMD, id); err == nil {
		if c, err := service.ParseMetadata(id, doc); err == nil {
			return &clientEntry{c: c}, nil
		}
	}
	if c := p.readMetadata(ctx, r, id, true); c != nil {
		return &clientEntry{c: c}, nil
	}
	return nil, store.ErrNotFound
}

// readMetadata reads and checks the document at id (at most once a minute per URL, and for an application not
// stored yet, metadataPerIPMin per address): nil when it cannot be read or is not a valid document.
func (p *Provider) readMetadata(ctx context.Context, r *http.Request, id string, unstored bool) *model.Client {
	if n, err := p.s.Eph.Incr(ctx, nsRateOIDC, "cimd|"+id, 1, time.Minute); err != nil || n > 1 {
		return nil
	}
	if unstored && r != nil {
		if n, err := p.s.Eph.Incr(ctx, nsRateOIDC, "cimd-ip|"+web.ClientIP(r), 1, time.Minute); err != nil || n > metadataPerIPMin {
			return nil
		}
	}
	doc, err := p.fetch(ctx, id, service.MaxMetadataBytes)
	if err != nil {
		p.log.Warn("oidc: reading a client metadata document", "client_id", id, "error", err)
		return nil
	}
	c, err := service.ParseMetadata(id, doc)
	if err != nil {
		p.log.Warn("oidc: client metadata document refused", "client_id", id, "error", err)
		return nil
	}
	if unstored {
		_ = p.s.Eph.Set(ctx, nsCIMD, id, doc, flowTTL)
	}
	return c
}

// handleRegister is dynamic client registration (RFC 7591): public clients with PKCE for user sign-in only, limited
// per address and capped in total; see service.RegisterClient.
func (p *Provider) handleRegister(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	if n, err := p.s.Eph.Incr(r.Context(), nsRateOIDC, "register|"+web.ClientIP(r), 1, time.Minute); err != nil || n > registerPerIPMin {
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down", desc: "too many registrations from this address"})
		return
	}
	var in service.RegistrationInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
		writeOAuthError(w, oerr("invalid_client_metadata", "the request body must be a JSON object"))
		return
	}
	in.ClientID = ""
	c, err := p.svc.RegisterClient(r.Context(), in)
	var re *service.RegistrationError
	switch {
	case errors.As(err, &re):
		writeOAuthError(w, oerr(re.Code, re.Description))
		return
	case errors.Is(err, service.ErrLimit):
		w.Header().Set("Retry-After", "3600")
		writeOAuthError(w, &oauthError{status: http.StatusServiceUnavailable, code: "temporarily_unavailable", desc: "registration is not possible now"})
		return
	case err != nil:
		writeOAuthError(w, serverError(err))
		return
	}
	web.WriteJSON(w, http.StatusCreated, map[string]any{
		"client_id": c.ID, "client_id_issued_at": c.Created.Unix(), "client_name": c.Name,
		"redirect_uris": c.RedirectURIs, "grant_types": c.GrantTypes, "response_types": []string{"code"},
		"token_endpoint_auth_method": model.AuthMethodNone, "scope": strings.Join(c.Scopes, " "),
	})
}
