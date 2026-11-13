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

// Self-registered applications (service/selfreg.go): dynamic client registration (RFC 7591) at /o/<org>/oauth/register,
// and clients whose client_id is the https URL of their Client ID Metadata Document, read on first use. Each belongs to
// the organization it registered or was authorized in; forResources places one in the tenant of that organization that
// owns the resources a request names.

// Registration is unauthenticated, so it is limited per address and minute, per address and organization a day (an
// unused registration is kept a day: one address alone cannot fill the organization's cap of unused ones,
// service.MaxSelfRegistered), and per organization and minute from every address together (how fast anyone can fill
// that cap, and how often registrations write to the store).
const (
	registerPerIPMin  = 10
	registerPerIPDay  = 100
	registerPerOrgMin = 60
)

// forResources returns the client as the request sees it: itself for an administrator's client; for a
// self-registered one, a copy in the tenant of its organization that owns resources (service.InTenant), with that
// tenant. An error means the resources accept no self-registered application (none named, not one tenant's of the
// organization, or the tenant does not allow them).
func (p *Provider) forResources(ctx context.Context, c *model.Client, resources []string) (*model.Client, *model.Tenant, error) {
	if !c.SelfRegistered {
		return c, nil, nil
	}
	t, err := p.svc.TenantForResources(ctx, c.OrgID, resources)
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

// appClient is the client of a sign-in (authorize, resume, consent) in organization orgID. A client_id that is a
// metadata document URL is the stored application when the organization has authorized it before (its document read
// again once MetadataRefresh old), else the application the document describes, read now or earlier in this sign-in,
// not stored.
func (p *Provider) appClient(ctx context.Context, r *http.Request, orgID, id string) (*clientEntry, error) {
	if !metadataURL(id) {
		return p.client(ctx, orgID, id)
	}
	if ce, err := p.client(ctx, orgID, id); err == nil {
		if !ce.c.SelfRegistered || time.Since(ce.c.MetadataFetched) < service.MetadataRefresh {
			return ce, nil
		}
		fresh, rerr := p.readMetadata(ctx, r, orgID, id, false)
		if fresh != nil { // kept even if the request hangs up now: the URL's one read a minute was spent on it
			if c, err := p.svc.RefreshMetadataClient(context.WithoutCancel(ctx), fresh); err == nil {
				p.clients.Del(c.ID)
				return &clientEntry{c: c}, nil
			}
		}
		if time.Since(ce.c.MetadataFetched) < service.MetadataStale {
			return ce, nil // the document cannot be read now: the copy kept is good for a while
		}
		if rerr != nil {
			return nil, rerr
		}
		return nil, store.ErrNotFound
	}
	if doc, err := p.s.Eph.Get(ctx, nsCIMD, id); err == nil {
		if c, err := service.ParseMetadata(orgID, id, doc); err == nil {
			return &clientEntry{c: c}, nil
		}
	}
	c, err := p.readMetadata(ctx, r, orgID, id, true)
	if c != nil {
		return &clientEntry{c: c}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, store.ErrNotFound
}

// readMetadata reads and checks the document at id for organization orgID (at most once a minute per URL, and for an
// application not stored yet, metadataPerIPMin per address): nil when it cannot be read or is not a valid document.
// The error is set only when a counter could not be used: nothing was fetched (a limit never fails open), but the
// document was not judged either, so the caller reports "unavailable", not "unknown application".
func (p *Provider) readMetadata(ctx context.Context, r *http.Request, orgID, id string, unstored bool) (*model.Client, error) {
	// The caller's own budget first: one over it must not spend the document's one read a minute, which every other
	// caller then goes without (an application nobody could sign in to while someone kept asking for it).
	if unstored && r != nil {
		n, err := p.s.Eph.Incr(ctx, nsRateOIDC, "cimd-ip|"+web.RateKeyIP(r), 1, time.Minute)
		if err != nil {
			return nil, unavailable(err)
		}
		if n > metadataPerIPMin {
			return nil, nil
		}
	}
	n, err := p.s.Eph.Incr(ctx, nsRateOIDC, "cimd|"+id, 1, time.Minute)
	if err != nil {
		return nil, unavailable(err)
	}
	if n > 1 {
		return nil, nil
	}
	// The read is this minute's for every caller, not this request's: it runs to the end (or the fetch timeout) and
	// keeps what it read even when the request that spent the slot hangs up meanwhile.
	ctx = context.WithoutCancel(ctx)
	doc, err := p.fetch(ctx, id, service.MaxMetadataBytes)
	if err != nil {
		p.log.Warn("oidc: reading a client metadata document", "client_id", id, "error", err)
		return nil, nil
	}
	c, err := service.ParseMetadata(orgID, id, doc)
	if err != nil {
		p.log.Warn("oidc: client metadata document refused", "client_id", id, "error", err)
		return nil, nil
	}
	if unstored {
		_ = p.s.Eph.Set(ctx, nsCIMD, id, doc, flowTTL)
	}
	return c, nil
}

// handleRegister is dynamic client registration (RFC 7591): public clients with PKCE for user sign-in only, at an
// organization with a tenant that accepts them, limited per address and organization and capped in total; see
// service.RegisterClient.
func (p *Provider) handleRegister(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	n, err := p.s.Eph.Incr(r.Context(), nsRateOIDC, "register|"+web.RateKeyIP(r), 1, time.Minute)
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	if n > registerPerIPMin {
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down", desc: "too many registrations from this address"})
		return
	}
	var in service.RegistrationInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
		writeOAuthError(w, oerr("invalid_client_metadata", "the request body must be a JSON object"))
		return
	}
	orgID := web.Org(r).ID
	// The address's daily allowance first, counted as the minute's is, on every request: an address past its own does
	// not reach what every other address shares. The organization's minute is only read here, and counted below for a
	// registration made: one refused (no tenant accepts them, metadata refused, the cap reached) writes nothing, and
	// must not spend what every address shares, or a few addresses sending bad requests would block everyone's.
	n, err = p.s.Eph.Incr(r.Context(), nsRateOIDC, "register-day|"+orgID+"|"+web.RateKeyIP(r), 1, 24*time.Hour)
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	if n > registerPerIPDay {
		w.Header().Set("Retry-After", "3600")
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down", desc: "too many registrations from this address"})
		return
	}
	orgKey := "register-org|" + orgID
	n, err = p.s.Eph.Incr(r.Context(), nsRateOIDC, orgKey, 0, time.Minute)
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	if n >= registerPerOrgMin {
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "slow_down", desc: "too many registrations at this organization"})
		return
	}
	in.ClientID = ""
	c, err := p.svc.RegisterClient(r.Context(), orgID, in)
	var re *service.RegistrationError
	switch {
	case errors.As(err, &re):
		writeOAuthError(w, oerr(re.Code, re.Description))
		return
	case errors.Is(err, service.ErrForbidden):
		writeOAuthError(w, &oauthError{status: http.StatusForbidden, code: "access_denied",
			desc: "this organization does not accept self-registered applications"})
		return
	case err != nil:
		writeOAuthError(w, serverError(err))
		return
	}
	// Registrations at the same moment can each pass the read above, so the organization's minute can be overrun by as
	// many as arrive together; it bounds the rate, not each request. The application is made: a counter that cannot be
	// written now does not undo it.
	_, _ = p.s.Eph.Incr(r.Context(), nsRateOIDC, orgKey, 1, time.Minute)
	web.WriteJSON(w, http.StatusCreated, map[string]any{
		"client_id": c.ID, "client_id_issued_at": c.Created.Unix(), "client_name": c.Name,
		"redirect_uris": c.RedirectURIs, "grant_types": c.GrantTypes, "response_types": []string{"code"},
		"token_endpoint_auth_method": model.AuthMethodNone, "scope": strings.Join(c.Scopes, " "),
	})
}
