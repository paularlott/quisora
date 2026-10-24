package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Leaver detection. A session signed in through an upstream provider would otherwise live on after the person left
// the organization behind that provider: Quisora only hears from the provider at sign-in. So the refresh token the
// provider gives at sign-in (OpenID Connect providers that issue one, usually when the provider's scopes include
// offline_access) is kept, sealed, on the identity, and replayed on a schedule while the user has a session signed
// in through that provider. A provider that refuses it with invalid_grant no longer accepts the account: the user's
// sessions and refresh grants end here (applications are told by back-channel logout). Anything else (the
// provider unreachable, a server error, a misconfigured client) is tolerated and tried again next time. A provider
// that rotates refresh tokens returns a new one with each use; it replaces the stored one.

// refreshBinding is the sealing binding of an identity's refresh token.
func refreshBinding(identityID string) string { return service.IdentityRefreshBinding(identityID) }

// keepRefresh stores the provider's refresh token on the identity just used to sign in (best effort: without it the
// sessions are simply not checked).
func (s *Service) keepRefresh(ctx context.Context, p *model.Provider, subject, refresh string) {
	for range 4 {
		id, err := s.Svc.Identities.GetByUnique(ctx, model.IdentityKey(p.ID, subject))
		if err != nil {
			return
		}
		id.Refresh = s.Svc.Sealer.SealFor(refreshBinding(id.ID), []byte(refresh))
		id.RefreshChecked = s.Now().UTC()
		if err := s.Svc.Identities.Update(ctx, id); !errors.Is(err, store.ErrStale) {
			return
		}
	}
}

// LeaverResult counts what one CheckSessions run did.
type LeaverResult struct {
	Checked int // refresh tokens replayed
	Ended   int // users whose sessions were ended because their provider refused the token
	Failed  int // replays that failed for another reason (tried again next time)
}

// identityPage is how many identities CheckSessions reads at a time.
const identityPage = 500

// CheckSessions replays the stored refresh token of every identity whose last check is older than every and whose
// user has a live session signed in through its provider (see the package comment on leaver detection). Run by the
// housekeeping leader.
func (s *Service) CheckSessions(ctx context.Context, every time.Duration) (LeaverResult, error) {
	var res LeaverResult
	now := s.Now()
	down := map[string]bool{} // providers whose check failed this run: their other identities wait for the next run
	// Paged by id (After), not by offset: every page is a range read from where the last one ended, where an offset
	// would walk past every earlier identity again (and miss or repeat some when identities come and go meanwhile).
	for after := ""; ; {
		ids, _, err := s.Svc.Identities.List(ctx, store.ListQuery{After: after, Limit: identityPage})
		if err != nil {
			return res, err
		}
		if len(ids) > 0 {
			after = ids[len(ids)-1].ID
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			if id.Refresh == "" || now.Sub(id.RefreshChecked) < every || down[id.ProviderID] || !s.hasProviderSession(ctx, id) {
				continue
			}
			if !s.checkIdentity(ctx, id, &res) {
				down[id.ProviderID] = true
			}
		}
		if len(ids) < identityPage {
			return res, nil
		}
	}
}

// hasProviderSession reports whether the identity's user has a live session signed in through its provider.
func (s *Service) hasProviderSession(ctx context.Context, id *model.Identity) bool {
	sessions, err := s.Svc.Sessions.All(ctx, id.UserID)
	if err != nil {
		return false
	}
	now := s.Now()
	for _, ss := range sessions {
		if ss.Provider == id.ProviderID && ss.Valid(now) {
			return true
		}
	}
	return false
}

var errRefused = errors.New("upstream: the provider refused the refresh token")

// checkIdentity replays one identity's refresh token. It reports false when the provider could not answer (the
// identity is left unmarked, so it is checked again next run, and so are the provider's others).
func (s *Service) checkIdentity(ctx context.Context, id *model.Identity, res *LeaverResult) bool {
	p, err := s.Svc.Providers.Get(ctx, id.ProviderID)
	if err != nil || !p.Enabled || !p.OIDC() || id.Authority != model.ProviderAuthority(p) {
		return true // a provider that is gone, off or pointed elsewhere: its sessions do not pass sign-in checks anyway
	}
	plain, err := s.Svc.Sealer.OpenFor(refreshBinding(id.ID), id.Refresh)
	if err != nil {
		return true
	}
	res.Checked++
	next, err := s.replay(ctx, p, string(plain))
	switch {
	case errors.Is(err, errRefused):
		s.leaver(ctx, id, p)
		res.Ended++
		return true
	case err != nil:
		// Not recorded as checked: the user was not checked. (Discovery failures are remembered for a while, so the
		// provider's other identities would fail the same way: the caller leaves them for the next run.)
		res.Failed++
		s.Svc.Log.Warn("upstream: refresh token check failed; trying again later", "provider", p.Name, "user", id.UserID, "error", err)
		return false
	}
	// Record the check (and a rotated token). A concurrent sign-in that stored a newer token wins: its token is the
	// current one, and the one just replayed is dropped.
	for range 4 {
		cur, gerr := s.Svc.Identities.Get(ctx, id.ID)
		if gerr != nil || cur.Refresh != id.Refresh {
			return true
		}
		if next != "" && next != string(plain) {
			cur.Refresh = s.Svc.Sealer.SealFor(refreshBinding(cur.ID), []byte(next))
		}
		cur.RefreshChecked = s.Now().UTC()
		uerr := s.Svc.Identities.Update(ctx, cur)
		if errors.Is(uerr, store.ErrStale) {
			continue
		}
		if !store.Applied(uerr) && next != "" {
			// The provider rotated the token and the new one could not be kept: the next check will be refused and
			// end the user's sessions (they sign in again). Rare; logged so it can be told apart from a leaver.
			s.Svc.Log.Error("upstream: could not keep the provider's rotated refresh token", "provider", p.Name,
				"user", id.UserID, "error", uerr)
		}
		return true
	}
	return true
}

// leaver ends the sessions and refresh grants of a user whose provider no longer accepts their refresh token, and
// forgets the token. A sign-in through the provider since the token was read (a newer token is stored) means the
// provider accepted the account again: nothing ends then, and the new token is checked next time.
func (s *Service) leaver(ctx context.Context, id *model.Identity, p *model.Provider) {
	cur, err := s.Svc.Identities.Get(ctx, id.ID)
	if err != nil || cur.Refresh != id.Refresh {
		return
	}
	target := id.UserID
	if u, err := s.Svc.Users.Get(ctx, id.UserID); err == nil {
		target = u.Username
	}
	result := "sessions ended"
	if err := s.Svc.RevokeSessions(ctx, service.System, id.UserID); err != nil {
		result = "not every session ended: " + err.Error()
		s.Svc.Log.Warn("upstream: ending the sessions of a user the provider refused", "provider", p.Name, "user", id.UserID, "error", err)
	}
	actor := &service.Actor{OrgID: p.OrgID, Role: model.RoleManager, Name: "provider:" + p.Name}
	s.Svc.Audit(ctx, actor, p.OrgID, "identity.refresh.refused", target, map[string]string{"provider": p.Name, "result": result})
	for range 4 {
		cur.Refresh, cur.RefreshChecked = "", s.Now().UTC()
		if err := s.Svc.Identities.Update(service.Durable(ctx), cur); !errors.Is(err, store.ErrStale) {
			return
		}
		if cur, err = s.Svc.Identities.Get(ctx, id.ID); err != nil || cur.Refresh != id.Refresh {
			return
		}
	}
}

// replay uses refresh at the provider's token endpoint. It returns the provider's new refresh token when it rotated
// it (else ""), errRefused when the provider answered invalid_grant, and another error for anything else.
func (s *Service) replay(ctx context.Context, p *model.Provider, refresh string) (string, error) {
	d, err := s.discoverFor(ctx, p)
	if err != nil {
		return "", err
	}
	secret, err := s.Svc.Sealer.OpenFor(service.ProviderSecretBinding(p.ID), p.ClientSecret)
	if err != nil {
		return "", fmt.Errorf("upstream: provider secret: %w", err)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	var basic [2]string
	if contains(d.TokenAuthMethods, "client_secret_basic") && !contains(d.TokenAuthMethods, "client_secret_post") {
		basic = [2]string{p.ClientID, string(secret)}
	} else {
		form.Set("client_id", p.ClientID)
		form.Set("client_secret", string(secret))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic[0] != "" {
		req.SetBasicAuth(url.QueryEscape(basic[0]), url.QueryEscape(basic[1]))
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	_ = json.Unmarshal(body, &out)
	switch {
	case resp.StatusCode == http.StatusOK && out.AccessToken != "":
		return out.RefreshToken, nil
	case resp.StatusCode == http.StatusBadRequest && out.Error == "invalid_grant":
		return "", errRefused
	}
	return "", fmt.Errorf("%w: %s answered %d %s", ErrUpstream, req.URL.Host, resp.StatusCode, out.Error)
}
