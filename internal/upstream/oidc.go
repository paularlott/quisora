package upstream

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

const (
	discoveryTTL = time.Hour
	// discoveryRetry bounds how often a provider whose discovery failed is asked again: one that is down or never
	// answers costs at most one outbound request per interval, not one per sign-in, and the sign-ins in between fail
	// at once instead of each holding a request slot until the upstream timeout.
	discoveryRetry = 30 * time.Second
	jwksTTL        = time.Hour
	jwksMinRefetch = time.Minute // unknown-kid refetches are rate limited
	clockLeeway    = time.Minute
)

type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	fetched               time.Time
}

func httpsURL(u string) bool {
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.Host != ""
}

// sameIssuer compares issuers, ignoring one trailing slash (Quisora stores most without it; Auth0's ends with one).
func sameIssuer(a, b string) bool {
	return a != "" && strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

// microsoftBase is the address of a Microsoft provider's directory, and the issuer its discovery document names:
// the tenant's own address, or a {tenantid} template for "organizations" (each token then names its tenant).
func (s *Service) microsoftBase(p *model.Provider) (base, issuer string) {
	base = s.MicrosoftAuthority + "/" + url.PathEscape(p.Tenant) + "/v2.0"
	if p.Tenant == "organizations" {
		return base, s.MicrosoftAuthority + "/{tenantid}/v2.0"
	}
	return base, base
}

// discoverFor returns the OpenID configuration of an OpenID Connect provider.
func (s *Service) discoverFor(ctx context.Context, p *model.Provider) (*discovery, error) {
	if p.Type == model.ProviderMicrosoft {
		base, issuer := s.microsoftBase(p)
		return s.discover(ctx, base, issuer)
	}
	return s.discover(ctx, p.Issuer, p.Issuer)
}

// discoveryCall is a discovery fetch in progress, or one that failed less than discoveryRetry ago.
type discoveryCall struct {
	done chan struct{} // closed when d, err and at are set
	d    *discovery
	err  error
	at   time.Time
}

// discover returns the (cached) OpenID configuration published under base, checking that it names issuer. One fetch
// per base runs at a time, whoever asks, and a failure is remembered for discoveryRetry. The fetch is not tied to
// the caller: a caller that goes away (a browser that gave up) returns at once and frees its request, and the fetch
// finishes, bounded by the HTTP client's timeout, for the callers still waiting and the next ones.
func (s *Service) discover(ctx context.Context, base, issuer string) (*discovery, error) {
	s.mu.Lock()
	if d := s.disc[base]; d != nil && s.Now().Sub(d.fetched) < discoveryTTL {
		s.mu.Unlock()
		return d, nil
	}
	c := s.discCalls[base]
	if c != nil {
		select {
		case <-c.done: // finished calls are kept only when they failed
			if s.Now().Sub(c.at) >= discoveryRetry {
				c = nil
			}
		default:
		}
	}
	if c == nil {
		c = &discoveryCall{done: make(chan struct{})}
		s.discCalls[base] = c
		go s.fetchDiscovery(context.WithoutCancel(ctx), base, issuer, c)
	}
	s.mu.Unlock()
	select {
	case <-c.done:
		return c.d, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Service) fetchDiscovery(ctx context.Context, base, issuer string, c *discoveryCall) {
	ctx, cancel := context.WithTimeout(ctx, discoveryRetry) // in case the HTTP client has no timeout of its own
	defer cancel()
	var nd discovery
	err := s.getJSON(ctx, strings.TrimSuffix(base, "/")+"/.well-known/openid-configuration", &nd, nil)
	switch {
	case err != nil:
	case !sameIssuer(nd.Issuer, issuer):
		err = fmt.Errorf("%w: discovery issuer mismatch", ErrUpstream)
	case !httpsURL(nd.AuthorizationEndpoint) || !httpsURL(nd.TokenEndpoint) || !httpsURL(nd.JWKSURI):
		err = fmt.Errorf("%w: discovery document has missing or non-https endpoints", ErrUpstream)
	}
	now := s.Now()
	s.mu.Lock()
	if err == nil {
		nd.fetched = now
		c.d = &nd
		s.disc[base] = &nd
		delete(s.discCalls, base)
	}
	c.err, c.at = err, now
	s.mu.Unlock()
	close(c.done)
}

type keyCache struct {
	keys    []verifyKey
	fetched time.Time
}

// keysFor returns the provider's signing keys; force refetches (rate limited) when a kid was not found.
func (s *Service) keysFor(ctx context.Context, uri string, force bool) ([]verifyKey, error) {
	s.mu.Lock()
	kc := s.cache[uri]
	s.mu.Unlock()
	age := time.Duration(1<<62 - 1)
	if kc != nil {
		age = s.Now().Sub(kc.fetched)
	}
	if kc != nil && age < jwksTTL && (!force || age < jwksMinRefetch) {
		return kc.keys, nil
	}
	var set jwks
	if err := s.getJSON(ctx, uri, &set, nil); err != nil {
		if kc != nil {
			return kc.keys, nil // keep serving the last good set through a provider blip
		}
		return nil, err
	}
	nk := &keyCache{keys: parseKeys(set), fetched: s.Now()}
	s.mu.Lock()
	s.cache[uri] = nk
	s.mu.Unlock()
	return nk.keys, nil
}

// pickKey selects the key named by kid; without a kid it only accepts an unambiguous single-key set.
func pickKey(keys []verifyKey, kid string) *verifyKey {
	if kid == "" {
		if len(keys) == 1 {
			return &keys[0]
		}
		return nil
	}
	for i := range keys {
		if keys[i].kid == kid {
			return &keys[i]
		}
	}
	return nil
}

// verifyIDToken checks signature and claims and returns the claims.
func (s *Service) verifyIDToken(ctx context.Context, d *discovery, p *model.Provider, raw, nonce string) (map[string]any, error) {
	h, payload, signingInput, sig, err := splitJWT(raw)
	if err != nil {
		return nil, err
	}
	switch h.Alg {
	case "RS256", "RS384", "RS512", "PS256", "ES256", "ES384":
	default:
		return nil, fmt.Errorf("unsupported id token algorithm %q", h.Alg)
	}
	keys, err := s.keysFor(ctx, d.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	k := pickKey(keys, h.Kid)
	if k == nil && h.Kid != "" {
		if keys, err = s.keysFor(ctx, d.JWKSURI, true); err != nil {
			return nil, err
		}
		k = pickKey(keys, h.Kid)
	}
	if k == nil {
		return nil, errors.New("id token signing key not found")
	}
	if err := verifySignature(h.Alg, *k, signingInput, sig); err != nil {
		return nil, err
	}
	var c map[string]any
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errBadToken
	}
	if p.Type == model.ProviderMicrosoft {
		// Each tenant issues its own tokens: the issuer must be the address of the tenant the token names, and that
		// tenant must be allowed.
		tid := strings.ToLower(str(c, "tid"))
		allowed := p.AllowedTenants
		if p.Tenant != "organizations" {
			allowed = []string{p.Tenant}
		}
		if tid == "" || !contains(allowed, tid) {
			return nil, errors.New("this Microsoft tenant is not allowed to sign in")
		}
		if !strings.EqualFold(str(c, "iss"), s.MicrosoftAuthority+"/"+tid+"/v2.0") {
			return nil, errors.New("id token issuer mismatch")
		}
	} else if !sameIssuer(str(c, "iss"), p.Issuer) {
		return nil, errors.New("id token issuer mismatch")
	}
	var aud []string
	switch v := c["aud"].(type) {
	case string:
		aud = []string{v}
	case []any:
		for _, a := range v {
			if as, ok := a.(string); ok {
				aud = append(aud, as)
			}
		}
	}
	if !contains(aud, p.ClientID) {
		return nil, errors.New("id token audience mismatch")
	}
	if azp, _ := c["azp"].(string); (len(aud) > 1 || azp != "") && azp != p.ClientID {
		return nil, errors.New("id token authorized party mismatch")
	}
	now := s.Now()
	exp, ok := c["exp"].(float64)
	if !ok || now.After(time.Unix(int64(exp), 0).Add(clockLeeway)) {
		return nil, errors.New("id token expired")
	}
	if iat, ok := c["iat"].(float64); ok && time.Unix(int64(iat), 0).After(now.Add(5*time.Minute)) {
		return nil, errors.New("id token issued in the future")
	}
	if nbf, ok := c["nbf"].(float64); ok && time.Unix(int64(nbf), 0).After(now.Add(clockLeeway)) {
		return nil, errors.New("id token not valid yet")
	}
	if n, _ := c["nonce"].(string); n == "" || subtle.ConstantTimeCompare([]byte(n), []byte(nonce)) != 1 {
		return nil, errors.New("id token nonce mismatch")
	}
	if sub, _ := c["sub"].(string); sub == "" || len(sub) > 255 {
		return nil, errors.New("id token has no usable subject")
	}
	return c, nil
}

func str(c map[string]any, k string) string { s, _ := c[k].(string); return s }

// boolish reads email_verified, which some providers send as the string "true".
func boolish(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return false
}

func (s *Service) oidcClaims(ctx context.Context, p *model.Provider, secret, code string, st state) (Claims, error) {
	c, _, err := s.oidcSignIn(ctx, p, secret, code, st)
	return c, err
}

// oidcSignIn exchanges the code and returns the identity, and the provider's refresh token when it gave one.
func (s *Service) oidcSignIn(ctx context.Context, p *model.Provider, secret, code string, st state) (Claims, string, error) {
	d, err := s.discoverFor(ctx, p)
	if err != nil {
		return Claims{}, "", err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.CallbackURL(p.ID)},
		"code_verifier": {st.Verifier}}
	var basic [2]string
	if contains(d.TokenAuthMethods, "client_secret_basic") && !contains(d.TokenAuthMethods, "client_secret_post") {
		basic = [2]string{p.ClientID, secret}
	} else {
		form.Set("client_id", p.ClientID)
		form.Set("client_secret", secret)
	}
	var tok struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := s.postForm(ctx, d.TokenEndpoint, form, basic, &tok); err != nil {
		return Claims{}, "", err
	}
	if tok.IDToken == "" {
		return Claims{}, "", fmt.Errorf("%w: no id_token in the token response", ErrUpstream)
	}
	c, err := s.verifyIDToken(ctx, d, p, tok.IDToken, st.Nonce)
	if err != nil {
		return Claims{}, "", fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	out := Claims{Subject: str(c, "sub"), Email: str(c, "email"), EmailVerified: boolish(c["email_verified"]),
		Name: str(c, "name"), GivenName: str(c, "given_name"), FamilyName: str(c, "family_name"),
		Username: str(c, "preferred_username")}
	if p.Type == model.ProviderMicrosoft {
		// A Microsoft user is their tenant and object IDs (sub differs per application). Entra's email claim is
		// whatever the tenant's administrators set: it counts as verified only when Microsoft vouches for the
		// domain (xms_edov, an optional claim to enable); a sign-in name standing in for it never does.
		oid := strings.ToLower(str(c, "oid"))
		if oid == "" {
			return Claims{}, "", fmt.Errorf("%w: the Microsoft ID token has no object ID", ErrUpstream)
		}
		out.Subject = strings.ToLower(str(c, "tid")) + ":" + oid
		out.EmailVerified = out.Email != "" && boolish(c["xms_edov"])
		if out.Email == "" && strings.Contains(out.Username, "@") {
			out.Email = out.Username
		}
	}
	if out.Email != "" && out.EmailVerified {
		out.VerifiedEmails = []string{out.Email}
	}
	if out.Email == "" && d.UserinfoEndpoint != "" && httpsURL(d.UserinfoEndpoint) && tok.AccessToken != "" {
		var ui map[string]any
		if err := s.getJSON(ctx, d.UserinfoEndpoint, &ui, map[string]string{"Authorization": "Bearer " + tok.AccessToken}); err == nil &&
			str(ui, "sub") == out.Subject {
			out.Email, out.EmailVerified = str(ui, "email"), boolish(ui["email_verified"])
			if out.Email != "" && out.EmailVerified {
				out.VerifiedEmails = []string{out.Email}
			}
			if out.Name == "" {
				out.Name = str(ui, "name")
			}
			if out.GivenName == "" {
				out.GivenName, out.FamilyName = str(ui, "given_name"), str(ui, "family_name")
			}
		}
	}
	return out, tok.RefreshToken, nil
}
