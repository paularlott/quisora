package sshcli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	scope       = "openid profile"
	deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"
)

// tokenResponse is what the token endpoint answers (only what the CLI uses).
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

// basicCreds are client credentials sent as HTTP Basic (client_secret_basic).
type basicCreds struct{ id, secret string }

// postForm sends a form to a token or device endpoint, with client credentials in an Authorization header when basic
// is given (client_secret_post ones are form fields), and decodes the JSON answer into out. An error answer is an
// *apiError.
func (e *Env) postForm(ctx context.Context, endpoint string, form url.Values, basic *basicCreds, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic != nil {
		// client_secret_basic: both parts are form-encoded before they are joined (RFC 6749 section 2.3.1)
		req.SetBasicAuth(url.QueryEscape(basic.id), url.QueryEscape(basic.secret))
	}
	resp, err := e.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return readError(resp)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(out); err != nil {
		return fmt.Errorf("unreadable answer: %w", err)
	}
	return nil
}

// checkToken refuses an answer that has no usable access token.
func checkToken(t *tokenResponse) error {
	if t.AccessToken == "" {
		return errors.New("the token endpoint gave no access token")
	}
	if t.TokenType != "" && !strings.EqualFold(t.TokenType, "Bearer") {
		return fmt.Errorf("the token endpoint gave a %s token: the CLI uses Bearer tokens", t.TokenType)
	}
	return nil
}

// randomString is n random bytes, URL-safe base64.
func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("sshcli: no random bytes: " + err.Error()) // the system's source failed: nothing safe is left to do
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// callback is what the loopback listener receives.
type callback struct {
	code string
	err  error
}

// browserLogin is the authorization code flow with PKCE: a listener on a random loopback port receives the
// redirect, and the code is exchanged for tokens.
func (e *Env) browserLogin(ctx context.Context, d *Discovery, noBrowser bool) (*tokenResponse, error) {
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.ClientID == "" {
		return nil, errors.New("discovery has no authorization endpoint, token endpoint or client: is SSH set up for the tenant?")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listening on the loopback address for the sign-in: %w", err)
	}
	redirect := "http://" + ln.Addr().String() + "/callback"
	verifier := randomString(32)
	sum := sha256.Sum256([]byte(verifier))
	state, nonce := randomString(24), randomString(24)

	authURL, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		ln.Close()
		return nil, err
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", d.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	if d.ACRValues != "" {
		q.Set("acr_values", d.ACRValues)
	}
	if d.MaxAuthAge > 0 {
		q.Set("max_age", strconv.Itoa(d.MaxAuthAge))
	}
	authURL.RawQuery = q.Encode()

	got := make(chan callback, 1)
	deliver := func(c callback) {
		select {
		case got <- c:
		default: // one answer is enough
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(p.Get("state")), []byte(state)) != 1 {
			// not an answer to this sign-in: a stray request must not end it
			page(w, http.StatusBadRequest, "Sign-in failed", "This response does not belong to the sign-in that is waiting. Start again from the terminal.")
			return
		}
		if code := p.Get("error"); code != "" {
			desc := p.Get("error_description")
			page(w, http.StatusOK, "Sign-in failed", cmpOr(desc, code)+" You can close this window.")
			deliver(callback{err: (&apiError{Code: code, Desc: desc})})
			return
		}
		code := p.Get("code")
		if code == "" {
			page(w, http.StatusBadRequest, "Sign-in failed", "The response has no code.")
			return
		}
		page(w, http.StatusOK, "Signed in", "You can close this window and return to the terminal.")
		deliver(callback{code: code})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	if noBrowser {
		fmt.Fprintf(e.errw(), "Open this URL in a browser on this machine (the sign-in returns to %s):\n\n%s\n\n", ln.Addr(), authURL)
	} else {
		if err := e.openBrowser(authURL.String()); err != nil {
			fmt.Fprintf(e.errw(), "Could not open a browser (%v).\n", err)
		} else {
			fmt.Fprintln(e.errw(), "Opening your browser to sign in; if it does not open, go to:")
		}
		fmt.Fprintf(e.errw(), "\n%s\n\n", authURL)
	}
	fmt.Fprintln(e.errw(), "Waiting for the sign-in...")

	timeout := e.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var cb callback
	select {
	case cb = <-got:
	case <-timer.C:
		return nil, fmt.Errorf("timed out after %s waiting for the sign-in", timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if cb.err != nil {
		return nil, fmt.Errorf("sign-in refused: %w", cb.err)
	}

	var tok tokenResponse
	err = e.postForm(ctx, d.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.code},
		"redirect_uri":  {redirect},
		"client_id":     {d.ClientID},
		"code_verifier": {verifier},
	}, nil, &tok)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	if err := checkToken(&tok); err != nil {
		return nil, err
	}
	// The tokens came straight from the token endpoint over TLS, so the ID token's signature is not checked; its
	// nonce shows it belongs to this sign-in.
	idNonce, err := idTokenNonce(tok.IDToken)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(idNonce), []byte(nonce)) != 1 {
		return nil, errors.New("the ID token does not answer this sign-in (nonce mismatch)")
	}
	return &tok, nil
}

// idTokenNonce is the nonce claim of an ID token (not verified otherwise).
func idTokenNonce(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("the token endpoint gave no usable ID token")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("the ID token is not readable")
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return "", errors.New("the ID token is not readable")
	}
	return claims.Nonce, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// page writes the small page the browser is left on.
func page(w http.ResponseWriter, status int, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>`+
		`<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}</style></head>`+
		`<body><h1>%s</h1><p>%s</p></body></html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(msg))
}

// openBrowser opens u in the user's browser.
func (e *Env) openBrowser(u string) error {
	if e.OpenBrowser != nil {
		return e.OpenBrowser(u)
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// deviceResponse is the device authorization endpoint's answer (RFC 8628 section 3.2).
type deviceResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// deviceLogin is the device authorization grant (RFC 8628): it prints the code and the URL to approve it at, then
// polls the token endpoint.
func (e *Env) deviceLogin(ctx context.Context, d *Discovery) (*tokenResponse, error) {
	if d.DeviceAuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.ClientID == "" {
		return nil, errors.New("discovery has no device authorization endpoint, token endpoint or client: is SSH set up for the tenant?")
	}
	form := url.Values{"client_id": {d.ClientID}, "scope": {scope}}
	if d.ACRValues != "" {
		form.Set("acr_values", d.ACRValues)
	}
	if d.MaxAuthAge > 0 {
		form.Set("max_age", strconv.Itoa(d.MaxAuthAge))
	}
	var dev deviceResponse
	if err := e.postForm(ctx, d.DeviceAuthorizationEndpoint, form, nil, &dev); err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}
	if dev.DeviceCode == "" || dev.UserCode == "" || (dev.VerificationURIComplete == "" && dev.VerificationURI == "") {
		return nil, errors.New("device authorization: the answer is incomplete")
	}
	uri := cmpOr(dev.VerificationURIComplete, dev.VerificationURI)
	fmt.Fprintf(e.errw(), "To sign in, open this URL on any device:\n\n%s\n\nand check that it shows the code %s.\n\nWaiting for the sign-in...\n", uri, dev.UserCode)
	if dev.VerificationURIComplete != "" {
		fmt.Fprintf(e.errw(), "(Without the link: go to %s and enter the code.)\n", dev.VerificationURI)
	}

	interval := time.Duration(dev.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	expires := e.now().Add(15 * time.Minute)
	if dev.ExpiresIn > 0 {
		expires = e.now().Add(time.Duration(dev.ExpiresIn) * time.Second)
	}
	wait, failures := interval, 0
	for {
		if err := e.sleep(ctx, wait); err != nil {
			return nil, err
		}
		if e.now().After(expires) {
			return nil, errors.New("the sign-in expired before it was approved: start again")
		}
		var tok tokenResponse
		err := e.postForm(ctx, d.TokenEndpoint, url.Values{
			"grant_type":  {deviceGrant},
			"device_code": {dev.DeviceCode},
			"client_id":   {d.ClientID},
		}, nil, &tok)
		if err == nil {
			if err := checkToken(&tok); err != nil {
				return nil, err
			}
			return &tok, nil
		}
		var ae *apiError
		if !errors.As(err, &ae) || ae.Status >= http.StatusInternalServerError {
			// The network, a proxy or a restarting server, not an answer about the code, which is still good: try
			// again, further apart each time, until it expires.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if failures == 0 {
				fmt.Fprintf(e.errw(), "warning: the token endpoint did not answer (%v): trying again until the code expires\n", err)
			}
			failures++
			wait = max(interval, min(interval<<min(failures, 4), time.Minute))
			continue
		}
		failures, wait = 0, interval
		switch ae.Code {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
			wait = interval
		case "expired_token":
			return nil, errors.New("the sign-in expired before it was approved: start again")
		case "access_denied":
			return nil, fmt.Errorf("the sign-in was refused: %w", err)
		default:
			return nil, fmt.Errorf("token request: %w", err)
		}
	}
}
