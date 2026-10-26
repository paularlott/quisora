package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/web"
)

// Commands against a running server ("quisora invite", "quisora set-primary", "quisora sign-out"). Nobody may be able to sign in
// (that is when break-glass is needed), so a command request is not authenticated by a session or a token: it is
// signed with a key derived from the master key, the secret the offline command needs anyway. A request is good for
// two minutes and once, and a node takes at most commandRequestsPerMin from one address.
const (
	nsCommand             = "command"
	commandWindow         = 2 * time.Minute
	commandRequestsPerMin = 10
)

// commandAuth is how the audit log says a command request was authenticated.
const commandAuth = "request signed with the master key"

// commandSig is the signed part every command request carries: when it was made, a single-use nonce, and the MAC of
// the request's message (base64url).
type commandSig struct {
	At    int64  `json:"at"`    // unix seconds
	Nonce string `json:"nonce"` // single use
	MAC   string `json:"mac"`
}

func newCommandSig() commandSig {
	return commandSig{At: time.Now().Unix(), Nonce: secure.RandomToken(18)}
}

func (s *commandSig) signature() *commandSig { return s }

// commandRequest is a command's request: its message is every field the MAC covers, At and Nonce included.
type commandRequest interface {
	signature() *commandSig
	message() []string
}

func signCommand(r commandRequest, sealer *secure.Sealer) {
	r.signature().MAC = base64.RawURLEncoding.EncodeToString(sealer.MAC(r.message()...))
}

// commandSignedBy reports whether r was signed with a master key of sealer's ring.
func commandSignedBy(r commandRequest, sealer *secure.Sealer) bool {
	got, err := base64.RawURLEncoding.DecodeString(r.signature().MAC)
	if err != nil {
		return false
	}
	ok := false
	for _, want := range sealer.MACs(r.message()...) {
		ok = hmac.Equal(got, want) || ok
	}
	return ok
}

// commandModule serves the command requests on a running node.
type commandModule struct{ a *App }

func (m commandModule) Register(s *web.Server) {
	s.Mux.HandleFunc("POST "+commandInvitePath, m.invite)
	s.Mux.HandleFunc("POST "+commandSetPrimaryPath, m.setPrimary)
	s.Mux.HandleFunc("POST "+commandSignOutPath, m.signOut)
}

func commandRefuse(w http.ResponseWriter, status int, msg string) {
	web.WriteJSON(w, status, web.ErrorBody{Error: msg})
}

// accept reads a command request into in and checks it: within the rate limit, signed with this server's master key,
// recent, and not used before. It has answered the refusal when it returns false.
func (m commandModule) accept(w http.ResponseWriter, r *http.Request, in commandRequest) bool {
	ctx := r.Context()
	n, err := m.a.Eph.Incr(ctx, nsCommand, "ip|"+web.RateKeyIP(r), 1, time.Minute)
	if err != nil || n > commandRequestsPerMin {
		commandRefuse(w, http.StatusTooManyRequests, "too many requests: try again in a minute")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := json.NewDecoder(r.Body).Decode(in); err != nil {
		commandRefuse(w, http.StatusBadRequest, "the request could not be read")
		return false
	}
	sig := in.signature()
	at := time.Unix(sig.At, 0)
	if len(sig.Nonce) < 16 || len(sig.Nonce) > 128 || time.Since(at).Abs() > commandWindow || !commandSignedBy(in, m.a.Svc.Sealer) {
		m.a.Log.Warn("command request refused: not signed with this server's master key, or stale",
			"ip", web.ClientIP(r))
		commandRefuse(w, http.StatusUnauthorized, "the request is not signed with this server's master key, or is too old "+
			"(check the clocks)")
		return false
	}
	if n, err := m.a.Eph.Incr(ctx, nsCommand, "nonce|"+sig.Nonce, 1, 2*commandWindow); err != nil || n != 1 {
		commandRefuse(w, http.StatusUnauthorized, "the request was already used")
		return false
	}
	return true
}

// errServerDown means no server answered at the address.
var errServerDown = errors.New("no server is running there")

// commandClient is the HTTP client of a command request. The server's certificate is checked against the system
// roots, server.extra_ca_file, caFile and the node's own self-signed certificate (in the data directory), unless
// insecure.
func commandClient(c *config.Config, caFile string, insecure bool) (*http.Client, error) {
	roots, err := secure.RootPool(c.Server.ExtraCAFile)
	if err != nil {
		return nil, err
	}
	if roots == nil { // the system roots, to add to
		if roots, err = x509.SystemCertPool(); err != nil {
			roots = x509.NewCertPool()
		}
	}
	for _, f := range []string{caFile, c.DataPath(config.DirTLS, "self-signed.crt")} {
		if pem, err := os.ReadFile(f); f != "" && err == nil {
			roots.AppendCertsFromPEM(pem)
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: roots, InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}}}, nil
}

// postCommand signs req with the configured master key, posts it to path on the server at base, and decodes the
// answer into out. A server that cannot be reached is errServerDown.
func postCommand(ctx context.Context, c *config.Config, client *http.Client, base *url.URL, path string,
	req commandRequest, out any) error {
	key, err := masterKey(c)
	if err != nil {
		return err
	}
	sealer, err := newSealer(c, key)
	if err != nil {
		return err
	}
	signCommand(req, sealer)
	body, _ := json.Marshal(req)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(hr)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return fmt.Errorf("%w: %s", errServerDown, base.Host)
		}
		return fmt.Errorf("server %s: %w", base.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e web.ErrorBody
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if resp.StatusCode == http.StatusNotFound && e.Error == "" {
			return fmt.Errorf("server %s does not take this command (an older build?)", base.Host)
		}
		return fmt.Errorf("server %s: %s", base.Host, e.Error)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("server %s: unexpected answer", base.Host)
	}
	return nil
}
