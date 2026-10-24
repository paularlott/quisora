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
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// "quisora invite" against a running server. A node-local store (BadgerDB, SQLite) belongs to the node that runs on
// it, so the command asks that server to issue the invitation instead of writing to the store itself. Nobody may be
// able to sign in (that is when break-glass is needed), so the request is not authenticated by a session or a token:
// it is signed with a key derived from the master key, the secret the offline command needs anyway. A request is
// good for two minutes and once, and a node takes at most commandRequestsPerMin from one address.
const (
	commandInvitePath     = "/api-internal/command/invite"
	nsCommand             = "command"
	commandWindow         = 2 * time.Minute
	commandRequestsPerMin = 10
)

// commandInvite is the signed request.
type commandInvite struct {
	Org        string `json:"org"`
	Email      string `json:"email"`
	BreakGlass bool   `json:"break_glass,omitempty"`
	At         int64  `json:"at"`    // unix seconds
	Nonce      string `json:"nonce"` // single use
	MAC        string `json:"mac"`   // base64url of the MAC of everything above
}

func (ci *commandInvite) message() []string {
	return []string{"quisora command: invite v1", ci.Org, ci.Email, strconv.FormatBool(ci.BreakGlass),
		strconv.FormatInt(ci.At, 10), ci.Nonce}
}

func (ci *commandInvite) sign(sealer *secure.Sealer) {
	ci.MAC = base64.RawURLEncoding.EncodeToString(sealer.MAC(ci.message()...))
}

// signedBy reports whether ci was signed with a master key of sealer's ring.
func (ci *commandInvite) signedBy(sealer *secure.Sealer) bool {
	got, err := base64.RawURLEncoding.DecodeString(ci.MAC)
	if err != nil {
		return false
	}
	ok := false
	for _, want := range sealer.MACs(ci.message()...) {
		ok = hmac.Equal(got, want) || ok
	}
	return ok
}

type commandInviteReply struct {
	Link    string    `json:"link"`
	Expires time.Time `json:"expires"`
}

// commandModule serves the command requests on a running node.
type commandModule struct{ a *App }

func (m commandModule) Register(s *web.Server) {
	s.Mux.HandleFunc("POST "+commandInvitePath, m.invite)
}

func (m commandModule) invite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	refuse := func(status int, msg string) { web.WriteJSON(w, status, web.ErrorBody{Error: msg}) }
	n, err := m.a.Eph.Incr(ctx, nsCommand, "ip|"+web.RateKeyIP(r), 1, time.Minute)
	if err != nil || n > commandRequestsPerMin {
		refuse(http.StatusTooManyRequests, "too many requests: try again in a minute")
		return
	}
	var in commandInvite
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		refuse(http.StatusBadRequest, "the request could not be read")
		return
	}
	at := time.Unix(in.At, 0)
	if len(in.Nonce) < 16 || len(in.Nonce) > 128 || time.Since(at).Abs() > commandWindow || !in.signedBy(m.a.Svc.Sealer) {
		m.a.Log.Warn("command request refused: not signed with this server's master key, or stale",
			"ip", web.ClientIP(r))
		refuse(http.StatusUnauthorized, "the request is not signed with this server's master key, or is too old "+
			"(check the clocks)")
		return
	}
	if n, err := m.a.Eph.Incr(ctx, nsCommand, "nonce|"+in.Nonce, 1, 2*commandWindow); err != nil || n != 1 {
		refuse(http.StatusUnauthorized, "the request was already used")
		return
	}
	link, expires, err := InviteUser(ctx, m.a.Svc, in.Org, in.Email, in.BreakGlass)
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, service.ErrNotFound) {
			status = http.StatusNotFound
		}
		refuse(status, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusOK, commandInviteReply{Link: link, Expires: expires})
}

// errServerDown means no server answered at the address: the command may use the store itself.
var errServerDown = errors.New("no server is running there")

// RemoteInvite asks the server at server (default: server.public_url) to issue the invitation, signing the request
// with the configured master key. Its certificate is checked against the system roots, server.extra_ca_file, caFile
// and the node's own self-signed certificate (in the data directory), unless insecure.
func RemoteInvite(ctx context.Context, c *config.Config, server, caFile string, insecure bool, orgName, email string,
	breakGlass bool) (string, time.Time, error) {
	key, err := masterKey(c)
	if err != nil {
		return "", time.Time{}, err
	}
	sealer, err := newSealer(c, key)
	if err != nil {
		return "", time.Time{}, err
	}
	if server == "" {
		server = c.Server.PublicURL
	}
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", time.Time{}, fmt.Errorf("the server must be an https URL, such as https://id.example.com")
	}
	roots, err := secure.RootPool(c.Server.ExtraCAFile)
	if err != nil {
		return "", time.Time{}, err
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
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: roots, InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}}}

	req := commandInvite{Org: orgName, Email: email, BreakGlass: breakGlass, At: time.Now().Unix(),
		Nonce: secure.RandomToken(18)}
	req.sign(sealer)
	body, _ := json.Marshal(req)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String()+commandInvitePath, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(hr)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return "", time.Time{}, fmt.Errorf("%w: %s", errServerDown, u.Host)
		}
		return "", time.Time{}, fmt.Errorf("server %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e web.ErrorBody
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if resp.StatusCode == http.StatusNotFound && e.Error == "" {
			return "", time.Time{}, fmt.Errorf("server %s does not take invitations from the command (an older build?)", u.Host)
		}
		return "", time.Time{}, fmt.Errorf("server %s: %s", u.Host, e.Error)
	}
	var out commandInviteReply
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Link == "" {
		return "", time.Time{}, fmt.Errorf("server %s: unexpected answer", u.Host)
	}
	return out.Link, out.Expires, nil
}

// Invite is "quisora invite": through the running server when the store is the node's own (BadgerDB or SQLite, or
// any database of a gossip cluster: a write that bypassed the node would not be replicated) and a server answers at
// server (or server.public_url); else into the store directly (a shared database, which every node reads, or the
// store of a node that is stopped).
func Invite(ctx context.Context, c *config.Config, log logger.Logger, server, caFile string, insecure bool, orgName,
	email string, breakGlass bool) (link string, expires time.Time, how string, err error) {
	if server != "" || !c.SharedStorage() || c.Replicate() {
		link, expires, err = RemoteInvite(ctx, c, server, caFile, insecure, orgName, email, breakGlass)
		if err == nil {
			return link, expires, "the running server", nil
		}
		if server != "" || !errors.Is(err, errServerDown) {
			return "", time.Time{}, "", err
		}
	}
	link, expires, err = IssueInvite(ctx, c, log, orgName, email, breakGlass)
	return link, expires, "the store", err
}
