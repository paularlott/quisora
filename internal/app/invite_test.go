package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func totpNow(secret string) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

// The first super admin has no password: the bootstrap file holds an invitation link, the page sets a password and
// the primary org's MFA requirement forces a second factor before any session exists.
func TestBootstrapAdminInvitationRequiresSecondFactor(t *testing.T) {
	a, hc, base := startApp(t, "sqlite")
	jar, _ := cookiejar.New(nil)
	hc.Jar = jar

	// "quisora bootstrap" printed the invitation link (startApp ran it before serving)
	m := []string{"", lastBootstrapLink}
	if !strings.HasPrefix(m[1], base+"/invite?token=") {
		t.Fatalf("bootstrap link: %q", m[1])
	}
	ctx := context.Background()
	primary, _ := a.Svc.PrimaryOrg(ctx)
	admin, _ := a.Svc.FindUserByEmail(ctx, primary.ID, "admin@example.com")
	if admin.PasswordHash != "" || !primary.Settings.RequireMFA || admin.Role != "super_admin" {
		t.Fatalf("bootstrap state: %+v %+v", admin, primary.Settings)
	}
	// Email+password sign-in is impossible until the invitation is accepted.
	resp, err := hc.Get(m[1])
	if err != nil {
		t.Fatal(err)
	}
	var page bytes.Buffer
	_, _ = page.ReadFrom(resp.Body)
	resp.Body.Close()
	csrf := regexp.MustCompile(`<meta name="csrf-token" content="([^"]*)"`).FindStringSubmatch(page.String())
	if resp.StatusCode != 200 || csrf == nil || !strings.Contains(page.String(), "Confirm password") {
		t.Fatalf("invite page %d", resp.StatusCode)
	}
	post := func(p string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		return doJSON(t, hc, "POST", base+p, map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf[1]}, bytes.NewReader(b))
	}
	tok := m[1][strings.Index(m[1], "token=")+6:]
	code, out := post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "bootstrap admin password"})
	if code != 200 || out["step"] != "enrol" || out["ticket"] == nil {
		t.Fatalf("expected the enrolment step: %d %v", code, out)
	}
	if resp, _ := hc.Get(base + "/account"); resp.StatusCode == 200 {
		t.Fatal("session before the second factor")
	}
	ticket := out["ticket"]
	code, out = post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": ticket})
	if code != 200 {
		t.Fatalf("totp begin %d %v", code, out)
	}
	code, out = post("/api-internal/login/enrol/totp/confirm", map[string]any{"ticket": ticket, "code": totpNow(out["secret"].(string))})
	if code != 200 || out["next"] != "/account" {
		t.Fatalf("totp confirm %d %v", code, out)
	}
	resp, err = hc.Get(base + "/account")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("account after enrolment: %v %v", resp, err)
	}
	resp.Body.Close()
	// The link is single use.
	code, _ = post("/api-internal/invite/complete", map[string]any{"token": tok, "password": "another admin password"})
	if code != 410 {
		t.Fatalf("link reused: %d", code)
	}
}

func inviteService(t *testing.T) *service.Service {
	t.Helper()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := memstore.New()
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(cfg, st, sealer)
	if _, _, err := svc.Bootstrap(context.Background(), "root@example.com"); err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestInviteUserCore(t *testing.T) {
	svc := inviteService(t)
	ctx := context.Background()
	first, exp, err := InviteUser(ctx, svc, "Primary", "root@example.com")
	if err != nil || !strings.Contains(first, "/invite?token=") || time.Until(exp) < 6*24*time.Hour {
		t.Fatalf("invite: %q %v %v", first, exp, err)
	}
	// A second invitation (by upper-case email address this time) revokes the first.
	second, _, err := InviteUser(ctx, svc, "primary", "ROOT@example.com")
	if err != nil || second == first {
		t.Fatalf("second invite: %v", err)
	}
	if _, _, err := svc.PeekLink(ctx, first[strings.Index(first, "token=")+6:], service.LinkInvite); err == nil {
		t.Fatal("older invitation still valid")
	}
	if _, _, err := svc.PeekLink(ctx, second[strings.Index(second, "token=")+6:], service.LinkInvite); err != nil {
		t.Fatalf("newest invitation: %v", err)
	}
	if _, _, err := InviteUser(ctx, svc, "nope", "admin@example.com"); err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatalf("unknown org: %v", err)
	}
	if _, _, err := InviteUser(ctx, svc, "primary", "ghost"); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("unknown user: %v", err)
	}
	// Disabled accounts are refused.
	pat, err := svc.CreateUser(ctx, service.System, mustPrimary(t, svc), service.UserInput{GivenName: gn("T"), Username: ptr("pat"), Email: ptr("pat@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := svc.UpdateUser(ctx, service.System, pat.ID, service.UserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := InviteUser(ctx, svc, "primary", "pat"); err == nil {
		t.Fatal("invited a disabled account")
	}
}

func mustPrimary(t *testing.T, svc *service.Service) string {
	t.Helper()
	o, err := svc.PrimaryOrg(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return o.ID
}

// IssueInvite opens the configured store like serve does: with the server (or anything) holding a badger store it
// fails with a clear message, and on a free store it works and leaves the store usable.
func TestIssueInviteStoreLockedAndFree(t *testing.T) {
	c := config.Default()
	c.Server.DataDir = t.TempDir()
	c.Server.MasterKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	c.Server.PublicURL = "https://quisora.example.test"
	c.Storage.Backend = "badgerdb"
	c.Limits.PasswordWorkers = 2
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	log := logger.NewNullLogger()

	// Set up as an operator would, then keep the store open like a running server.
	if _, _, err := Bootstrap(ctx, c, log); err != nil {
		t.Fatal(err)
	}
	a, err := Start(ctx, withListen(t, c), log)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = IssueInvite(ctx, c, log, "primary", "admin@example.com")
	if !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("a locked store: %v", err)
	}
	a.Close()

	link, _, err := IssueInvite(ctx, c, log, "primary", "admin@example.com")
	if err != nil || !strings.HasPrefix(link, "https://quisora.example.test/invite?token=") {
		t.Fatalf("free store: %q %v", link, err)
	}
	// ... and the link it wrote is honoured by a server started afterwards.
	a, err = Start(ctx, withListen(t, c), log)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, _, err := a.Svc.PeekLink(ctx, link[strings.Index(link, "token=")+6:], service.LinkInvite); err != nil {
		t.Fatalf("invitation not durable across processes: %v", err)
	}
}

func withListen(t *testing.T, c *config.Config) *config.Config {
	t.Helper()
	cc := *c
	cc.Server.Listen = "127.0.0.1:0"
	return &cc
}
