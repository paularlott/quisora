package mail

import (
	"context"
	"errors"
	"io"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func newMailer(t *testing.T, mut func(*config.Config), tr Transport) *Mailer {
	t.Helper()
	cfg := config.Default()
	cfg.Server.PublicURL = "https://quisora.example.test"
	cfg.UI.SiteName = "Acme ID"
	if mut != nil {
		mut(cfg)
	}
	cfg.Server.DataDir = t.TempDir()
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(cfg, logger.NewNullLogger(), sealer, tr)
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	m.SetService(service.New(cfg, st, sealer))
	t.Cleanup(func() { m.Close(); _ = st.Close() })
	return m
}

type capture struct {
	mu   sync.Mutex
	msgs []Message
	ch   chan Message
}

func newCapture() *capture { return &capture{ch: make(chan Message, 16)} }
func (c *capture) Deliver(_ context.Context, m Message) error {
	c.mu.Lock()
	c.msgs = append(c.msgs, m)
	c.mu.Unlock()
	c.ch <- m
	return nil
}
func (c *capture) wait(t *testing.T) Message {
	t.Helper()
	select {
	case m := <-c.ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message delivered")
	}
	return Message{}
}

func TestTemplatesAndLinks(t *testing.T) {
	cap := newCapture()
	m := newMailer(t, nil, cap)
	ctx := context.Background()
	org, err := m.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("widgets"), DisplayName: ptr("Widgets <Inc>")})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: ptr("ann"), GivenName: ptr("Ann <b>"), Email: ptr("ann@example.com")})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		purpose string
		send    func() error
		subject string
		path    string
	}{
		{service.LinkInvite, func() error { return m.SendInvite(ctx, u, org) }, "invited to Acme ID", "/o/" + org.ID + "/invite?token="},
		{service.LinkReset, func() error { return m.SendReset(ctx, u, org) }, "Reset your Acme ID password", "/o/" + org.ID + "/reset?token="},
		{service.LinkVerify, func() error { return m.SendVerify(ctx, u, org) }, "Confirm your email", "/o/" + org.ID + "/verify-email?token="},
	} {
		if err := tc.send(); err != nil {
			t.Fatal(err)
		}
		msg := cap.wait(t)
		if msg.To != "ann@example.com" || !strings.Contains(msg.Subject, tc.subject) {
			t.Fatalf("%s: %+v", tc.purpose, msg)
		}
		i := strings.Index(msg.Text, "https://quisora.example.test"+tc.path)
		if i < 0 {
			t.Fatalf("%s: link missing in text: %s", tc.purpose, msg.Text)
		}
		link := strings.Fields(msg.Text[i:])[0]
		tok := strings.TrimPrefix(link, "https://quisora.example.test"+tc.path)
		if strings.Contains(msg.HTML, "Ann <b>") || !strings.Contains(msg.HTML, "Ann &lt;b&gt;") {
			t.Fatalf("%s: html not escaped: %s", tc.purpose, msg.HTML)
		}
		if !strings.Contains(msg.HTML, link) {
			t.Fatalf("%s: link missing in html", tc.purpose)
		}
		if tc.purpose == service.LinkInvite && (strings.Contains(msg.HTML, "Widgets <Inc>") || !strings.Contains(msg.HTML, "Widgets &lt;Inc&gt;")) {
			t.Fatalf("organization name not escaped in the invitation: %s", msg.HTML)
		}
		// Wrong purpose never redeems, the right one works exactly once.
		if _, _, err := m.Svc.PeekLink(ctx, tok, service.LinkVerify+"x"); !errors.Is(err, service.ErrLink) {
			t.Fatal("purpose mismatch accepted")
		}
		l, got, err := m.Svc.PeekLink(ctx, tok, tc.purpose)
		if err != nil || l.Purpose != tc.purpose || got.ID != u.ID {
			t.Fatalf("peek: %v %v", l, err)
		}
		if tc.purpose == service.LinkVerify && l.Email != "ann@example.com" {
			t.Fatalf("verification link lost the address: %q", l.Email)
		}
		use := func() error {
			if tc.purpose == service.LinkVerify {
				_, _, err := m.Svc.RedeemLink(ctx, tok)
				return err
			}
			_, _, err := m.Svc.UseSignInLink(ctx, tok, tc.purpose, "a fresh long passphrase", service.NewCredEpoch())
			return err
		}
		if err := use(); err != nil {
			t.Fatal(err)
		}
		if err := use(); !errors.Is(err, service.ErrLink) {
			t.Fatal("link reusable")
		}
	}
	if err := m.SendReset(ctx, &model.User{Meta: model.Meta{ID: "x"}}, org); err == nil {
		t.Fatal("user without email accepted")
	}
	if err := m.SendInvite(ctx, &model.User{}, nil); err == nil {
		t.Fatal("invite for a user without an address accepted")
	}
	if err := m.SendInviteLink(ctx, &model.User{}, nil, "https://x/invite?token=t", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("invite link for a user without an address accepted")
	}
	if err := m.Send(ctx, Message{To: "not an address"}); err == nil {
		t.Fatal("bad recipient accepted")
	}
}

func TestSendInviteLinkAndExpiry(t *testing.T) {
	cap := newCapture()
	m := newMailer(t, nil, cap)
	ctx := context.Background()
	org, _ := m.Svc.PrimaryOrg(ctx)
	if org == nil {
		var err error
		if org, err = m.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")}); err != nil {
			t.Fatal(err)
		}
	}
	u, err := m.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("bob"), Email: ptr("bob@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	link, exp, err := m.Svc.CreateInvite(ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SendInviteLink(ctx, u, org, link, exp); err != nil {
		t.Fatal(err)
	}
	msg := cap.wait(t)
	if !strings.Contains(msg.Text, link) || !strings.Contains(msg.Text, "7 days") {
		t.Fatalf("invite mail: %s", msg.Text)
	}
	// Mailing a new invitation revokes the one issued before.
	if err := m.SendInvite(ctx, u, org); err != nil {
		t.Fatal(err)
	}
	cap.wait(t)
	tok := link[strings.Index(link, "token=")+len("token="):]
	if _, _, err := m.Svc.PeekLink(ctx, tok, service.LinkInvite); err == nil {
		t.Fatal("older invitation still valid")
	}
}

func ptr[T any](v T) *T { return &v }

func TestHumanTTL(t *testing.T) {
	for d, want := range map[time.Duration]string{7 * 24 * time.Hour: "7 days", 24 * time.Hour: "24 hours", time.Hour: "1 hour",
		2 * time.Hour: "2 hours", 10 * time.Minute: "10 minutes", time.Second: "1 minute"} {
		if got := humanTTL(d); got != want {
			t.Errorf("%v: %q want %q", d, got, want)
		}
	}
}

func TestBuildMessage(t *testing.T) {
	raw := Build("Acme <no-reply@example.com>", Message{To: "bob@example.com\r\nBcc: evil@example.com",
		Subject: "Héllo\r\nX-Injected: 1", Text: "plain é", HTML: "<p>html</p>"})
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Bcc") != "" || msg.Header.Get("X-Injected") != "" {
		t.Fatal("header injection")
	}
	if !strings.HasPrefix(msg.Header.Get("Content-Type"), "multipart/alternative") {
		t.Fatal(msg.Header.Get("Content-Type"))
	}
	b, _ := io.ReadAll(msg.Body)
	if !strings.Contains(string(b), "text/plain") || !strings.Contains(string(b), "text/html") {
		t.Fatalf("parts: %s", b)
	}
	if !strings.Contains(msg.Header.Get("Subject"), "=?utf-8?q?") {
		t.Fatalf("subject not encoded: %q", msg.Header.Get("Subject"))
	}
}

// An invitation or reset link is mailed to the address it is bound to (the account's when it was issued), never to the
// address on the caller's older copy of the user: an address corrected after the caller read the user (the admin page
// holds the user across the invitation) must not mail the link to the old, mistyped address, which it no longer opens
// the account for.
func TestLinksGoToTheAddressTheyAreBoundTo(t *testing.T) {
	cap := newCapture()
	m := newMailer(t, nil, cap)
	ctx := context.Background()
	org, err := m.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("typo"), Email: ptr("typo@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	stale := *u // the caller's copy, read before the correction
	if _, err := m.Svc.UpdateUser(ctx, service.System, u.ID, service.UserInput{Email: ptr("right@example.com")}); err != nil {
		t.Fatal(err)
	}

	link, exp, err := m.Svc.CreateInvite(ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SendInviteLink(ctx, &stale, org, link, exp); err != nil {
		t.Fatal(err)
	}
	if to := cap.wait(t).To; to != "right@example.com" {
		t.Fatalf("the invitation was mailed to %q, want the address it is bound to", to)
	}
	if err := m.SendReset(ctx, &stale, org); err != nil {
		t.Fatal(err)
	}
	if to := cap.wait(t).To; to != "right@example.com" {
		t.Fatalf("the reset link was mailed to %q, want the address it is bound to", to)
	}
	// the invitation, mailed to the address it is bound to, proves that address when it is used
	tok := link[strings.Index(link, "token=")+len("token="):]
	if l, _, err := m.Svc.PeekLink(ctx, tok, service.LinkInvite); err != nil || l.Email != "right@example.com" {
		t.Fatalf("the invitation: %v %+v", err, l)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	for _, msg := range cap.msgs {
		if msg.To == "typo@example.com" {
			t.Fatalf("a link was mailed to the old address: %q", msg.Subject)
		}
	}
}
