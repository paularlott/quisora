package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

func userAndOrg(t *testing.T, m *Mailer, email string) (*model.User, *model.Org) {
	t.Helper()
	ctx := context.Background()
	org, err := m.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("widgets"), DisplayName: ptr("Widgets <Inc>")})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: ptr("ann"), GivenName: ptr("Ann"), Email: ptr(email)})
	if err != nil {
		t.Fatal(err)
	}
	return u, org
}

func TestSendVerifyAddress(t *testing.T) {
	cap := newCapture()
	m := newMailer(t, nil, cap)
	ctx := context.Background()
	u, org := userAndOrg(t, m, "ann@example.com")
	if err := m.SendVerifyAddress(ctx, u, org, "ann@example.com"); err != nil {
		t.Fatal(err)
	}
	msg := cap.wait(t)
	if msg.To != "ann@example.com" || !strings.Contains(msg.Text, "https://quisora.example.test/verify-email?token=") {
		t.Fatalf("%+v", msg)
	}
	if !strings.Contains(msg.Text, "24 hours") && !strings.Contains(msg.HTML, "24 hours") {
		t.Fatalf("expiry not stated: %s", msg.Text)
	}
	// An address the user does not have is refused, and nothing is sent.
	if err := m.SendVerifyAddress(ctx, u, org, "stranger@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("foreign address: %v", err)
	}
	// Without the service there are no link tokens.
	bare := &Mailer{Cfg: m.Cfg, Log: m.Log, q: m.q}
	if err := bare.SendVerifyAddress(ctx, u, org, u.Email); err == nil {
		t.Fatal("verification without a link service")
	}
	if err := bare.SendReset(ctx, u, org); err == nil {
		t.Fatal("reset without a link service")
	}
	if err := bare.SendInvite(ctx, u, org); err == nil {
		t.Fatal("invite without a link service")
	}
}

func TestSendRecoveryUsed(t *testing.T) {
	cap := newCapture()
	m := newMailer(t, nil, cap)
	u, org := userAndOrg(t, m, "ann@example.com")
	if err := m.SendRecoveryUsed(context.Background(), u, org, 7); err != nil {
		t.Fatal(err)
	}
	msg := cap.wait(t)
	if msg.To != "ann@example.com" || !strings.Contains(msg.Subject, "Acme ID") || !strings.Contains(msg.Text, "7 of them are left") {
		t.Fatalf("%+v", msg)
	}
	if !strings.Contains(msg.Text, "https://quisora.example.test/account") {
		t.Fatalf("account link missing: %s", msg.Text)
	}
	if !strings.Contains(msg.HTML, "Widgets &lt;Inc&gt;") && strings.Contains(msg.HTML, "Widgets <Inc>") {
		t.Fatalf("org name not escaped: %s", msg.HTML)
	}
	// Without an organization the message still renders.
	if err := m.SendRecoveryUsed(context.Background(), u, nil, 0); err != nil {
		t.Fatal(err)
	}
	cap.wait(t)
}

func TestSendSignInCode(t *testing.T) {
	cap := newCapture()
	m := newMailer(t, nil, cap)
	u, org := userAndOrg(t, m, "ann@example.com")
	if err := m.SendSignInCode(context.Background(), u, org, "493021", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	msg := cap.wait(t)
	if strings.Contains(msg.Subject, "493021") {
		t.Fatalf("the code must not be in the subject: %q", msg.Subject)
	}
	if !strings.Contains(msg.Text, "493021") || !strings.Contains(msg.HTML, "493021") || !strings.Contains(msg.Text, "10 minutes") {
		t.Fatalf("%+v", msg)
	}
	if err := m.SendSignInCode(context.Background(), u, nil, "1", time.Hour); err != nil {
		t.Fatal(err)
	}
	cap.wait(t)
}

func TestSendInviteLinkNoEmail(t *testing.T) {
	m := newMailer(t, nil, newCapture())
	if err := m.SendInviteLink(context.Background(), &model.User{}, nil, "https://x/invite?token=t", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("user without an address accepted")
	}
	if err := m.SendInvite(context.Background(), &model.User{}, nil); err == nil {
		t.Fatal("user without an address accepted")
	}
}

// A queued message survives a failing transport: it is retried after the backoff and then delivered; Queued counts
// what is waiting.
func TestRetryThenDeliver(t *testing.T) {
	cfg := config.Default()
	cfg.Server.DataDir = t.TempDir()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	var calls atomic.Int32
	done := make(chan Message, 1)
	tr := TransportFunc(func(_ context.Context, msg Message) error {
		if calls.Add(1) < 3 {
			return errors.New("smtp down")
		}
		done <- msg
		return nil
	})
	m, err := New(cfg, logger.NewNullLogger(), sealer, tr, 10*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Send(context.Background(), Message{To: "bob@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-done:
		if msg.To != "bob@example.com" || calls.Load() != 3 {
			t.Fatalf("%+v after %d calls", msg, calls.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("never delivered")
	}
	deadline := time.Now().Add(5 * time.Second)
	for m.Queued() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Queued() != 0 {
		t.Fatalf("%d still queued", m.Queued())
	}
	if stale, lost := m.Reseal(); stale+lost != 0 {
		t.Fatalf("reseal left %d stale, %d lost", stale, lost)
	}
}

// A message that exhausts its backoff is dropped instead of retried forever.
func TestGiveUpAfterBackoff(t *testing.T) {
	cfg := config.Default()
	cfg.Server.DataDir = t.TempDir()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	var calls atomic.Int32
	m, err := New(cfg, logger.NewNullLogger(), sealer, TransportFunc(func(context.Context, Message) error {
		calls.Add(1)
		return errors.New("nope")
	}), 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	_ = m.Send(context.Background(), Message{To: "bob@example.com", Text: "t"})
	deadline := time.Now().Add(5 * time.Second)
	for (m.Queued() != 0 || calls.Load() < 2) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Queued() != 0 || calls.Load() != 2 {
		t.Fatalf("queued=%d calls=%d", m.Queued(), calls.Load())
	}
}

func TestNewFailsOnUnusableDataDir(t *testing.T) {
	cfg := config.Default()
	f := t.TempDir() + "/file"
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Server.DataDir = f // a file where the directory should be
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	if _, err := New(cfg, logger.NewNullLogger(), sealer, TransportFunc(nil)); err == nil {
		t.Fatal("unusable data dir accepted")
	}
}

func TestSMTPErrors(t *testing.T) {
	msg := Message{To: "bob@example.com", Subject: "Hi", Text: "hello"}
	ctx := context.Background()
	t.Run("connection refused", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := ln.Addr().(*net.TCPAddr)
		ln.Close()
		tr := &SMTP{Cfg: config.Mail{SMTPHost: "127.0.0.1", SMTPPort: addr.Port, TLS: "none"}}
		if err := tr.Deliver(ctx, msg); err == nil {
			t.Fatal("delivered to nothing")
		}
		tr.Cfg.TLS = "tls"
		if err := tr.Deliver(ctx, msg); err == nil {
			t.Fatal("delivered to nothing over TLS")
		}
	})
	t.Run("bad from", func(t *testing.T) {
		f := startSMTP(t, false, true)
		tr := smtpTransport(f, "starttls")
		tr.Cfg.From = "not an address"
		if err := tr.Deliver(ctx, msg); err == nil || !strings.Contains(err.Error(), "from") {
			t.Fatalf("bad from: %v", err)
		}
	})
	t.Run("default from and no auth", func(t *testing.T) {
		f := startSMTP(t, false, false)
		tr := smtpTransport(f, "none")
		tr.Cfg.From, tr.Cfg.Username = "", ""
		if err := tr.Deliver(ctx, msg); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.auth != "" || len(f.got) != 1 || !strings.Contains(f.got[0], "From: quisora@127.0.0.1") {
			t.Fatalf("auth=%q got=%v", f.auth, f.got)
		}
	})
	t.Run("untrusted certificate", func(t *testing.T) {
		f := startSMTP(t, false, true)
		tr := smtpTransport(f, "starttls")
		tr.TLSConfig = nil // verify against system roots: the fake's certificate is self-signed
		if err := tr.Deliver(ctx, msg); err == nil {
			t.Fatal("self-signed certificate accepted")
		}
	})
	t.Run("server name defaults to host", func(t *testing.T) {
		f := startSMTP(t, true, false)
		tr := smtpTransport(f, "tls")
		tr.TLSConfig = &tls.Config{InsecureSkipVerify: true, ServerName: ""}
		if err := tr.Deliver(ctx, msg); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("recipient header injection is stripped", func(t *testing.T) {
		f := startSMTP(t, false, false)
		m := msg
		m.To = "bob@example.com\r\nBcc: evil@example.com"
		if err := smtpTransport(f, "none").Deliver(ctx, m); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.got) != 1 || strings.Contains(f.got[0], "\r\nBcc:") {
			t.Fatalf("injected header: %v", f.got)
		}
	})
}
