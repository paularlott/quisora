package mail

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
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
	if msg.To != "ann@example.com" || !strings.Contains(msg.Text, "https://quisora.example.test/o/"+org.ID+"/verify-email?token=") {
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
	if !strings.Contains(msg.Text, "https://quisora.example.test/o/"+org.ID+"/account") {
		t.Fatalf("account link missing: %s", msg.Text)
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
