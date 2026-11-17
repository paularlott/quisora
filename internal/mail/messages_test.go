package mail

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/mailtpl"
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
}

func TestSendRecoveryUsed(t *testing.T) {
	cap := newCapture()
	m := newMailer(t, nil, cap)
	u, org := userAndOrg(t, m, "ann@example.com")
	if err := m.SendRecoveryUsed(context.Background(), u, org, 7); err != nil {
		t.Fatal(err)
	}
	msg := cap.wait(t)
	if msg.To != "ann@example.com" || !strings.Contains(msg.Subject, "Widgets <Inc>") || !strings.Contains(msg.Text, "7 of them are left") {
		t.Fatalf("%+v", msg)
	}
	if !strings.Contains(msg.Text, "https://quisora.example.test/o/"+org.ID+"/account") {
		t.Fatalf("account link missing: %s", msg.Text)
	}
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
	// It is queued as its organization's, and is not sent once the code has expired.
	if msg.OrgID != org.ID || time.Until(msg.Expires) < 9*time.Minute || time.Until(msg.Expires) > 10*time.Minute {
		t.Fatalf("organization %q, expires %v: want %q, in 10 minutes", msg.OrgID, msg.Expires, org.ID)
	}
}

// An organization's emails are rendered from its own templates over the primary organization's, with its brand.
func TestOrgTemplates(t *testing.T) {
	cap := newCapture()
	m := newMailer(t, nil, cap)
	ctx := context.Background()
	u, org := userAndOrg(t, m, "ann@example.com")
	_, err := m.Svc.UpdateEmailTemplates(ctx, service.System, org.ID, model.EmailTemplateSet{
		LayoutText: "{{.Org}} ({{.PrimaryColor}}, {{.LogoURL}})\n{{template \"body\" .}}",
		Emails:     map[string]model.EmailTemplate{mailtpl.Reset: {Subject: "New password for {{.Name}}"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SendReset(ctx, u, org); err != nil {
		t.Fatal(err)
	}
	msg := cap.wait(t)
	if msg.Subject != "New password for Ann" || !strings.HasPrefix(msg.Text, "Widgets <Inc> (#3730a3, https://quisora.example.test/branding/logo-light)\n") ||
		!strings.Contains(msg.Text, "/reset?token=") || !strings.Contains(msg.HTML, "Reset password") {
		t.Fatalf("%+v", msg)
	}
	if err := m.SendTest(ctx, org.ID, "bob@example.com", mailtpl.Message{Subject: "s", Text: "t", HTML: "<p>h</p>"}); err != nil {
		t.Fatal(err)
	}
	if msg = cap.wait(t); msg.To != "bob@example.com" || msg.OrgID != org.ID || msg.Subject != "s" {
		t.Fatalf("test email: %+v", msg)
	}
}

// The access request emails: a new request goes to the approver group's members (not to the person who asked, when
// they are one), a decision and an early end to the person who asked, each with the tenant, length and link.
func TestSendAccessRequest(t *testing.T) {
	cap := newCapture()
	m := newMailer(t, nil, cap)
	ctx := context.Background()
	pat, org := userAndOrg(t, m, "pat@example.com")
	sam, err := m.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: ptr("sam"), GivenName: ptr("Sam"), Email: ptr("sam@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	approvers, err := m.Svc.CreateGroupWithMembers(ctx, service.System, org.ID, service.GroupInput{DisplayName: ptr("Leads")}, []string{sam.ID, pat.ID})
	if err != nil {
		t.Fatal(err)
	}
	tn, err := m.Svc.CreateTenant(ctx, service.System, org.ID, service.TenantInput{Name: ptr("ops"), DisplayName: ptr("Ops tools")})
	if err != nil {
		t.Fatal(err)
	}
	r := &model.AccessRequest{OrgID: org.ID, TenantID: tn.ID, UserID: pat.ID, Approvers: approvers.ID, Length: 4 * 3600,
		Reason: "INC-1", State: model.RequestPending}
	if err := m.SendAccessRequest(ctx, service.AccessRequestNotice{Event: "new", Request: r, By: "Pat"}); err != nil {
		t.Fatal(err)
	}
	msg := cap.wait(t)
	if msg.To != "sam@example.com" || !strings.Contains(msg.Subject, "asks for access to Ops tools") || !strings.Contains(msg.Text, "for 4 hours") ||
		!strings.Contains(msg.Text, "Why: INC-1") || !strings.Contains(msg.Text, "/o/"+org.ID+"/account/approvals") {
		t.Fatalf("new: %+v", msg)
	}
	r.State, r.Ends, r.Note = model.RequestApproved, time.Date(2026, 11, 18, 15, 0, 0, 0, time.UTC), "ok"
	if err := m.SendAccessRequest(ctx, service.AccessRequestNotice{Event: "approved", Request: r, By: "Sam"}); err != nil {
		t.Fatal(err)
	}
	msg = cap.wait(t)
	if msg.To != "pat@example.com" || !strings.Contains(msg.Subject, "was approved") || !strings.Contains(msg.Text, "until 18 Nov 2026 15:00 UTC") ||
		!strings.Contains(msg.Text, "Their note: ok") || !strings.Contains(msg.Text, "/o/"+org.ID+"/account/requests") {
		t.Fatalf("approved: %+v", msg)
	}
	if err := m.SendAccessRequest(ctx, service.AccessRequestNotice{Event: "ended", Request: r, By: "Sam"}); err != nil {
		t.Fatal(err)
	}
	if msg = cap.wait(t); msg.To != "pat@example.com" || !strings.Contains(msg.Text, "Sam ended your access to Ops tools") {
		t.Fatalf("ended: %+v", msg)
	}
	select {
	case extra := <-cap.ch:
		t.Fatalf("an extra email: %+v", extra)
	default:
	}
}
