package mail

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/paularlott/quisora/internal/mailtpl"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// SetService enables the emails that carry links (invitation, reset, verification): the links are the service's
// durable, hashed, single-use link tokens, so they work on any node and survive a restart.
func (m *Mailer) SetService(svc *service.Service) { m.Svc = svc }

var errNoService = errors.New("mail: link tokens are not configured")

// SendInviteLink emails an invitation URL that was issued already (service.CreateInvite): "generate a new invite and
// email it" is CreateInvite as the acting admin followed by this.
func (m *Mailer) SendInviteLink(ctx context.Context, u *model.User, org *model.Org, link string, expires time.Time) error {
	if u.Email == "" {
		return errors.New("mail: user has no email address")
	}
	// The address the invitation is bound to, not the one on the caller's copy of the user, which may be older (an
	// address corrected since): a link is only ever mailed to the address it opens the account for.
	to := u.Email
	if m.Svc != nil {
		var err error
		if to, err = m.Svc.LinkAddress(ctx, link); err != nil {
			return err
		}
	}
	if err := m.renderTo(ctx, to, u, org, mailtpl.Invite, link, time.Until(expires)); err != nil {
		return err
	}
	if m.Svc != nil {
		// Accepting an invitation that went to the address on file proves the address.
		if err := m.Svc.MarkLinkSent(ctx, link, to); err != nil {
			m.Log.Warn("mail: invitation not marked as emailed", "error", err)
		}
	}
	return nil
}

// SendReset emails u a password reset link (valid 1 hour).
func (m *Mailer) SendReset(ctx context.Context, u *model.User, org *model.Org) error {
	return m.sendLink(ctx, service.LinkReset, service.ResetTTL, u, org, mailtpl.Reset)
}

// SendVerify emails u a link (valid 24 hours) that confirms the address on file.
func (m *Mailer) SendVerify(ctx context.Context, u *model.User, org *model.Org) error {
	return m.sendLink(ctx, service.LinkVerify, service.VerifyTTL, u, org, mailtpl.Verify)
}

// linkPaths are the pages the mailed links open, in the address space of the organization of the user they are for.
var linkPaths = map[string]string{service.LinkInvite: "/invite", service.LinkReset: "/reset", service.LinkVerify: "/verify-email"}

func (m *Mailer) sendLink(ctx context.Context, purpose string, ttl time.Duration, u *model.User, org *model.Org, name string) error {
	if m.Svc == nil {
		return errNoService
	}
	if u.Email == "" {
		return errors.New("mail: user has no email address")
	}
	tok, l, err := m.Svc.IssueLink(ctx, u, purpose, u.Email, ttl)
	if err != nil {
		return err
	}
	// To the address the link was issued for (the account's as it is now), not the caller's copy of the user's.
	return m.renderTo(ctx, l.Email, u, org, name, m.Svc.LinkURL(u.OrgID, linkPaths[purpose], tok), ttl)
}

// SendVerifyAddress emails a verification link to one address of u (a linked address, or the primary): the link is
// bound to that address, so it verifies nothing else.
func (m *Mailer) SendVerifyAddress(ctx context.Context, u *model.User, org *model.Org, address string) error {
	if m.Svc == nil {
		return errNoService
	}
	tok, err := m.Svc.IssueEmailLink(ctx, u, address)
	if err != nil {
		return err
	}
	return m.renderTo(ctx, address, u, org, mailtpl.Verify, m.Svc.LinkURL(u.OrgID, linkPaths[service.LinkVerify], tok), service.VerifyTTL)
}

// SendRecoveryUsed tells u that one of their recovery codes was used to sign in, and how many are left: someone who
// got hold of the codes is noticed at their first use.
func (m *Mailer) SendRecoveryUsed(ctx context.Context, u *model.User, org *model.Org, left int) error {
	d := web.MailBrand(m.Cfg, org)
	d.Name, d.Link, d.Left = u.FullName(), m.Cfg.Server.PublicURL+web.OrgPath(u.OrgID, "/account"), strconv.Itoa(left)
	msg, err := m.render(ctx, org, mailtpl.Recovery, d)
	if err != nil {
		return err
	}
	msg.To, msg.OrgID = u.Email, u.OrgID
	return m.Send(ctx, msg)
}

// SendSignInCode emails u the one-time code that finishes a sign-in as its second factor, valid for ttl.
func (m *Mailer) SendSignInCode(ctx context.Context, u *model.User, org *model.Org, code string, ttl time.Duration) error {
	d := web.MailBrand(m.Cfg, org)
	d.Name, d.Code, d.Expires = u.FullName(), code, humanTTL(ttl)
	msg, err := m.render(ctx, org, mailtpl.Code, d)
	if err != nil {
		return err
	}
	msg.To, msg.OrgID, msg.Expires = u.Email, u.OrgID, time.Now().Add(ttl)
	return m.Send(ctx, msg)
}

// SendTest queues msg, rendered from organization orgID's templates as they are being edited, to the address to, as
// that organization's mail: the console's test email.
func (m *Mailer) SendTest(ctx context.Context, orgID, to string, msg mailtpl.Message) error {
	return m.Send(ctx, Message{To: to, Subject: msg.Subject, Text: msg.Text, HTML: msg.HTML, OrgID: orgID,
		Expires: time.Now().Add(time.Hour)})
}

func (m *Mailer) renderTo(ctx context.Context, to string, u *model.User, org *model.Org, name, link string, ttl time.Duration) error {
	d := web.MailBrand(m.Cfg, org)
	d.Name, d.Link, d.Expires = u.FullName(), link, humanTTL(ttl)
	msg, err := m.render(ctx, org, name, d)
	if err != nil {
		return err
	}
	msg.To, msg.OrgID, msg.Expires = to, u.OrgID, time.Now().Add(ttl)
	return m.Send(ctx, msg)
}

// render renders the email name from the templates org sends with (its own, the primary organization's, the built-in
// ones: service.SendingEmailTemplates). Templates are checked when they are saved; one that fails now all the same is
// logged, and the email goes out from the built-in templates rather than not at all.
func (m *Mailer) render(ctx context.Context, org *model.Org, name string, d mailtpl.Data) (Message, error) {
	set := mailtpl.Builtin()
	if m.Svc != nil && org != nil {
		set = m.Svc.SendingEmailTemplates(ctx, org.ID)
	}
	r, err := mailtpl.Render(set, name, d)
	if err != nil {
		orgID := ""
		if org != nil {
			orgID = org.ID
		}
		m.Log.Error("email template failed: sent from the built-in one", "organization", orgID, "email", name, "error", err)
		if r, err = mailtpl.Render(mailtpl.Builtin(), name, d); err != nil {
			return Message{}, err
		}
	}
	return Message{Subject: r.Subject, Text: r.Text, HTML: r.HTML}, nil
}

func humanTTL(d time.Duration) string {
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return strconv.Itoa(n) + " " + unit + "s"
	}
	switch {
	case d >= 47*time.Hour:
		return plural(int((d+12*time.Hour)/(24*time.Hour)), "day")
	case d >= 55*time.Minute:
		return plural(int((d+30*time.Minute)/time.Hour), "hour")
	case d >= time.Minute:
		return plural(int((d+30*time.Second)/time.Minute), "minute")
	}
	return "1 minute"
}
