package main

import (
	"context"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/login"
	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/web"
)

// demoMailHost turns email on for the demo (so the pages that offer email can be audited); nothing is delivered.
const demoMailHost = "mail.demo.invalid"

// extraModules registers modules owned by other packages so their pages can be audited together with the admin UI.
// The demo has email turned on with a transport that delivers nothing.
func extraModules(s *web.Server, adm *admin.Module) {
	m := mail.New(s.Cfg, logger.NewNullLogger())
	m.Transport = mail.TransportFunc(func(context.Context, mail.Message) error { return nil })
	m.SetService(s.Svc)
	adm.Mailer = demoMailer{m}
	s.Use(login.New(s, login.Options{Mail: m}))
}

type demoMailer struct{ m *mail.Mailer }

func (d demoMailer) SendInviteLink(ctx context.Context, org *model.Org, u *model.User, url string, expires time.Time) error {
	return d.m.SendInviteLink(ctx, u, org, url, expires)
}

func (d demoMailer) SendVerifyAddress(ctx context.Context, org *model.Org, u *model.User, address string) error {
	return d.m.SendVerifyAddress(ctx, u, org, address)
}
