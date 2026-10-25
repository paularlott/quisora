package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// The shortest password accepted is limits.password_min_length: 15 by default (NIST SP 800-63B rev 4, where a
// password may be the only factor), lower where the operator sets it (development: task run-server uses 10).
func TestPasswordMinLength(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "len", model.RoleUser)
	if got := e.svc.Cfg.Limits.PasswordMinLength; got != 15 {
		t.Fatalf("default %d", got)
	}
	if err := e.svc.CheckPassword(e.ctx, u, "fourteen chars"); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("14 characters accepted by default: %v", err)
	}
	if err := e.svc.CheckPassword(e.ctx, u, "violet maple ox"); err != nil {
		t.Fatalf("15 characters refused: %v", err)
	}
	e.svc.Cfg.Limits.PasswordMinLength = 10
	if err := e.svc.CheckPassword(e.ctx, u, "violet oak"); err != nil {
		t.Fatalf("10 characters refused with the minimum at 10: %v", err)
	}
}
