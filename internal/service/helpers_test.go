package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// env is a service over a memory store with the primary org bootstrapped.
type env struct {
	t       testing.TB
	ctx     context.Context
	svc     *service.Service
	primary *model.Org
	super   *model.User
	seq     int
}

func newEnv(t testing.TB) *env {
	t.Helper()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 4
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(cfg, st, sealer)
	ctx := context.Background()
	super, _, err := svc.Bootstrap(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	primary, err := svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, ctx: ctx, svc: svc, primary: primary, super: super}
}

func ptr[T any](v T) *T { return &v }

func (e *env) org(name string) *model.Org {
	e.t.Helper()
	o, err := e.svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: &name})
	if err != nil {
		e.t.Fatalf("create org %s: %v", name, err)
	}
	return o
}

// user creates a user directly as the system actor (primary-org super admins included).
func (e *env) user(orgID, username string, role model.Role) *model.User {
	e.t.Helper()
	in := service.UserInput{Username: &username, GivenName: ptr(username), Role: &role, Email: ptr(username + "@example.com")}
	u, err := e.svc.CreateUser(e.ctx, service.System, orgID, in)
	if err != nil {
		e.t.Fatalf("create user %s: %v", username, err)
	}
	return u
}

func (e *env) next(prefix string) string {
	e.seq++
	return prefix + string(rune('a'+e.seq%26)) + itoa(e.seq)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func actor(u *model.User) *service.Actor { return service.ActorForUser(u, "127.0.0.1") }

func isErr(err, target error) bool { return errors.Is(err, target) }

// outcome classifies an error for matrix tests.
func outcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, service.ErrForbidden):
		return "forbidden"
	case errors.Is(err, service.ErrNotFound):
		return "notfound"
	case errors.Is(err, service.ErrLastAdmin):
		return "lastadmin"
	case errors.Is(err, service.ErrInvalid):
		return "invalid"
	case errors.Is(err, service.ErrConflict):
		return "conflict"
	case errors.Is(err, service.ErrStale):
		return "stale"
	}
	return "other:" + err.Error()
}
