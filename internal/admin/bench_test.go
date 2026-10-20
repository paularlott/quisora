package admin_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

func benchEnv(b *testing.B, users int) (*webtest.Env, *http.Client, string) {
	b.Helper()
	env := webtest.New(b, webtest.Options{Modules: func(*web.Server) []web.Module { return []web.Module{admin.New()} }})
	ctx := context.Background()
	org, err := env.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < users; i++ {
		_, err := env.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: ptr(fmt.Sprintf("user%05d", i)),
			Email: ptr(fmt.Sprintf("user%05d@x.example", i)), Role: ptr(model.RoleUser)})
		if err != nil {
			b.Fatal(err)
		}
	}
	c, _ := env.SessionAMR(env.Admin, []string{"pwd", "otp", "mfa"})
	return env, detach(c), org.ID
}

func get(b *testing.B, c *http.Client, url string) {
	res, err := c.Get(url)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		b.Fatalf("status %d", res.StatusCode)
	}
}

// Server-rendered page (layout + partials + page template), no data: the list itself loads through the API.
func BenchmarkPageRenderUsers(b *testing.B) {
	env, c, _ := benchEnv(b, 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		get(b, c, env.URL+"/admin/orgs/acme/users")
	}
}

// Clients are listed on their tenant's page (the old clients page redirects there).
func BenchmarkPageRenderTenantClients(b *testing.B) {
	env, c, _ := benchEnv(b, 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		get(b, c, env.URL+"/admin/orgs/acme/tenants/default")
	}
}

// One page of a 2,000-user organization: plain order, sorted, and searched.
func BenchmarkListUsersAPI(b *testing.B) {
	env, c, _ := benchEnv(b, 2000)
	for name, q := range map[string]string{"plain": "", "sorted": "&sort=email&desc=1", "search": "&q=user0199", "page80": "&offset=1975"} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				get(b, c, env.URL+"/api/orgs/acme/users?limit=25"+q)
			}
		})
	}
}
