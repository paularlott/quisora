package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Revoking sessions through the service (admin "sign out everywhere", disabling a user) must reach the relying
// party's back-channel endpoint, not only RP-initiated logout.
func TestBackchannelOnServiceRevocation(t *testing.T) {
	for name, revoke := range map[string]func(h *harness){
		"revoke sessions": func(h *harness) {
			if err := h.env.Svc.RevokeSessions(context.Background(), service.System, h.user.ID); err != nil {
				t.Fatal(err)
			}
		},
		"disable user": func(h *harness) {
			f := false
			if _, err := h.env.Svc.UpdateUser(context.Background(), service.System, h.user.ID, service.UserInput{Active: &f}); err != nil {
				t.Fatal(err)
			}
		},
		"session delete": func(h *harness) {
			list, _ := h.env.Svc.Sessions.All(context.Background(), h.user.ID)
			for _, s := range list {
				_ = h.env.Server.Sessions.Delete(context.Background(), s.ID)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			rp := newRP()
			defer rp.Close()
			h := setup(t, nil)
			cl, sec := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
			c, _ := h.session(h.user)
			v, ch := pkce()
			code := h.getCode(c, cl, ch, nil)
			if r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cl, sec); r.status != 200 {
				t.Fatal(r.m)
			}
			revoke(h)
			h.p.Wait()
			select {
			case <-rp.got:
			default:
				t.Fatal("no back-channel logout token delivered")
			}
		})
	}
}

// Removing one application's access from the account page signs the user out of that application (back-channel
// logout) and kills its refresh token at once; other applications are not contacted.
func TestBackchannelOnAppAccessRemoved(t *testing.T) {
	rp, other := newRP(), newRP()
	defer rp.Close()
	defer other.Close()
	h := setup(t, nil)
	cl, sec := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	cl2, sec2 := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(other.URL) })
	c, _ := h.session(h.user)
	refresh := map[string]string{}
	for _, x := range []struct {
		cl  *model.Client
		sec string
	}{{cl, sec}, {cl2, sec2}} {
		v, ch := pkce()
		code := h.getCode(c, x.cl, ch, url.Values{"scope": {"openid offline_access"}})
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, x.cl, x.sec)
		if r.status != 200 || r.str("refresh_token") == "" {
			t.Fatal(r.m)
		}
		refresh[x.cl.ID] = r.str("refresh_token")
	}
	// warm the grant cache: a cached "alive" must not outlive the removal
	if r := h.refreshWith(cl, sec, refresh[cl.ID]); r.status != 200 {
		t.Fatal(r.m)
	}
	refresh[cl.ID] = h.refreshWith(cl, sec, refresh[cl.ID]).str("refresh_token")

	n, err := h.env.Svc.RevokeAppAccess(context.Background(), h.user.ID, cl.ID)
	if err != nil || n == 0 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	h.p.Wait()
	select {
	case tok := <-rp.got:
		if claimsOf(t, tok)["sub"] != h.user.ID {
			t.Fatalf("logout token for the wrong user: %s", tok)
		}
	default:
		t.Fatal("no back-channel logout token delivered")
	}
	select {
	case <-other.got:
		t.Fatal("another application was signed out")
	default:
	}
	if r := h.refreshWith(cl, sec, refresh[cl.ID]); r.status == 200 {
		t.Fatal("refresh token still works after access was removed")
	}
	if r := h.refreshWith(cl2, sec2, refresh[cl2.ID]); r.status != 200 {
		t.Fatalf("the other application's refresh token stopped working: %v", r.m)
	}
	if n, _ := h.env.Svc.RevokeAppAccess(context.Background(), h.user.ID, cl.ID); n != 0 {
		t.Fatalf("second removal found %d grants", n)
	}
}
