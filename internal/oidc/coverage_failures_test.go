package oidc

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestCoverageRefreshUnavailableStates(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")

	// the user cannot be read
	users := h.env.Svc.Users.S
	h.env.Svc.Users.S = failReads{Store: users, kind: model.KindUser}
	h.p.users.clear()
	expectUnavailable(t, "user", h.refreshWith(cl, secret, rt))
	h.env.Svc.Users.S = users
	h.p.users.clear()

	if x := h.refreshWith(cl, secret, rt); x.status != 200 {
		t.Fatalf("once the stores answer: %v", x.m)
	}
}

func TestCoverageRefreshWriteFailures(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	good := h.env.Svc.Grants.S
	fresh := func() string { r, _ := h.login(cl, secret, nil); return r.str("refresh_token") }

	// this node cannot write: the client retries
	rt := fresh()
	h.env.Svc.Grants.S = casFail{Store: good, err: func() error { return store.ErrNotWritable }}
	expectUnavailable(t, "not writable", h.refreshWith(cl, secret, rt))
	// any other write error is a server error
	h.env.Svc.Grants.S = casFail{Store: good, err: func() error { return errors.New("disk full") }}
	if x := h.refreshWith(cl, secret, rt); x.status != 500 || x.m["error"] != "server_error" {
		t.Fatalf("%d %v", x.status, x.m)
	}
	h.env.Svc.Grants.S = good

	// stale writes that never end: the refresh gives up after three attempts
	rt = fresh()
	var n atomic.Int32
	h.env.Svc.Grants.S = casFail{Store: good, err: func() error { n.Add(1); return store.ErrStale }}
	tokenErr(t, h.refreshWith(cl, secret, rt), 400, "invalid_grant")
	if n.Load() != 3 {
		t.Fatalf("attempts: %d", n.Load())
	}
	h.env.Svc.Grants.S = good

	// stale because the grant was revoked meanwhile
	rt = fresh()
	gid := strings.SplitN(rt, ".", 2)[0]
	var once atomic.Bool
	h.env.Svc.Grants.S = casFail{Store: good, err: func() error {
		if once.CompareAndSwap(false, true) {
			_ = h.env.Svc.Grants.Delete(context.Background(), gid) // via the failing store: Put is not intercepted
		}
		return store.ErrStale
	}}
	tokenErr(t, h.refreshWith(cl, secret, rt), 400, "invalid_grant")
	h.env.Svc.Grants.S = good

	// stale because another presentation of the same token won: the family ends
	rt = fresh()
	gid = strings.SplitN(rt, ".", 2)[0]
	once.Store(false)
	h.env.Svc.Grants.S = casFail{Store: good, err: func() error {
		if once.CompareAndSwap(false, true) {
			tbl := *h.env.Svc.Grants
			tbl.S = good
			g, err := tbl.Get(context.Background(), gid)
			if err != nil {
				t.Error(err)
				return store.ErrStale
			}
			g.Counter++
			if err := tbl.Update(context.Background(), g); err != nil {
				t.Error(err)
			}
		}
		return store.ErrStale
	}}
	tokenErr(t, h.refreshWith(cl, secret, rt), 400, "invalid_grant")
	h.env.Svc.Grants.S = good
	if got := h.auditActions("oauth.refresh.reuse"); len(got) != 1 || !strings.Contains(got[0].Detail["reason"], "twice at once") {
		t.Fatalf("audit: %+v", got)
	}

	// stale for an unrelated change (same counter): the refresh goes ahead on the new copy
	rt = fresh()
	gid = strings.SplitN(rt, ".", 2)[0]
	once.Store(false)
	h.env.Svc.Grants.S = casFail{Store: good, err: func() error {
		if once.CompareAndSwap(false, true) {
			tbl := *h.env.Svc.Grants
			tbl.S = good
			g, _ := tbl.Get(context.Background(), gid)
			_ = tbl.Update(context.Background(), g) // a rewrite without a counter change
			return store.ErrStale
		}
		return nil
	}}
	if x := h.refreshWith(cl, secret, rt); x.status != 200 {
		t.Fatalf("%d %v", x.status, x.m)
	}
	h.env.Svc.Grants.S = good
}

// casFail fails every grant compare-and-put with err() (nil from err lets the write through).
type casFail struct {
	store.Store
	err func() error
}

func (s casFail) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindGrant && !r.Deleted {
		if err := s.err(); err != nil {
			return err
		}
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

func TestCoverageCodeExchangeWriteFailure(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	good := h.env.Svc.Grants.S
	h.env.Svc.Grants.S = casFail{Store: good, err: func() error { return store.ErrNotWritable }}
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]}, "code_verifier": {v}}, cl, secret)
	expectUnavailable(t, "grant create", r)
	h.env.Svc.Grants.S = good
}
