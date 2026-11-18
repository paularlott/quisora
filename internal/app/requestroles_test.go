package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// menuRolesFollow checks that a group changed on one node shows in the account menu of another (who asks for and
// approves access: service.AccessRequestRoles) within within. The other node's view is warm first: kept an hour, it
// changes that fast only when the change reaches the node's change hook (a replicated record), or, on a node never
// told of other nodes' writes (a shared database without cluster.notify), as its short cache expires.
func menuRolesFollow(t *testing.T, writer, reader *App, within time.Duration) {
	t.Helper()
	ctx := context.Background()
	org, err := writer.Svc.PrimaryOrgID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	name := "menu-" + time.Now().Format("150405.000000")
	var u *model.User
	retryWhileUnavailable(t, func() (err error) {
		u, err = writer.Svc.CreateUser(ctx, service.System, org, service.UserInput{Username: &name, GivenName: ptrTo("Menu"), Email: ptrTo(name + "@example.com")})
		return err
	})
	var g *model.Group
	retryWhileUnavailable(t, func() (err error) {
		g, err = writer.Svc.CreateGroupWithMembers(ctx, service.System, org, service.GroupInput{DisplayName: ptrTo("Menu " + name)}, []string{u.ID})
		return err
	})
	// the reader has the user and the group, and its view of the user's roles is warm: neither
	deadline := time.Now().Add(30 * time.Second)
	var seen *model.User
	for {
		if seen, err = reader.Svc.Users.Get(ctx, u.ID); err == nil {
			if _, err = reader.Svc.Groups.Get(ctx, g.ID); err == nil {
				if asks, approves := reader.Svc.AccessRequestRoles(ctx, seen); !asks && !approves {
					break
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the reader never had the user and the group without roles: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	retryWhileUnavailable(t, func() error {
		_, err := writer.Svc.UpdateGroup(ctx, service.System, g.ID, service.GroupInput{ApprovesRequests: ptrTo(true)})
		return err
	})
	start := time.Now()
	for {
		if _, approves := reader.Svc.AccessRequestRoles(ctx, seen); approves {
			t.Logf("the other node's menu followed the group change in %v", time.Since(start).Round(time.Millisecond))
			return
		}
		if time.Since(start) > within {
			t.Fatalf("the other node's menu did not follow the group change within %v", within)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// retryWhileUnavailable runs write until it is not refused as unavailable (a cluster still settling: a partition's
// owner not heard from lately), as a client told to try again shortly would, for up to 20 seconds.
func retryWhileUnavailable(t *testing.T, write func() error) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		err := write()
		if err == nil {
			return
		}
		if !errors.Is(err, service.ErrUnavailable) && !errors.Is(err, store.ErrUnavailable) || time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
