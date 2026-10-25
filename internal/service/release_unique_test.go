package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A unique value (a provider link's subject, a passkey's credential id) held by a record that counts for nothing is
// freed at once, not left to the orphan sweep: deleting an account never blocks linking that provider identity, or
// registering that authenticator, to another. A record that counts keeps its value.
func TestReleaseUniqueFreesOnlyDeadHolders(t *testing.T) {
	c := newCast(t)
	prov, err := c.svc.CreateProvider(c.ctx, service.System, c.a.ID, goodProvider("sso"))
	if err != nil {
		t.Fatal(err)
	}
	gone, next := c.user(c.a.ID, "gone", model.RoleUser), c.user(c.a.ID, "next", model.RoleUser)
	key := model.IdentityKey(prov.ID, "sub-1")
	if err := c.svc.Identities.Create(c.ctx, model.NewIdentity(gone, prov, "sub-1", "", "admin")); err != nil {
		t.Fatal(err)
	}
	cred := []byte("authenticator-1")
	if err := c.svc.Passkeys.Create(c.ctx, &model.Passkey{UserID: gone.ID, OrgID: c.a.ID, CredentialID: cred, Name: "k"}); err != nil {
		t.Fatal(err)
	}
	// A recent passkey of an epoch the account has not committed (an invitation in flight) counts as live.
	pending := []byte("authenticator-2")
	if err := c.svc.Passkeys.Create(c.ctx, &model.Passkey{UserID: next.ID, OrgID: c.a.ID, CredentialID: pending, Name: "k", Epoch: 99}); err != nil {
		t.Fatal(err)
	}

	for name, v := range map[string]struct {
		kind  model.Kind
		value string
	}{"live link": {model.KindIdentity, key}, "live passkey": {model.KindPasskey, model.PasskeyCredentialKey(cred)},
		"in-flight passkey": {model.KindPasskey, model.PasskeyCredentialKey(pending)}} {
		if freed, err := c.svc.ReleaseUnique(c.ctx, v.kind, v.value); err != nil || freed {
			t.Errorf("%s released: %v %v", name, freed, err)
		}
	}
	if err := c.svc.DeleteUser(c.ctx, actor(c.aAdmin), gone.ID); err != nil {
		t.Fatal(err)
	}
	if freed, err := c.svc.ReleaseUnique(c.ctx, model.KindIdentity, key); err != nil || !freed {
		t.Fatalf("link of a deleted user kept: %v %v", freed, err)
	}
	if err := c.svc.Identities.Create(c.ctx, model.NewIdentity(next, prov, "sub-1", "", "admin")); err != nil {
		t.Fatalf("relink: %v", err)
	}
	if freed, err := c.svc.ReleaseUnique(c.ctx, model.KindPasskey, model.PasskeyCredentialKey(cred)); err != nil || !freed {
		t.Fatalf("passkey of a deleted user kept: %v %v", freed, err)
	}
	if err := c.svc.Passkeys.Create(c.ctx, &model.Passkey{UserID: next.ID, OrgID: c.a.ID, CredentialID: cred, Name: "k"}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if freed, err := c.svc.ReleaseUnique(c.ctx, model.KindPasskey, "nothing-holds-this"); err != nil || !freed {
		t.Errorf("an unheld value: %v %v", freed, err)
	}
}
