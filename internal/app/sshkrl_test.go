package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/store"
)

// A node keeps a tenant's SSH revocation list for a while, but every change of a certificate, a CA key or a tenant
// clears it through the change hook every node runs (here or replicated): a revocation written without the service
// telling this node's cache (as one made on another node is) is on the list at once.
func TestSSHKRLFollowsChanges(t *testing.T) {
	a, _, _ := startApp(t, "badgerdb")
	ctx := context.Background()
	name := "sshkrl"
	o, err := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: &name, DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	tn, err := a.Svc.CreateTenant(ctx, service.System, o.ID, service.TenantInput{Name: ptrTo("prod")})
	if err != nil {
		t.Fatal(err)
	}
	open := tn.Settings
	open.MembersOnly = false
	if _, err := a.Svc.UpdateTenant(ctx, service.System, tn.ID, service.TenantInput{Settings: &open}); err != nil {
		t.Fatal(err)
	}
	if tn, err = a.Svc.UpdateTenantSSH(ctx, service.System, tn.ID, service.SSHSettingsInput{Enabled: ptrTo(true)}); err != nil {
		t.Fatal(err)
	}
	u, err := a.Svc.CreateUser(ctx, service.System, o.ID, service.UserInput{Username: ptrTo("pat"), Email: ptrTo("pat@example.com"), GivenName: ptrTo("Pat")})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	stamp, err := a.Svc.SessionStamp(ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Svc.SignUserSSH(ctx, service.SSHUserRequest{User: u, TenantID: tn.ID, ClientID: tn.SSH.ClientID, PublicKey: sshca.AuthorizedKey(k),
		AMR: []string{"pwd", "otp"}, AuthTime: time.Now(), Via: "cli", SessionEpoch: u.SessionEpoch, Stamp: stamp})
	if err != nil {
		t.Fatal(err)
	}
	listed := func() bool {
		t.Helper()
		data, err := a.Svc.SSHKRL(ctx, tn.ID)
		if err != nil {
			t.Fatal(err)
		}
		krl, err := sshca.ParseKRL(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, ca := range krl.CAs {
			for _, s := range ca.Serials {
				if s == got.Cert.Serial {
					return true
				}
			}
		}
		return false
	}
	if listed() { // made, and kept for 30 seconds
		t.Fatal("listed before it was revoked")
	}
	c, err := a.Svc.SSHCerts.Get(ctx, got.Cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Revoked, c.RevokedAt, c.RevokedBy = true, time.Now(), "elsewhere"
	if err := a.Svc.SSHCerts.Update(ctx, c); err != nil { // not through the service: no InvalidateSSHKRL here
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !listed() {
		if time.Now().After(deadline) {
			t.Fatal("the node kept the list made before the revocation")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func ptrTo[T any](v T) *T { return &v }

// sshTenantIn makes organization name with a tenant "prod" that has SSH on.
func sshTenantIn(t *testing.T, a *App, name string) *model.Tenant {
	t.Helper()
	ctx := context.Background()
	o, err := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: &name, DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	tn, err := a.Svc.CreateTenant(ctx, service.System, o.ID, service.TenantInput{Name: ptrTo("prod")})
	if err != nil {
		t.Fatal(err)
	}
	if tn, err = a.Svc.UpdateTenantSSH(ctx, service.System, tn.ID, service.SSHSettingsInput{Enabled: ptrTo(true)}); err != nil {
		t.Fatal(err)
	}
	return tn
}

// The change hook drops only the lists a change can alter: not a tenant's for a certificate just signed (not revoked:
// on no list), and for a change that names no tenant (a notice of a node sharing the database carries no index fields)
// those of its organization, not every tenant's.
func TestSSHKRLInvalidationIsNarrow(t *testing.T) {
	a, _, _ := startApp(t, "badgerdb")
	ctx := context.Background()
	ta, tb := sshTenantIn(t, a, "krl-a"), sshTenantIn(t, a, "krl-b")
	version := func(tn *model.Tenant) uint64 {
		t.Helper()
		data, err := a.Svc.SSHKRL(ctx, tn.ID)
		if err != nil {
			t.Fatal(err)
		}
		k, err := sshca.ParseKRL(data)
		if err != nil {
			t.Fatal(err)
		}
		return k.Version
	}
	va, vb := version(ta), version(tb)
	time.Sleep(1100 * time.Millisecond) // a list made again has a later version (unix seconds)
	sshKRLChanged(a.Svc, &store.Record{Kind: model.KindSSHCert, ID: "c1", Scope: ta.OrgID,
		Fields: map[string]any{"tenant_id": ta.ID, "revoked": false}})
	if version(ta) != va {
		t.Error("a certificate that is not revoked dropped its tenant's list")
	}
	sshKRLChanged(a.Svc, &store.Record{Kind: model.KindSSHCert, ID: "c1", Scope: ta.OrgID}) // a notice: no fields
	if version(ta) == va {
		t.Error("a change notice in the tenant's organization kept its list")
	}
	if version(tb) != vb {
		t.Error("a change notice of another organization dropped the list")
	}
	sshKRLChanged(a.Svc, &store.Record{Kind: model.KindSSHCert, ID: "c2", Scope: tb.OrgID,
		Fields: map[string]any{"tenant_id": tb.ID, "revoked": true}})
	if version(tb) == vb {
		t.Error("a revocation kept its tenant's list")
	}
}
