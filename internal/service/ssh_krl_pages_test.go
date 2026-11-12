package service_test

import (
	"maps"
	"strconv"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// The revocation list is worked out a page of certificates at a time: a tenant with several pages of them gets every
// certificate revoked on its list, whichever page it is on, with its reason, and no other.
func TestSSHKRLAcrossPages(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	var users []*model.User
	var issued []*service.SSHIssued
	for i := range 600 {
		u := w.user(w.org.ID, "user"+strconv.Itoa(i), model.RoleUser)
		users = append(users, u)
		issued = append(issued, w.mustSign(u), w.mustSign(u))
	}
	want := map[uint64]string{}
	for i := 0; i < len(users); i += 97 {
		if _, err := w.svc.UpdateUser(w.ctx, service.System, users[i].ID, service.UserInput{Active: ptr(false)}); err != nil {
			t.Fatal(err)
		}
		want[issued[2*i].Cert.Serial], want[issued[2*i+1].Cert.Serial] = service.SSHReasonUserDisabled, service.SSHReasonUserDisabled
	}
	for i := 5; i < len(issued); i += 211 {
		if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, issued[i].Cert.ID); err != nil {
			t.Fatal(err)
		}
		want[issued[i].Cert.Serial] = service.SSHReasonRevoked
	}
	if got := w.revokedFor(); !maps.Equal(got, want) {
		t.Fatalf("revoked: %d certificates, want %d: %v", len(got), len(want), got)
	}
	krl := w.krlOf()
	ca := pubKeyOf(t, keysOf(t, w, model.SSHPurposeUser)[0])
	for _, c := range issued {
		if listed := krl.Revoked(ca, c.Cert.Serial, ""); listed != (want[c.Cert.Serial] != "") {
			t.Fatalf("certificate %d: listed %v, revoked for %q", c.Cert.Serial, listed, want[c.Cert.Serial])
		}
	}
}
