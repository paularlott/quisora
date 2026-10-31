package sshcli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/sshcli/sshclitest"
	"golang.org/x/crypto/ssh"
)

func TestCheckKRL(t *testing.T) {
	empty := sshclitest.EmptyKRL()
	if err := checkKRL(empty); err != nil {
		t.Fatalf("an empty KRL: %v", err)
	}
	// a KRL with a certificates section
	caKey, _, _ := ed25519.GenerateKey(rand.Reader)
	caPub, _ := ssh.NewPublicKey(caKey)
	krl := sshca.NewKRL(1, time.Now(), "")
	krl.Add(caPub, 5, 9)
	withSection := krl.Marshal()
	if err := checkKRL(withSection); err != nil {
		t.Errorf("a KRL with a section: %v", err)
	}
	for n := range len(empty) {
		if checkKRL(empty[:n]) == nil {
			t.Errorf("a KRL cut at %d bytes was accepted", n)
		}
	}
	if checkKRL(withSection[:len(withSection)-1]) == nil {
		t.Error("a KRL with a cut section was accepted")
	}
	if checkKRL(append(append([]byte(nil), empty...), 1, 0xff, 0xff, 0xff, 0xff)) == nil {
		t.Error("a section longer than the data was accepted")
	}
	badMagic := append([]byte(nil), empty...)
	badMagic[0] = 'X'
	badVersion := append([]byte(nil), empty...)
	binary.BigEndian.PutUint32(badVersion[8:], 2)
	for name, b := range map[string][]byte{"bad magic": badMagic, "format version 2": badVersion, "html": []byte("<html><body>502 Bad Gateway</body></html>"), "empty": nil} {
		if checkKRL(b) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A KRL made by OpenSSH's own ssh-keygen passes.
func TestCheckKRLFromSSHKeygen(t *testing.T) {
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	caFile, spec, krl := filepath.Join(dir, "ca.pub"), filepath.Join(dir, "spec"), filepath.Join(dir, "out.krl")
	_ = os.WriteFile(caFile, ssh.MarshalAuthorizedKey(sp), 0o644)
	_ = os.WriteFile(spec, []byte("serial: 5\nserial: 9-12\nid: someone@example\n"), 0o644)
	if out, err := exec.Command(bin, "-k", "-f", krl, "-s", caFile, spec).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -k: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(krl)
	if err := checkKRL(b); err != nil {
		t.Fatalf("a KRL of ssh-keygen: %v", err)
	}
}
