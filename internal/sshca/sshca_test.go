package sshca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newCA(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	pub, priv, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ParseCA(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := AuthorizedKey(signer.PublicKey()); got != pub {
		t.Fatalf("public key %q, signer's %q", pub, got)
	}
	return signer, pub
}

func userKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k, AuthorizedKey(k) + " me@laptop"
}

func TestCAKeyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") || strings.ContainsAny(pub, " \n") && strings.Count(pub, " ") != 1 {
		t.Errorf("public key %q", pub)
	}
	if !strings.Contains(string(priv), "BEGIN OPENSSH PRIVATE KEY") {
		t.Errorf("private key is not an OpenSSH PEM: %.40q", priv)
	}
	s, err := ParseCA(priv)
	if err != nil {
		t.Fatal(err)
	}
	if AuthorizedKey(s.PublicKey()) != pub {
		t.Error("parsed key is another key")
	}
	// the raw seed form
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s2, err := ParseCA(key.Seed())
	if err != nil || s2.PublicKey().Type() != "ssh-ed25519" {
		t.Errorf("seed: %v", err)
	}
	for _, bad := range [][]byte{nil, []byte("nonsense"), priv[:len(priv)/2]} {
		if _, err := ParseCA(bad); err == nil {
			t.Errorf("ParseCA(%.20q) accepted", bad)
		}
	}
	// an RSA key is not a CA key
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	blk, _ := ssh.MarshalPrivateKey(rk, "")
	if _, err := ParseCA(pem.EncodeToMemory(blk)); err == nil {
		t.Error("RSA CA key accepted")
	}
}

func TestParsePublicKey(t *testing.T) {
	_, ed := userKey(t)
	ec := func(c elliptic.Curve) string {
		k, _ := ecdsa.GenerateKey(c, rand.Reader)
		p, _ := ssh.NewPublicKey(&k.PublicKey)
		return AuthorizedKey(p)
	}
	rsaKey := func(bits int) string {
		k, _ := rsa.GenerateKey(rand.Reader, bits)
		p, _ := ssh.NewPublicKey(&k.PublicKey)
		return AuthorizedKey(p)
	}
	ca, _ := newCA(t)
	cert, certLine, err := SignCert(ca, CertSpec{Key: ca.PublicKey(), Serial: 1, KeyID: "x", Principals: []string{"a"},
		ValidAfter: time.Now(), ValidBefore: time.Now().Add(time.Hour)})
	if err != nil || cert == nil {
		t.Fatal(err)
	}
	skEd := skLine(t, ssh.KeyAlgoSKED25519, func() []byte {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		return wireStrings([]byte(ssh.KeyAlgoSKED25519), pub, []byte("ssh:"))
	}())
	skEc := skLine(t, ssh.KeyAlgoSKECDSA256, func() []byte {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		point := elliptic.Marshal(elliptic.P256(), k.X, k.Y) //nolint:staticcheck // the wire form of a point
		return wireStrings([]byte(ssh.KeyAlgoSKECDSA256), []byte("nistp256"), point, []byte("ssh:"))
	}())
	cases := []struct {
		name, line string
		want       error // nil: accepted
	}{
		{"ed25519", ed, nil},
		{"ed25519 with surrounding space", "  " + ed + "\n", nil},
		{"ecdsa p256", ec(elliptic.P256()), nil},
		{"ecdsa p384", ec(elliptic.P384()), nil},
		{"ecdsa p521", ec(elliptic.P521()), nil},
		{"rsa 2048", rsaKey(2048), nil},
		{"rsa 3072", rsaKey(3072), nil},
		{"sk ed25519", skEd, nil},
		{"sk ecdsa", skEc, nil},
		{"rsa 1024", rsaKey(1024), ErrWeakRSA},
		{"certificate", certLine, ErrCertificate},
		{"dsa", "ssh-dss AAAAB3NzaC1kc3MAAACBAOmZlKVsMdUt", ErrNotAKey},
		{"empty", "", ErrNotAKey},
		{"junk", "hello world", ErrNotAKey},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----", ErrNotAKey},
		{"two lines", ed + "\n" + ed, nil}, // checked below: not nil
		{"options", `no-pty ` + ed, nil},   // checked below: not nil
	}
	for _, c := range cases {
		key, _, err := ParsePublicKey(c.line)
		switch c.name {
		case "two lines", "options":
			if err == nil {
				t.Errorf("%s accepted", c.name)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: error %v, want %v", c.name, err, c.want)
		}
		if err == nil && key == nil {
			t.Errorf("%s: no key", c.name)
		}
	}
	if _, comment, err := ParsePublicKey(ed); err != nil || comment != "me@laptop" {
		t.Errorf("comment %q (%v)", comment, err)
	}
	if _, _, err := ParsePublicKey(strings.Repeat("a", maxKeyLine+1)); err == nil {
		t.Error("an oversized line was accepted")
	}
}

func TestFingerprint(t *testing.T) {
	k, line := userKey(t)
	parsed, _, err := ParsePublicKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if f := Fingerprint(parsed); f != Fingerprint(k) || !strings.HasPrefix(f, "SHA256:") {
		t.Errorf("fingerprint %q", f)
	}
}

func TestSourceAddresses(t *testing.T) {
	got, err := ValidSourceAddresses([]string{" 10.0.0.1 ", "192.168.1.7/24", "2001:db8::1", "10.0.0.1", ""})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.1", "192.168.1.0/24", "2001:db8::1"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for _, bad := range []string{"example.com", "10.0.0.256", "10.0.0.0/33", "fe80::1%eth0", "*"} {
		if _, err := ValidSourceAddresses([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHostMatching(t *testing.T) {
	pats := []string{"*.example.com", "db1.internal"}
	for name, want := range map[string]bool{
		"web.example.com": true, "A.B.Example.COM": true, "db1.internal": true, "db2.internal": false,
		"example.com": false, "web.example.org": false, "evil.com/x.example.com": false,
	} {
		if got := MatchHost(pats, name); got != want {
			t.Errorf("MatchHost(%q) = %v, want %v", name, got, want)
		}
	}
	if MatchHost(nil, "a") {
		t.Error("no patterns matched")
	}
	for name, want := range map[string]bool{"a.example.com": true, "10.0.0.5": true, "::1": true, "": false, "A.com": false,
		"*.example.com": false, "a b": false, "a/b": false} {
		if ValidHostName(name) != want {
			t.Errorf("ValidHostName(%q) = %v", name, !want)
		}
	}
	for p, want := range map[string]bool{"*.example.com": true, "db?.internal": true, "[ab].x": false, "": false, "A.com": false} {
		if ValidHostPattern(p) != want {
			t.Errorf("ValidHostPattern(%q) = %v", p, !want)
		}
	}
}

func TestSignUserCertificate(t *testing.T) {
	ca, _ := newCA(t)
	key, _ := userKey(t)
	now := time.Now().Truncate(time.Second)
	serial, err := RandomSerial()
	if err != nil || serial == 0 {
		t.Fatal(serial, err)
	}
	_, line, err := SignCert(ca, CertSpec{
		Key: key, Serial: serial, KeyID: "paul@acme/u_1", Principals: []string{"ops", "paul", "ops"},
		ValidAfter: now.Add(-5 * time.Minute), ValidBefore: now.Add(8 * time.Hour),
		Extensions:      UserExtensions(true, true, false, false, false),
		SourceAddresses: []string{"10.0.0.0/8", "192.0.2.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "ssh-ed25519-cert-v01@openssh.com ") || strings.Contains(line, "\n") {
		t.Fatalf("line %.60q", line)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	pc, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed %T", parsed)
	}
	if pc.Serial != serial || pc.KeyId != "paul@acme/u_1" || pc.CertType != ssh.UserCert {
		t.Errorf("certificate %+v", pc)
	}
	if !slices.Equal(pc.ValidPrincipals, []string{"ops", "paul"}) {
		t.Errorf("principals %v", pc.ValidPrincipals)
	}
	if pc.ValidAfter != uint64(now.Add(-5*time.Minute).Unix()) || pc.ValidBefore != uint64(now.Add(8*time.Hour).Unix()) {
		t.Errorf("validity %d-%d", pc.ValidAfter, pc.ValidBefore)
	}
	if got := pc.CriticalOptions["source-address"]; got != "10.0.0.0/8,192.0.2.1" {
		t.Errorf("source-address %q", got)
	}
	if _, ok := pc.Extensions["permit-pty"]; !ok {
		t.Error("no permit-pty")
	}
	if _, ok := pc.Extensions["permit-port-forwarding"]; ok {
		t.Error("permit-port-forwarding present")
	}
	// the CA verifies it, as sshd does
	checker := &ssh.CertChecker{SupportedCriticalOptions: []string{"source-address"},
		IsUserAuthority: func(a ssh.PublicKey) bool { return string(a.Marshal()) == string(ca.PublicKey().Marshal()) }}
	if err := checker.CheckCert("paul", pc); err != nil {
		t.Errorf("CheckCert paul: %v", err)
	}
	if err := checker.CheckCert("root", pc); err == nil {
		t.Error("a principal the certificate does not carry was accepted")
	}
	if !keysEqual(pc.Key, key) || pc.SignatureKey == nil || !keysEqual(pc.SignatureKey, ca.PublicKey()) {
		t.Error("keys")
	}
}

func TestSignHostCertificate(t *testing.T) {
	ca, _ := newCA(t)
	key, _ := userKey(t)
	now := time.Now()
	cert, _, err := SignCert(ca, CertSpec{Host: true, Key: key, Serial: 7, KeyID: "host:db1@acme", Principals: []string{"db1.example.com"},
		ValidAfter: now.Add(-5 * time.Minute), ValidBefore: now.Add(24 * time.Hour),
		Extensions: UserExtensions(true, true, true, true, true), SourceAddresses: []string{"10.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.HostCert {
		t.Error("not a host certificate")
	}
	if len(cert.Extensions) != 0 || len(cert.CriticalOptions) != 0 {
		t.Errorf("host certificate carries user options: %v %v", cert.Extensions, cert.CriticalOptions)
	}
	checker := &ssh.CertChecker{IsHostAuthority: func(a ssh.PublicKey, _ string) bool { return keysEqual(a, ca.PublicKey()) }}
	if err := checker.CheckHostKey("db1.example.com:22", nil, cert); err != nil {
		t.Errorf("CheckHostKey: %v", err)
	}
}

func TestSignCertRefusals(t *testing.T) {
	ca, _ := newCA(t)
	key, _ := userKey(t)
	now := time.Now()
	ok := CertSpec{Key: key, Serial: 1, KeyID: "k", Principals: []string{"a"}, ValidAfter: now, ValidBefore: now.Add(time.Hour)}
	if _, _, err := SignCert(ca, ok); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*CertSpec){
		"no key":    func(s *CertSpec) { s.Key = nil },
		"serial 0":  func(s *CertSpec) { s.Serial = 0 },
		"no time":   func(s *CertSpec) { s.ValidBefore = s.ValidAfter },
		"backwards": func(s *CertSpec) { s.ValidBefore = s.ValidAfter.Add(-time.Hour) },
	} {
		s := ok
		mut(&s)
		if _, _, err := SignCert(ca, s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKRLRoundTrip(t *testing.T) {
	ca1, _ := newCA(t)
	ca2, _ := newCA(t)
	ca3, _ := newCA(t)
	k := NewKRL(42, time.Unix(1_700_000_000, 0), "quisora acme/prod")
	k.Add(ca1.PublicKey(), 9, 3, 3, 1<<63)
	k.Add(ca2.PublicKey()) // a CA with nothing revoked
	k.Add(ca1.PublicKey(), 5)
	data := k.Marshal()
	got, err := ParseKRL(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 42 || got.Generated.Unix() != 1_700_000_000 || got.Comment != "quisora acme/prod" || len(got.CAs) != 2 {
		t.Fatalf("parsed %+v", got)
	}
	if !slices.Equal(got.CAs[0].Serials, []uint64{3, 5, 9, 1 << 63}) || len(got.CAs[1].Serials) != 0 {
		t.Errorf("serials %v / %v", got.CAs[0].Serials, got.CAs[1].Serials)
	}
	for _, c := range []struct {
		ca     ssh.Signer
		serial uint64
		want   bool
	}{{ca1, 3, true}, {ca1, 1 << 63, true}, {ca1, 4, false}, {ca2, 3, false}, {ca3, 3, false}} {
		if got.Revoked(c.ca.PublicKey(), c.serial, "") != c.want {
			t.Errorf("Revoked(%d) = %v", c.serial, !c.want)
		}
	}
	// a CA key revoked outright revokes whatever it signed, and survives the round trip
	k.RevokeKey(ca3.PublicKey())
	k.RevokeKey(ca3.PublicKey()) // once
	got, err = ParseKRL(k.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Keys) != 1 || !got.KeyRevoked(ca3.PublicKey()) || got.KeyRevoked(ca2.PublicKey()) {
		t.Errorf("revoked keys %d, ca3 %v, ca2 %v", len(got.Keys), got.KeyRevoked(ca3.PublicKey()), got.KeyRevoked(ca2.PublicKey()))
	}
	if !got.Revoked(ca3.PublicKey(), 3, "") || got.Revoked(ca2.PublicKey(), 3, "") {
		t.Error("a certificate of a revoked CA key is not revoked, or another CA's is")
	}
	// an empty list is valid
	empty, err := ParseKRL(NewKRL(1, time.Now(), "").Marshal())
	if err != nil || len(empty.CAs) != 0 {
		t.Errorf("empty list: %v %+v", err, empty)
	}
	// the magic and format are the documented ones
	if string(data[:8]) != "SSHKRL\n\x00" || binary.BigEndian.Uint32(data[8:12]) != 1 {
		t.Errorf("header % x", data[:12])
	}
}

func TestParseKRLRefusals(t *testing.T) {
	ca, _ := newCA(t)
	k := NewKRL(1, time.Now(), "c")
	k.Add(ca.PublicKey(), 1, 2, 3)
	good := k.Marshal()
	if _, err := ParseKRL(good); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]byte{
		"empty":           nil,
		"bad magic":       append([]byte("NOTAKRL\n"), good[8:]...),
		"future format":   func() []byte { b := slices.Clone(good); b[11] = 9; return b }(),
		"unknown section": append(slices.Clone(good), 0x7f, 0, 0, 0, 0),
	}
	for n := range good {
		if n < len(good)-1 { // every strict prefix is truncated somewhere (the cut after the header may still end between sections)
			bad["prefix "+string(rune('a'+n%26))+string(rune('0'+n/26))] = good[:n]
		}
	}
	for name, b := range bad {
		_, err := ParseKRL(b)
		if err == nil {
			// a prefix that ends exactly between two sections is a shorter, valid list: only that is allowed
			if !strings.HasPrefix(name, "prefix") {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if !errors.Is(err, ErrKRL) {
			t.Errorf("%s: error %v is not ErrKRL", name, err)
		}
	}
}

// The other certificate subsections, as ssh-keygen writes them.
func TestParseKRLRangesAndBitmaps(t *testing.T) {
	ca, _ := newCA(t)
	var sect []byte
	sect = appendString(sect, ca.PublicKey().Marshal())
	sect = appendString(sect, nil)
	rng := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 100), 200)
	sect = append(sect, krlCertSerialRange)
	sect = appendString(sect, rng)
	bm := binary.BigEndian.AppendUint64(nil, 1000)
	bm = appendString(bm, []byte{0x05}) // bits 0 and 2: serials 1000 and 1002
	sect = append(sect, krlCertSerialBitmap)
	sect = appendString(sect, bm)
	sect = append(sect, krlCertKeyID)
	sect = appendString(sect, appendString(nil, []byte("old@key")))
	data := NewKRL(1, time.Unix(0, 0), "").Marshal()
	data = append(data, krlSectionCertificates)
	data = appendString(data, sect)
	k, err := ParseKRL(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		serial uint64
		id     string
		want   bool
	}{{100, "", true}, {150, "", true}, {200, "", true}, {201, "", false}, {1000, "", true}, {1001, "", false}, {1002, "", true}, {5, "old@key", true}} {
		if k.Revoked(ca.PublicKey(), c.serial, c.id) != c.want {
			t.Errorf("Revoked(%d,%q) = %v", c.serial, c.id, !c.want)
		}
	}
}

// ---- OpenSSH itself ----

func sshKeygen(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not on PATH")
	}
	return p
}

func run(t *testing.T, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("%s %v: %v", name, args, err)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

func TestSSHKeygenReadsOurCertificates(t *testing.T) {
	kg := sshKeygen(t)
	ca, _ := newCA(t)
	key, _ := userKey(t)
	now := time.Now()
	dir := t.TempDir()

	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	_, line, err := SignCert(ca, CertSpec{Key: key, Serial: 12345, KeyID: "paul@acme/u_1", Principals: []string{"paul", "ops"},
		ValidAfter: now.Add(-5 * time.Minute), ValidBefore: now.Add(time.Hour),
		Extensions: UserExtensions(true, true, false, true, false), SourceAddresses: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	out, code := run(t, kg, "-L", "-f", write("user-cert.pub", line))
	if code != 0 {
		t.Fatalf("ssh-keygen -L: %s", out)
	}
	for _, want := range []string{"Type: ssh-ed25519-cert-v01@openssh.com user certificate", "Serial: 12345",
		`Key ID: "paul@acme/u_1"`, "Signing CA: ED25519 SHA256:", "paul", "ops", "source-address 10.0.0.0/8",
		"permit-pty", "permit-user-rc", "permit-agent-forwarding"} {
		if !strings.Contains(out, want) {
			t.Errorf("ssh-keygen -L output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "permit-port-forwarding") || strings.Contains(out, "permit-X11-forwarding") {
		t.Errorf("extensions that were not granted are listed:\n%s", out)
	}

	_, hline, err := SignCert(ca, CertSpec{Host: true, Key: key, Serial: 99, KeyID: "host:db1@acme", Principals: []string{"db1.example.com"},
		ValidAfter: now.Add(-5 * time.Minute), ValidBefore: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	out, code = run(t, kg, "-L", "-f", write("host-cert.pub", hline))
	if code != 0 || !strings.Contains(out, "host certificate") || !strings.Contains(out, "db1.example.com") {
		t.Errorf("host certificate (%d): %s", code, out)
	}
}

func TestSSHKeygenChecksOurKRL(t *testing.T) {
	kg := sshKeygen(t)
	ca, _ := newCA(t)
	otherCA, _ := newCA(t)
	key, _ := userKey(t)
	now := time.Now()
	dir := t.TempDir()
	cert := func(name string, signer ssh.Signer, serial uint64) string {
		_, line, err := SignCert(signer, CertSpec{Key: key, Serial: serial, KeyID: name, Principals: []string{"paul"},
			ValidAfter: now.Add(-time.Minute), ValidBefore: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name+"-cert.pub")
		if err := os.WriteFile(p, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	revoked := cert("revoked", ca, 1000)
	alsoRevoked := cert("also", ca, 1001<<20+7)
	fine := cert("fine", ca, 2000)
	otherCAWithSameSerial := cert("other", otherCA, 1000)

	k := NewKRL(uint64(now.Unix()), now, "quisora acme/prod")
	k.Add(ca.PublicKey(), 1000, 1001<<20+7, 5)
	k.Add(otherCA.PublicKey()) // listed, nothing revoked
	krl := filepath.Join(dir, "krl")
	if err := os.WriteFile(krl, k.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		path string
		want bool
	}{{"revoked", revoked, true}, {"also", alsoRevoked, true}, {"fine", fine, false}, {"other CA, same serial", otherCAWithSameSerial, false}} {
		out, code := run(t, kg, "-Q", "-f", krl, c.path)
		got := strings.Contains(out, "REVOKED") && code != 0
		if got != c.want {
			t.Errorf("%s: revoked=%v (exit %d): %s", c.name, got, code, out)
		}
		if !c.want && code != 0 {
			t.Errorf("%s: not revoked but ssh-keygen exited %d: %s", c.name, code, out)
		}
	}
	// a CA key revoked outright: whatever it signed is revoked, whatever the serial, and nothing else is
	byKey := NewKRL(uint64(now.Unix()), now, "quisora acme/prod")
	byKey.Add(ca.PublicKey(), 1000)
	byKey.RevokeKey(otherCA.PublicKey())
	keyKRL := filepath.Join(dir, "key.krl")
	if err := os.WriteFile(keyKRL, byKey.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		path string
		want bool
	}{{"signed by the revoked CA key", otherCAWithSameSerial, true}, {"another serial of it", cert("other2", otherCA, 77), true},
		{"listed serial", revoked, true}, {"fine", fine, false}} {
		out, code := run(t, kg, "-Q", "-f", keyKRL, c.path)
		if got := strings.Contains(out, "REVOKED") && code != 0; got != c.want {
			t.Errorf("revoked CA key: %s: revoked=%v (exit %d): %s", c.name, got, code, out)
		}
	}
	if parsed, err := ParseKRL(byKey.Marshal()); err != nil || !parsed.KeyRevoked(otherCA.PublicKey()) {
		t.Errorf("our list with a revoked key: %v", err)
	}
	// an empty list
	emptyKRL := filepath.Join(dir, "empty.krl")
	if err := os.WriteFile(emptyKRL, NewKRL(1, now, "").Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, kg, "-Q", "-f", emptyKRL, fine); code != 0 {
		t.Errorf("empty KRL: exit %d: %s", code, out)
	}
	// and OpenSSH's own list parses with ours (ssh-keygen -k writes ranges and bitmaps, and prefers the CA in a spec)
	caPub := filepath.Join(dir, "ca.pub")
	if err := os.WriteFile(caPub, []byte(AuthorizedKey(ca.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := filepath.Join(dir, "spec")
	if err := os.WriteFile(spec, []byte("serial: 10-20\nserial: 30\nserial: 40-42\nid: gone@key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(dir, "own.krl")
	if out, code := run(t, kg, "-k", "-f", own, "-s", caPub, spec); code != 0 {
		t.Fatalf("ssh-keygen -k: %s", out)
	}
	data, err := os.ReadFile(own)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKRL(data)
	if err != nil {
		t.Fatalf("ParseKRL of an ssh-keygen list: %v", err)
	}
	for _, c := range []struct {
		serial uint64
		id     string
		want   bool
	}{{10, "", true}, {15, "", true}, {20, "", true}, {21, "", false}, {30, "", true}, {41, "", true}, {43, "", false}, {1, "gone@key", true}} {
		if parsed.Revoked(ca.PublicKey(), c.serial, c.id) != c.want {
			t.Errorf("ssh-keygen's list: Revoked(%d,%q) = %v", c.serial, c.id, !c.want)
		}
	}
}

func keysEqual(a, b ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), b.Marshal()) }

// wireStrings is the SSH wire encoding of strings, one after the other.
func wireStrings(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = appendString(b, p)
	}
	return b
}

// skLine is the authorized_keys line of a security-key public key blob.
func skLine(t *testing.T, typ string, blob []byte) string {
	t.Helper()
	return typ + " " + base64.StdEncoding.EncodeToString(blob)
}
