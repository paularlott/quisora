package sshca

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// UserExtensions returns the OpenSSH extensions of a user certificate for the permissions it grants; extensions not
// listed are not granted (a certificate carries only the permissions it names).
func UserExtensions(pty, userRC, portForwarding, agentForwarding, x11Forwarding bool) map[string]string {
	ext := map[string]string{}
	for name, on := range map[string]bool{
		"permit-pty":              pty,
		"permit-user-rc":          userRC,
		"permit-port-forwarding":  portForwarding,
		"permit-agent-forwarding": agentForwarding,
		"permit-X11-forwarding":   x11Forwarding,
	} {
		if on {
			ext[name] = ""
		}
	}
	return ext
}

// CertSpec describes a certificate to sign.
type CertSpec struct {
	Host                    bool // a host certificate; otherwise a user certificate
	Key                     ssh.PublicKey
	Serial                  uint64 // non-zero
	KeyID                   string
	Principals              []string
	ValidAfter, ValidBefore time.Time
	// Extensions and SourceAddresses (the critical option source-address) are for user certificates.
	Extensions      map[string]string
	SourceAddresses []string
}

// RandomSerial returns a random non-zero certificate serial.
func RandomSerial() (uint64, error) {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if s := binary.BigEndian.Uint64(b[:]); s != 0 {
			return s, nil
		}
	}
}

// SignCert builds the certificate spec describes and signs it with ca. Principals are sorted and de-duplicated. It
// returns the certificate and its authorized_keys form ("ssh-ed25519-cert-v01@openssh.com AAAA…", no line end).
func SignCert(ca ssh.Signer, spec CertSpec) (*ssh.Certificate, string, error) {
	switch {
	case spec.Key == nil:
		return nil, "", errors.New("sshca: no public key to certify")
	case spec.Serial == 0:
		return nil, "", errors.New("sshca: a certificate serial must not be zero")
	case !spec.ValidBefore.After(spec.ValidAfter):
		return nil, "", errors.New("sshca: the certificate is valid for no time")
	}
	if _, ok := spec.Key.(*ssh.Certificate); ok {
		return nil, "", ErrCertificate
	}
	principals := append([]string(nil), spec.Principals...)
	sort.Strings(principals)
	out := principals[:0]
	for i, p := range principals {
		if i == 0 || p != principals[i-1] {
			out = append(out, p)
		}
	}
	cert := &ssh.Certificate{
		Key:             spec.Key,
		Serial:          spec.Serial,
		CertType:        ssh.UserCert,
		KeyId:           spec.KeyID,
		ValidPrincipals: out,
		ValidAfter:      uint64(spec.ValidAfter.Unix()),
		ValidBefore:     uint64(spec.ValidBefore.Unix()),
	}
	if spec.Host {
		cert.CertType = ssh.HostCert
	} else {
		cert.Permissions.Extensions = map[string]string{}
		for k, v := range spec.Extensions {
			cert.Permissions.Extensions[k] = v
		}
		if len(spec.SourceAddresses) > 0 {
			cert.Permissions.CriticalOptions = map[string]string{"source-address": strings.Join(spec.SourceAddresses, ",")}
		}
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, "", err
	}
	return cert, AuthorizedKey(cert), nil
}
