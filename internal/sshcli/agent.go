package sshcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// commentPrefix starts the comment of every key Quisora puts in the agent (quisora:<org>/<tenant>), which is how
// status and logout know them.
const commentPrefix = "quisora:"

// errNoAgent says there is no ssh-agent to use.
var errNoAgent = errors.New("no ssh-agent")

// errExpired is a certificate that is over before it is added anywhere.
var errExpired = errors.New("the certificate has already expired")

// goos is the operating system the commands behave for.
func (e *Env) goos() string {
	if e.GOOS != "" {
		return e.GOOS
	}
	return runtime.GOOS
}

// useAgent reports whether there is an ssh-agent to talk to. It is spoken to over a Unix socket (SSH_AUTH_SOCK); the
// agent of Windows' OpenSSH is a named pipe, so there the keys are kept in files, as when there is no agent.
func (e *Env) useAgent() bool { return e.goos() != "windows" }

// dialAgent connects to the ssh-agent; errNoAgent (wrapped when the socket does not answer) when there is none.
func (e *Env) dialAgent() (agent.ExtendedAgent, func(), error) {
	sock := e.AgentSock
	if sock == "" {
		sock = os.Getenv("SSH_AUTH_SOCK")
	}
	if sock == "" {
		return nil, nil, fmt.Errorf("%w: SSH_AUTH_SOCK is not set", errNoAgent)
	}
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errNoAgent, err)
	}
	return agent.NewClient(conn), func() { conn.Close() }, nil
}

// agentCert is a Quisora certificate held by the agent.
type agentCert struct {
	comment string
	cert    *ssh.Certificate
}

// agentCerts lists the agent's keys that are certificates with a Quisora comment.
func agentCerts(ag agent.Agent) ([]agentCert, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, err
	}
	var out []agentCert
	for _, k := range keys {
		if !strings.HasPrefix(k.Comment, commentPrefix) {
			continue
		}
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		if cert, ok := pub.(*ssh.Certificate); ok {
			out = append(out, agentCert{k.Comment, cert})
		}
	}
	return out, nil
}

// addToAgent adds the key with its certificate, for as long as the certificate lasts, and then removes the
// certificates of the same tenant that were there before (this login replaces them).
func (e *Env) addToAgent(ag agent.Agent, priv ed25519.PrivateKey, cert *ssh.Certificate, comment string) error {
	left := time.Until(certEnd(cert))
	if cert.ValidBefore == ssh.CertTimeInfinity {
		left = 0
	} else if left < time.Second {
		return errExpired
	}
	old, _ := agentCerts(ag)
	if err := ag.Add(agent.AddedKey{PrivateKey: priv, Certificate: cert, Comment: comment,
		LifetimeSecs: uint32(left / time.Second)}); err != nil {
		return err
	}
	for _, o := range old {
		if o.comment == comment && !bytes.Equal(o.cert.Marshal(), cert.Marshal()) {
			_ = ag.Remove(o.cert)
		}
	}
	return nil
}

// certEnd is when a certificate stops being valid.
func certEnd(c *ssh.Certificate) time.Time {
	if c.ValidBefore == ssh.CertTimeInfinity {
		return time.Time{}
	}
	return time.Unix(int64(c.ValidBefore), 0)
}

// sshDir is where keys and certificates are written when there is no agent.
func (e *Env) sshDir() (string, error) {
	if e.Dir != "" {
		return e.Dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "quisora"), nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// keyFileName is the name (without directory) of the key written for a tenant without an agent.
func keyFileName(d *Discovery) string {
	return unsafeName.ReplaceAllString(d.Org, "_") + "-" + unsafeName.ReplaceAllString(d.Tenant, "_")
}

// keyPath is the path of the key written for a tenant (the directory is made when asked to).
func (e *Env) keyPath(d *Discovery, mkdir bool) (string, error) {
	dir, err := e.sshDir()
	if err != nil {
		return "", err
	}
	if mkdir {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, keyFileName(d)), nil
}

// writeKeyFiles writes the key (0600, OpenSSH format), its public key and the certificate into the Quisora directory
// and returns the key's path. ssh finds <path>-cert.pub next to the key by itself.
func (e *Env) writeKeyFiles(d *Discovery, priv ed25519.PrivateKey, cert *ssh.Certificate) (string, error) {
	path, err := e.keyPath(d, true)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, d.label())
	if err != nil {
		return "", err
	}
	if err := writeAtomic(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", err
	}
	return path, writePublicFiles(path, cert)
}

// writeAgentFiles is what a login that put the key in ssh-agent leaves beside it: the public key and the certificate,
// with no private key, so that IdentityFile <path>.pub and CertificateFile <path>-cert.pub (with IdentitiesOnly yes)
// pick this key in the agent. A private key an earlier login without an agent wrote there is removed: it is not
// this key, and ssh would pair it with this certificate.
func (e *Env) writeAgentFiles(d *Discovery, cert *ssh.Certificate) (string, error) {
	path, err := e.keyPath(d, true)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return path, writePublicFiles(path, cert)
}

// writePublicFiles writes <path>.pub and <path>-cert.pub.
func writePublicFiles(path string, cert *ssh.Certificate) error {
	if err := writeAtomic(path+".pub", ssh.MarshalAuthorizedKey(cert.Key), 0o644); err != nil {
		return err
	}
	return writeAtomic(path+"-cert.pub", authorizedLine(cert), 0o644)
}

// keepKey puts the new key and its certificate where ssh finds them, and says where, for the command's output: in
// ssh-agent (also writing the public key and the certificate, see writeAgentFiles), or in the files of the Quisora
// directory when noAgent, there is no agent to use, or the agent does not take the key (it is locked, or, like
// 1Password's and Secretive's, does not accept imported keys): the signed-in certificate is not thrown away for that.
func (e *Env) keepKey(d *Discovery, priv ed25519.PrivateKey, cert *ssh.Certificate, noAgent bool) (string, error) {
	switch {
	case noAgent:
	case !e.useAgent():
	default:
		ag, closeAgent, err := e.dialAgent()
		if err != nil {
			fmt.Fprintf(e.errw(), "warning: %v: writing the key to a file instead\n", err)
			break
		}
		defer closeAgent()
		if err = e.addToAgent(ag, priv, cert, d.label()); errors.Is(err, errExpired) {
			return "", err
		} else if err != nil {
			fmt.Fprintf(e.errw(), "warning: ssh-agent did not take the key (%v; it may be locked, or not accept imported keys): writing the key to a file instead\n", err)
			break
		}
		where := "Added to ssh-agent; it is removed when the certificate expires."
		if path, err := e.writeAgentFiles(d, cert); err != nil {
			fmt.Fprintf(e.errw(), "warning: could not write the public key and certificate: %v\n", err)
		} else {
			where += "\nThe public key and certificate are also in " + path + "{.pub,-cert.pub}, to name them in ~/.ssh/config\n(IdentityFile " + path + ".pub, CertificateFile " + path + "-cert.pub, IdentitiesOnly yes)."
		}
		return where, nil
	}
	path, err := e.writeKeyFiles(d, priv, cert)
	if err != nil {
		return "", err
	}
	if e.goos() == "windows" {
		return "The key, the public key and the certificate are in " + path + ", " + path + ".pub and " + path + "-cert.pub (ssh-agent is not used on Windows).\nUse them with: ssh -i " + path + " <host>", nil
	}
	return "Key and certificate written to " + path + "{,.pub,-cert.pub}.\nUse them with: ssh -i " + path + " <host>", nil
}

// authorizedLine is the certificate in authorized_keys form with a newline.
func authorizedLine(cert *ssh.Certificate) []byte { return ssh.MarshalAuthorizedKey(cert) }

// fileCert is a Quisora certificate found in the Quisora directory.
type fileCert struct {
	path string // the certificate file
	cert *ssh.Certificate
}

// fileCerts lists the certificates (*-cert.pub) in the Quisora directory.
func (e *Env) fileCerts() ([]fileCert, error) {
	dir, err := e.sshDir()
	if err != nil {
		return nil, err
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*-cert.pub"))
	slices.Sort(paths)
	var out []fileCert
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			continue
		}
		if cert, ok := pub.(*ssh.Certificate); ok {
			out = append(out, fileCert{p, cert})
		}
	}
	return out, nil
}

// Status lists the Quisora certificates in the agent and in the Quisora directory.
func (e *Env) Status() error {
	var rows [][]string
	row := func(source, name string, c *ssh.Certificate) {
		rows = append(rows, []string{source, name, strings.Join(c.ValidPrincipals, ","), expiry(c, e.now())})
	}
	if e.useAgent() {
		ag, closeAgent, err := e.dialAgent()
		switch {
		case err == nil:
			defer closeAgent()
			certs, err := agentCerts(ag)
			if err != nil {
				return fmt.Errorf("ssh-agent: %w", err)
			}
			for _, c := range certs {
				row("agent", c.comment, c.cert)
			}
		case !errors.Is(err, errNoAgent) || os.Getenv("SSH_AUTH_SOCK") != "" || e.AgentSock != "":
			fmt.Fprintf(e.errw(), "warning: %v\n", err)
		}
	}
	files, err := e.fileCerts()
	if err != nil {
		return err
	}
	for _, f := range files {
		source := "file"
		if _, err := os.Stat(strings.TrimSuffix(f.path, "-cert.pub")); err != nil {
			source = "file (no key)" // beside a key in ssh-agent
		}
		row(source, f.path, f.cert)
	}
	if len(rows) == 0 {
		fmt.Fprintln(e.out(), "No Quisora certificates.")
		return nil
	}
	tw := tabwriter.NewWriter(e.out(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "WHERE\tTENANT\tPRINCIPALS\tVALID UNTIL")
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	return tw.Flush()
}

// expiry is a certificate's end with the time left, or that it has expired.
func expiry(c *ssh.Certificate, now time.Time) string {
	end := certEnd(c)
	if end.IsZero() {
		return "never"
	}
	left := end.Sub(now)
	if left <= 0 {
		return end.Local().Format("2006-01-02 15:04 MST") + " (expired)"
	}
	return fmt.Sprintf("%s (%s left)", end.Local().Format("2006-01-02 15:04 MST"), left.Round(time.Minute))
}

// Logout removes the Quisora certificates (and their keys) from the agent and the Quisora directory: those of the
// tenant at rawURL, or all of them when it is empty.
func (e *Env) Logout(ctx context.Context, rawURL string) error {
	var comment, name string
	if rawURL != "" {
		d, err := e.discover(ctx, rawURL)
		if err != nil {
			return err
		}
		comment, name = d.label(), keyFileName(d)
	}
	var inAgent, inFiles int
	if e.useAgent() {
		ag, closeAgent, err := e.dialAgent()
		switch {
		case err == nil:
			defer closeAgent()
			certs, err := agentCerts(ag)
			if err != nil {
				return fmt.Errorf("ssh-agent: %w", err)
			}
			for _, c := range certs {
				if comment != "" && c.comment != comment {
					continue
				}
				if err := ag.Remove(c.cert); err != nil {
					return fmt.Errorf("removing %s from ssh-agent: %w", c.comment, err)
				}
				inAgent++
			}
		case !errors.Is(err, errNoAgent) || os.Getenv("SSH_AUTH_SOCK") != "" || e.AgentSock != "":
			fmt.Fprintf(e.errw(), "warning: %v\n", err)
		}
	}
	files, err := e.fileCerts()
	if err != nil {
		return err
	}
	for _, f := range files {
		base := strings.TrimSuffix(f.path, "-cert.pub")
		if name != "" && filepath.Base(base) != name {
			continue
		}
		for _, p := range []string{f.path, base + ".pub", base} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		inFiles++
	}
	if inAgent+inFiles == 0 {
		fmt.Fprintln(e.out(), "No Quisora certificates to remove.")
		return nil
	}
	if !e.useAgent() {
		fmt.Fprintf(e.out(), "Removed %d from %s.\n", inFiles, e.dirOrDefault())
		return nil
	}
	fmt.Fprintf(e.out(), "Removed %d from ssh-agent and %d from %s.\n", inAgent, inFiles, e.dirOrDefault())
	return nil
}

// dirOrDefault is the Quisora directory for messages.
func (e *Env) dirOrDefault() string {
	d, _ := e.sshDir()
	return d
}
