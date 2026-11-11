package sshcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// FetchOptions are the arguments of `quisora ssh fetch`; an empty file name leaves that file alone.
type FetchOptions struct {
	URL            string // the tenant's discovery URL
	CAFile         string // the user CA keys, for sshd's TrustedUserCAKeys
	KRLFile        string // the revocation list, for sshd's RevokedKeys
	KnownHostsFile string // the host CA lines, for clients' known_hosts
	// EndRevoked ends the SSH connections of certificates the revocation list in place revokes, and those open longer
	// than the tenant's certificate lifetime (Linux: sshd's log in journald): sshd checks a certificate only when it
	// is presented, so a revocation alone leaves open sessions open.
	EndRevoked bool
}

// Fetch brings a server's trust files up to date. Everything is fetched and checked before anything is written, so
// the files in use are kept when the server cannot be reached or answers with something that is not valid; each one
// is replaced atomically, and one that has not changed is not written at all.
//
// A revocation list is installed only if sshd would read it (it is parsed here, and checked with ssh-keygen when that
// is on the PATH: sshd refuses every public-key login when it cannot read its list), if it has a section for at least
// one of the CA keys the tenant publishes (a list of another tenant protects nothing), and unless it is older than the
// one installed (a few nodes keep an answer for 30 seconds) and revokes nothing the installed one does not: then the
// installed list stays, and the other files are updated all the same. The CA keys and the host CA lines are fetched whenever the list is, for that
// check, even when only the list is to be written.
func (e *Env) Fetch(ctx context.Context, o FetchOptions) error {
	d, err := e.discover(ctx, o.URL)
	if err != nil {
		return err
	}
	if d.off() { // still fetched: that is how the servers learn that every certificate is revoked
		fmt.Fprintf(e.errw(), "warning: SSH certificates are turned off for %s/%s: the revocation list revokes every certificate\n", d.Org, d.Tenant)
	}
	get := func(what, endpoint string, limit int64) ([]byte, error) {
		if endpoint == "" {
			return nil, fmt.Errorf("%s: discovery has no endpoint for it", what)
		}
		data, err := e.fetchBody(ctx, endpoint, limit)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		return data, nil
	}
	var caData, krlData, hostsData []byte
	var caKeys, hostKeys []ssh.PublicKey
	if o.CAFile != "" || o.KRLFile != "" {
		if caData, err = get("user CA keys", d.UserCAEndpoint, maxAPIBody); err != nil {
			return err
		}
		if caKeys, err = parseCAKeys(caData); err != nil {
			return fmt.Errorf("user CA keys: %w", err)
		}
	}
	if o.KRLFile != "" {
		if krlData, err = get("revocation list", d.KRLEndpoint, maxKRLBody); err != nil {
			return err
		}
	}
	if o.KnownHostsFile != "" || o.KRLFile != "" {
		if hostsData, err = get("host CA keys", d.KnownHostsEndpoint, maxAPIBody); err != nil {
			return err
		}
		if hostKeys, err = parseKnownHosts(hostsData); err != nil {
			return fmt.Errorf("host CA keys: %w", err)
		}
	}

	type file struct {
		path, what string
		data       []byte
		quiet      bool // written, but not reported (a new list with nothing changed in it)
	}
	var files []file
	var inEffect *sshca.KRL // the list in place once the files are written
	if o.CAFile != "" {
		files = append(files, file{path: o.CAFile, what: "user CA keys", data: caData})
	}
	if o.KnownHostsFile != "" {
		files = append(files, file{path: o.KnownHostsFile, what: "host CA keys", data: hostsData})
	}
	if o.KRLFile != "" {
		krl, err := sshca.ParseKRL(krlData)
		if err != nil {
			return fmt.Errorf("revocation list: %w", err)
		}
		var installed *sshca.KRL
		if old, err := os.ReadFile(o.KRLFile); err == nil {
			installed, _ = sshca.ParseKRL(old) // one that cannot be read is replaced
		}
		inEffect = krl
		// A version is a node's clock, which is not to be trusted to go forward: a list that is older than the installed
		// one is kept only if it revokes nothing the installed one does not (a clock that ran ahead and was set back
		// must not hold back new revocations), and an installed version in the local future is not counted at all.
		if installed != nil && installed.Version > krl.Version && installed.Version <= uint64(e.now().Add(krlClockSlack).Unix()) &&
			!revokesMore(krl, installed) {
			fmt.Fprintf(e.errw(), "note: the server's revocation list (version %d) is older than the one in %s (version %d) and revokes nothing more: keeping the installed one\n",
				krl.Version, o.KRLFile, installed.Version)
			inEffect = installed
		} else {
			if err := checkKRLCAs(krl, append(slices.Clone(caKeys), hostKeys...)); err != nil {
				return fmt.Errorf("revocation list: %w", err)
			}
			files = append(files, file{path: o.KRLFile, what: "revocation list", data: krlData,
				quiet: installed != nil && sameRevocations(installed, krl)})
		}
	}

	// stage every changed file next to its target, then rename them all
	type staged struct {
		tmp, path, what string
		quiet           bool
	}
	var todo []staged
	cleanup := func() {
		for _, s := range todo {
			os.Remove(s.tmp)
		}
	}
	for _, f := range files {
		if old, err := os.ReadFile(f.path); err == nil && bytes.Equal(old, f.data) {
			if st, err := os.Stat(f.path); err == nil && st.Mode().Perm() == 0o644 {
				continue // current
			}
		}
		tmp, err := stage(f.path, f.data, 0o644)
		if err != nil {
			cleanup()
			return fmt.Errorf("%s: %w", f.what, err)
		}
		todo = append(todo, staged{tmp, f.path, f.what, f.quiet})
		if f.path == o.KRLFile {
			if err := keygenCheck(ctx, tmp); err != nil {
				cleanup()
				return fmt.Errorf("%s: %w", f.what, err)
			}
		}
	}
	for i, s := range todo {
		if err := os.Rename(s.tmp, s.path); err != nil {
			todo = todo[i:] // what is not yet in place is removed
			cleanup()
			return fmt.Errorf("%s: %w", s.what, err)
		}
		syncDir(filepath.Dir(s.path))
		if !s.quiet {
			fmt.Fprintf(e.out(), "updated %s (%s)\n", s.path, s.what)
		}
	}
	if o.EndRevoked && inEffect != nil {
		if _, err := e.endRevoked(ctx, inEffect, caKeys, time.Duration(d.CertTTL)*time.Second); err != nil {
			return fmt.Errorf("ending connections of revoked certificates: %w", err)
		}
	}
	return nil
}

// fetchBody GETs endpoint and returns the body of a 200 answer, at most limit bytes.
func (e *Env) fetchBody(ctx context.Context, endpoint string, limit int64) ([]byte, error) {
	resp, err := e.get(ctx, endpoint, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("the answer is too large")
	}
	return data, nil
}

// checkKRL accepts what parses as an OpenSSH key revocation list: it refuses data that is not one (an error page, a
// truncated file) in place of the one in use.
func checkKRL(b []byte) error {
	_, err := sshca.ParseKRL(b)
	return err
}

// krlClockSlack is how far ahead of the local clock the version of the installed list may be before it is taken for a
// clock that was wrong and not counted (the server's clock and this one are not the same).
const krlClockSlack = 10 * time.Minute

// checkKRLCAs refuses a list that does not belong to the tenant: one with no certificates section for any of the
// published CA keys (a list of another tenant, which would revoke nothing here), or with a section for every CA, which
// Quisora never writes. A section for a key that is not published is ignored: a node's answer can be 30 seconds old
// and carry the section of a key that has just gone, and a proxy can serve an older ca.pub beside a newer list.
func checkKRLCAs(k *sshca.KRL, published []ssh.PublicKey) error {
	known := false
	for _, ca := range k.CAs {
		if len(ca.Key) == 0 {
			return errors.New("it has a section for every CA, not for one of the tenant's keys")
		}
		known = known || slices.ContainsFunc(published, func(p ssh.PublicKey) bool { return bytes.Equal(p.Marshal(), ca.Key) })
	}
	if !known {
		return errors.New("it has no section for any of the CA keys the tenant publishes: is this the right tenant?")
	}
	return nil
}

// revokesMore reports whether k revokes something that installed does not: a serial, serial range, key id or key.
// What it cannot show to be covered (a range that is not inside one of the installed ranges) counts as new.
func revokesMore(k, installed *sshca.KRL) bool {
	for _, key := range k.Keys {
		if !slices.ContainsFunc(installed.Keys, func(b []byte) bool { return bytes.Equal(b, key) }) {
			return true
		}
	}
	for _, ca := range k.CAs {
		// what the installed list revokes among the certificates of this CA (or of every CA)
		var serials []uint64
		var ranges [][2]uint64
		var ids []string
		for _, ic := range installed.CAs {
			if len(ic.Key) == 0 || bytes.Equal(ic.Key, ca.Key) {
				serials, ranges, ids = append(serials, ic.Serials...), append(ranges, ic.Ranges...), append(ids, ic.KeyIDs...)
			}
		}
		for _, n := range ca.Serials {
			if !slices.Contains(serials, n) && !slices.ContainsFunc(ranges, func(r [2]uint64) bool { return n >= r[0] && n <= r[1] }) {
				return true
			}
		}
		for _, r := range ca.Ranges {
			if !slices.ContainsFunc(ranges, func(o [2]uint64) bool { return r[0] >= o[0] && r[1] <= o[1] }) {
				return true
			}
		}
		for _, id := range ca.KeyIDs {
			if !slices.Contains(ids, id) {
				return true
			}
		}
	}
	return false
}

// sameRevocations reports whether two lists revoke the same: they differ in their version, date and comment each time
// they are made, which is not a change.
func sameRevocations(a, b *sshca.KRL) bool {
	x, y := *a, *b
	x.Version, y.Version, x.Generated, y.Generated, x.Comment, y.Comment = 0, 0, time.Time{}, time.Time{}, "", ""
	return reflect.DeepEqual(x, y)
}

// keygenCheck has OpenSSH's own parser read the list in path when ssh-keygen is installed: sshd refuses every
// public-key login if it cannot read its RevokedKeys file, so what it would not read must not be installed.
func keygenCheck(ctx context.Context, path string) error {
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return nil // nothing to ask; the list was parsed here
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, bin, "-Q", "-l", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-keygen cannot read it, so sshd would refuse it: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// checkCAKeys accepts a list of public keys, one per line (comments and blank lines allowed), with at least one.
func checkCAKeys(b []byte) error {
	_, err := parseCAKeys(b)
	return err
}

// parseCAKeys reads the CA keys of a TrustedUserCAKeys list: bare public keys, one per line (comments and blank lines
// allowed), at least one. A line with authorized_keys options or a certificate is refused: it is not what the server
// published, and what sshd makes of it is not what the tenant means.
func parseCAKeys(b []byte) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("not a public key line: %w", err)
		}
		if len(opts) > 0 {
			return nil, errors.New("a key line has options: a CA key is a plain public key")
		}
		if _, isCert := key.(*ssh.Certificate); isCert {
			return nil, errors.New("a key line is a certificate, not a CA public key")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("the list holds no keys")
	}
	return keys, nil
}

// checkKnownHosts accepts known_hosts lines (a marker, host patterns and a public key); an empty list is valid
// (a tenant without host certificates).
func checkKnownHosts(b []byte) error {
	_, err := parseKnownHosts(b)
	return err
}

// parseKnownHosts reads the keys of known_hosts lines.
func parseKnownHosts(b []byte) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if strings.HasPrefix(f[0], "@") {
			f = f[1:]
		}
		if len(f) < 3 {
			return nil, errors.New("not a known_hosts line")
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.Join(f[1:], " ")))
		if err != nil {
			return nil, fmt.Errorf("not a known_hosts line: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// stage writes data to a new file next to path (same directory, so renaming it over path is atomic), with the
// mode, and makes it durable. It returns the new file's name.
func stage(path string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// writeAtomic replaces path with data (mode) all at once: a temporary file in the same directory, synced, renamed.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := stage(path, data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// syncDir makes a rename in dir durable where the system lets a directory be synced (best effort).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
