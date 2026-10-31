package sshcli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/sshcli/sshclitest"
	"golang.org/x/crypto/ssh"
)

type trustFiles struct{ ca, krl, hosts string }

func newTrustFiles(t *testing.T) trustFiles {
	d := t.TempDir()
	return trustFiles{filepath.Join(d, "ca.pub"), filepath.Join(d, "q.krl"), filepath.Join(d, "known_hosts")}
}

func (tf trustFiles) opts(url string) FetchOptions {
	return FetchOptions{URL: url, CAFile: tf.ca, KRLFile: tf.krl, KnownHostsFile: tf.hosts}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// leftovers lists the files in dir that are not the three trust files (a temporary file left behind).
func leftovers(t *testing.T, tf trustFiles) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Dir(tf.ca))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if p := filepath.Join(filepath.Dir(tf.ca), e.Name()); p != tf.ca && p != tf.krl && p != tf.hosts {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestFetch(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	tf := newTrustFiles(t)

	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	for _, p := range []string{tf.ca, tf.krl, tf.hosts} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o644 {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(read(t, tf.ca)))
	if err != nil || string(ca.Marshal()) != string(f.UserCA.PublicKey().Marshal()) {
		t.Errorf("user CA file: %v\n%s", err, read(t, tf.ca))
	}
	if err := checkKRL([]byte(read(t, tf.krl))); err != nil {
		t.Error(err)
	}
	mustContain(t, "known_hosts", read(t, tf.hosts), "@cert-authority *.example.com ssh-ed25519 ")
	mustContain(t, "output", te.out.String(), "updated "+tf.ca)
	if l := leftovers(t, tf); len(l) != 0 {
		t.Errorf("temporary files left: %v", l)
	}

	// current: nothing is written
	old := time.Now().Add(-time.Hour)
	for _, p := range []string{tf.ca, tf.hosts} {
		_ = os.Chtimes(p, old, old)
	}
	f.Body["krl"] = []byte(read(t, tf.krl)) // the fake's own KRL changes with the clock: serve the one fetched
	te.out.b.Reset()
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	if te.out.String() != "" {
		t.Errorf("an unchanged fetch wrote: %s", te.out)
	}
	if st, _ := os.Stat(tf.ca); !st.ModTime().Before(time.Now().Add(-30 * time.Minute)) {
		t.Error("an unchanged file was rewritten")
	}

	// a change is picked up
	f.UserCA = f2CA()
	delete(f.Body, "krl") // the list is of the new CA's too
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	if got, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(read(t, tf.ca))); string(got.Marshal()) != string(f.UserCA.PublicKey().Marshal()) {
		t.Error("the new CA key was not written")
	}
}

// The files in use are kept when the server fails or answers with something that is not valid, whichever of the
// answers it is; nothing is written, not even the answers that were fine.
func TestFetchKeepsOldFiles(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	tf := newTrustFiles(t)
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	before := trustFiles{read(t, tf.ca), read(t, tf.krl), read(t, tf.hosts)}
	newCA := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f2CA().PublicKey()))) + "\n"

	for name, apply := range map[string]func(){
		"krl 500":          func() { f.Fail["krl"] = 500 },
		"ca.pub 500":       func() { f.Fail["ca.pub"] = 500 },
		"known_hosts 404":  func() { f.Fail["known_hosts"] = 404 },
		"garbage krl":      func() { f.Body["krl"] = []byte("<html>oops</html>") },
		"truncated krl":    func() { f.Body["krl"] = sshclitest.EmptyKRL()[:30] },
		"garbage ca":       func() { f.Body["ca.pub"] = []byte("<html>oops</html>") },
		"empty ca":         func() { f.Body["ca.pub"] = []byte("\n") },
		"garbage hosts":    func() { f.Body["known_hosts"] = []byte("@cert-authority only-two-fields\n") },
		"bad key in hosts": func() { f.Body["known_hosts"] = []byte("@cert-authority *.x ssh-ed25519 AAAAnope\n") },
	} {
		t.Run(name, func(t *testing.T) {
			f.Fail, f.Body = map[string]int{}, map[string][]byte{"ca.pub": []byte(newCA)} // a valid new CA that must not be written
			apply()
			err := te.Fetch(context.Background(), tf.opts(f.URL))
			if err == nil {
				t.Fatal("fetch succeeded")
			}
			if got := (trustFiles{read(t, tf.ca), read(t, tf.krl), read(t, tf.hosts)}); got != before {
				t.Errorf("a file changed: %v", err)
			}
			if l := leftovers(t, tf); len(l) != 0 {
				t.Errorf("temporary files left: %v", l)
			}
		})
	}

	t.Run("server gone", func(t *testing.T) {
		url := f.URL
		f.Close()
		if err := te.Fetch(context.Background(), tf.opts(url)); err == nil {
			t.Fatal("fetch succeeded with no server")
		}
		if got := (trustFiles{read(t, tf.ca), read(t, tf.krl), read(t, tf.hosts)}); got != before {
			t.Error("a file changed")
		}
	})
}

// A first fetch that fails leaves no file at all; a target directory that cannot be written is an error.
func TestFetchFirstFailure(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.Fail["krl"] = 500
	te := newTestEnv(t)
	tf := newTrustFiles(t)
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err == nil {
		t.Fatal("fetch succeeded")
	}
	for _, p := range []string{tf.ca, tf.krl, tf.hosts} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s exists", p)
		}
	}
	delete(f.Fail, "krl")
	bad := FetchOptions{URL: f.URL, CAFile: filepath.Join(t.TempDir(), "missing-dir", "ca.pub")}
	if err := te.Fetch(context.Background(), bad); err == nil {
		t.Fatal("a missing directory was accepted")
	}
}

// Without --known-hosts-file the host keys are not written; they are fetched when the list is, to check it against, and
// with the CA keys only, nothing else is asked for.
func TestFetchOnlyWhatIsAsked(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	tf := newTrustFiles(t)
	if err := te.Fetch(context.Background(), FetchOptions{URL: f.URL, CAFile: tf.ca, KRLFile: tf.krl}); err != nil {
		t.Fatal(err) // the list has a section for the host CA key: it is known only from known_hosts
	}
	if _, err := os.Stat(tf.hosts); !os.IsNotExist(err) {
		t.Error("known_hosts written")
	}
	if l := leftovers(t, tf); len(l) != 0 {
		t.Errorf("files left: %v", l)
	}

	f2 := sshclitest.New()
	defer f2.Close()
	if err := te.Fetch(context.Background(), FetchOptions{URL: f2.URL, CAFile: tf.ca}); err != nil {
		t.Fatal(err)
	}
	for _, p := range f2.Paths() {
		if strings.HasSuffix(p, "known_hosts") || strings.HasSuffix(p, "krl") {
			t.Errorf("%s requested for the CA keys alone", p)
		}
	}
}

// krlOf is a KRL of the given version with a section for each CA, revoking serials among those of the first.
func krlOf(version uint64, serials []uint64, cas ...ssh.PublicKey) []byte {
	k := sshca.NewKRL(version, time.Now(), "")
	for i, ca := range cas {
		if i == 0 {
			k.Add(ca, serials...)
		} else {
			k.Add(ca)
		}
	}
	return k.Marshal()
}

// A revocation list that would be installed is checked first: it must have a section for a CA key the tenant publishes
// (a list of another tenant protects nothing), and what sshd would not read is not installed. Nothing is written, not even
// the answers that were fine. A section for a key that is not published is no reason to refuse it: answers that are 30
// seconds old, or a stale ca.pub from a proxy, give that in the normal course of a rotation.
func TestFetchRefusesAnUnfitKRL(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	tf := newTrustFiles(t)
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	before := trustFiles{read(t, tf.ca), read(t, tf.krl), read(t, tf.hosts)}
	newCA := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f2CA().PublicKey()))) + "\n"
	other := f2CA().PublicKey()

	for name, krl := range map[string][]byte{
		"only another tenant's CA key": krlOf(1<<40, []uint64{7}, other),
		"no certificates section":      krlOf(1<<40, nil),
		"a section for every CA":       (&sshca.KRL{Version: 1 << 40, CAs: []sshca.KRLCA{{Serials: []uint64{7}}}}).Marshal(),
	} {
		t.Run(name, func(t *testing.T) {
			f.Body = map[string][]byte{"krl": krl, "ca.pub": []byte(newCA)}
			err := te.Fetch(context.Background(), tf.opts(f.URL))
			if err == nil || !strings.Contains(err.Error(), "revocation list") {
				t.Fatalf("fetch: %v", err)
			}
			if got := (trustFiles{read(t, tf.ca), read(t, tf.krl), read(t, tf.hosts)}); got != before {
				t.Error("a file changed")
			}
			if l := leftovers(t, tf); len(l) != 0 {
				t.Errorf("temporary files left: %v", l)
			}
		})
	}
	t.Run("a section of a key that is not published beside one that is", func(t *testing.T) {
		f.Body = map[string][]byte{"krl": krlOf(1<<40, []uint64{7}, f.UserCA.PublicKey(), other)}
		if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
			t.Fatalf("a section of a key that is gone refused the whole fetch: %v", err)
		}
	})
	t.Run("the CA key is published", func(t *testing.T) {
		f.Body = map[string][]byte{"krl": krlOf(1<<40, []uint64{7}, f.UserCA.PublicKey(), f.HostCA.PublicKey())}
		if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
			t.Fatal(err)
		}
	})
}

// fakeKeygen puts an ssh-keygen on the PATH that records its arguments and the file's size and exits with status.
func fakeKeygen(t *testing.T, status int) (log string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a shell script is the fake ssh-keygen")
	}
	dir := t.TempDir()
	log = filepath.Join(dir, "log")
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %q\nwc -c < \"$4\" >> %q\necho 'Cannot load KRL' >&2\nexit %d\n", log, log, status)
	if err := os.WriteFile(filepath.Join(dir, "ssh-keygen"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// sshd is the authority on its own revocation list: when ssh-keygen is on the PATH it reads the file about to be
// installed (-Q -l -f <file>), and a list it cannot read is refused, whatever this package made of it.
func TestFetchAsksSSHKeygenAboutTheKRL(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	tf := newTrustFiles(t)

	t.Run("accepted", func(t *testing.T) {
		log := fakeKeygen(t, 0)
		te := newTestEnv(t)
		if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
			t.Fatal(err)
		}
		got := strings.Fields(read(t, log))
		if len(got) < 5 || strings.Join(got[:3], " ") != "-Q -l -f" || filepath.Dir(got[3]) != filepath.Dir(tf.krl) ||
			got[3] == tf.krl || got[4] == "0" {
			t.Errorf("ssh-keygen was run as %v: want -Q -l -f <the file staged beside the list>, which holds the list", got)
		}
		if l := leftovers(t, tf); len(l) != 0 {
			t.Errorf("temporary files left: %v", l)
		}
	})
	t.Run("refused", func(t *testing.T) {
		before := trustFiles{read(t, tf.ca), read(t, tf.krl), read(t, tf.hosts)}
		fakeKeygen(t, 1)
		f.UserCA = f2CA()
		te := newTestEnv(t)
		err := te.Fetch(context.Background(), tf.opts(f.URL))
		if err == nil || !strings.Contains(err.Error(), "revocation list") || !strings.Contains(err.Error(), "ssh-keygen") ||
			!strings.Contains(err.Error(), "Cannot load KRL") {
			t.Fatalf("fetch: %v", err)
		}
		if got := (trustFiles{read(t, tf.ca), read(t, tf.krl), read(t, tf.hosts)}); got != before {
			t.Error("a file changed")
		}
		if l := leftovers(t, tf); len(l) != 0 {
			t.Errorf("temporary files left: %v", l)
		}
	})
	t.Run("not installed", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		te := newTestEnv(t)
		if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
			t.Fatalf("without ssh-keygen: %v", err)
		}
	})
}

// A list older than the installed one (a node that kept its answer) is not installed, and is not an error: the files
// that did change are still updated, with a note.
func TestFetchKeepsANewerKRL(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	tf := newTrustFiles(t)
	f.KRLVersion = 2000
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	krlBefore := read(t, tf.krl)

	f.KRLVersion = 1000
	f.UserCA = f2CA()
	te.out.b.Reset()
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatalf("an older list is not an error: %v", err)
	}
	if read(t, tf.krl) != krlBefore {
		t.Error("the older list replaced the installed one")
	}
	mustContain(t, "note", te.err.String(), "version 1000", "older", "version 2000", "keeping the installed one")
	mustContain(t, "output", te.out.String(), "updated "+tf.ca)
	mustNotContain(t, "output", te.out.String(), "updated "+tf.krl)
	if got, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(read(t, tf.ca))); string(got.Marshal()) != string(f.UserCA.PublicKey().Marshal()) {
		t.Error("the CA file was not updated")
	}

	// the same version, or a newer one, is installed
	f.KRLVersion = 2000
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	f.KRLVersion = 3000
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	if k, err := sshca.ParseKRL([]byte(read(t, tf.krl))); err != nil || k.Version != 3000 {
		t.Errorf("installed list: %v %v", k, err)
	}
}

// A version is a node's clock. A list that is older than the installed one is still installed when it revokes something
// the installed one does not (a clock that ran ahead and was set back must not hold back revocations); and an installed
// version that is in the future is not counted.
func TestFetchOlderKRLThatRevokesMore(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	cas := []ssh.PublicKey{f.UserCA.PublicKey(), f.HostCA.PublicKey()}
	other := f2CA().PublicKey()

	withKey := func(version uint64, key ssh.PublicKey) []byte {
		k, _ := sshca.ParseKRL(krlOf(version, []uint64{5}, cas...))
		k.RevokeKey(key)
		return k.Marshal()
	}
	for _, c := range []struct {
		name      string
		installed []byte // version 2000, with serial 5 revoked
		older     []byte // version 1000
		installs  bool
	}{
		{"the same revocations", krlOf(2000, []uint64{5}, cas...), krlOf(1000, []uint64{5}, cas...), false},
		{"fewer revocations", krlOf(2000, []uint64{5, 9}, cas...), krlOf(1000, []uint64{5}, cas...), false},
		{"a serial more", krlOf(2000, []uint64{5}, cas...), krlOf(1000, []uint64{5, 9}, cas...), true},
		{"a key (a CA key) more", krlOf(2000, []uint64{5}, cas...), withKey(1000, other), true},
		{"the key already revoked", withKey(2000, other), withKey(1000, other), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			te := newTestEnv(t)
			tf := newTrustFiles(t)
			f.Body = map[string][]byte{"krl": c.installed}
			if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
				t.Fatal(err)
			}
			f.Body = map[string][]byte{"krl": c.older}
			te.err.b.Reset()
			if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
				t.Fatal(err)
			}
			k, err := sshca.ParseKRL([]byte(read(t, tf.krl)))
			if err != nil {
				t.Fatal(err)
			}
			if c.installs != (k.Version == 1000) {
				t.Errorf("installed version %d: the older list should be installed: %v", k.Version, c.installs)
			}
			if c.installs {
				mustNotContain(t, "stderr", te.err.String(), "keeping the installed one")
			} else {
				mustContain(t, "stderr", te.err.String(), "revokes nothing more", "keeping the installed one")
			}
		})
	}

	t.Run("an installed version in the future is not counted", func(t *testing.T) {
		te := newTestEnv(t)
		tf := newTrustFiles(t)
		future := uint64(time.Now().Add(24 * time.Hour).Unix())
		f.Body = map[string][]byte{"krl": krlOf(future, []uint64{5}, cas...)}
		if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
			t.Fatal(err)
		}
		now := uint64(time.Now().Unix())
		f.Body = map[string][]byte{"krl": krlOf(now, nil, cas...)} // no more than the installed one, and older by a day
		if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
			t.Fatal(err)
		}
		if k, _ := sshca.ParseKRL([]byte(read(t, tf.krl))); k.Version != now {
			t.Errorf("the list stayed at version %d: a clock that ran ahead holds back the lists", k.Version)
		}
	})
}

// What revokes more: serials, ranges and key ids of a CA, and keys; what the installed list covers (also by a range, or
// by a section for every CA) is not more.
func TestRevokesMore(t *testing.T) {
	ca, other := []byte("ca"), []byte("other")
	list := func(cas ...sshca.KRLCA) *sshca.KRL { return &sshca.KRL{CAs: cas} }
	installed := list(sshca.KRLCA{Key: ca, Serials: []uint64{5}, Ranges: [][2]uint64{{10, 20}}, KeyIDs: []string{"a@x"}},
		sshca.KRLCA{Key: other, Serials: []uint64{99}})
	installed.Keys = [][]byte{[]byte("k1")}
	for _, c := range []struct {
		name string
		k    *sshca.KRL
		more bool
	}{
		{"nothing", list(), false},
		{"the same", installed, false},
		{"a serial that is listed", list(sshca.KRLCA{Key: ca, Serials: []uint64{5}}), false},
		{"a serial in a range", list(sshca.KRLCA{Key: ca, Serials: []uint64{10, 15, 20}}), false},
		{"a range inside a range", list(sshca.KRLCA{Key: ca, Ranges: [][2]uint64{{12, 18}}}), false},
		{"a key id that is listed", list(sshca.KRLCA{Key: ca, KeyIDs: []string{"a@x"}}), false},
		{"a key that is listed", &sshca.KRL{Keys: [][]byte{[]byte("k1")}}, false},
		{"a serial more", list(sshca.KRLCA{Key: ca, Serials: []uint64{5, 6}}), true},
		{"a serial of the other CA's under this one's", list(sshca.KRLCA{Key: ca, Serials: []uint64{99}}), true},
		{"a serial just outside the range", list(sshca.KRLCA{Key: ca, Serials: []uint64{21}}), true},
		{"a range that sticks out", list(sshca.KRLCA{Key: ca, Ranges: [][2]uint64{{15, 25}}}), true},
		{"a key id more", list(sshca.KRLCA{Key: ca, KeyIDs: []string{"b@x"}}), true},
		{"a CA that is not there", list(sshca.KRLCA{Key: []byte("third"), Serials: []uint64{1}}), true},
		{"a key more", &sshca.KRL{Keys: [][]byte{[]byte("k1"), []byte("k2")}}, true},
	} {
		if got := revokesMore(c.k, installed); got != c.more {
			t.Errorf("%s: %v, want %v", c.name, got, c.more)
		}
	}
	everyCA := list(sshca.KRLCA{Serials: []uint64{7}})
	if revokesMore(list(sshca.KRLCA{Key: ca, Serials: []uint64{7}}), everyCA) {
		t.Error("a section for every CA covers a serial of one")
	}
}

// Every list has a new version and date, which is not news: "updated" is printed for the revocation list when what it
// revokes (or whose certificates it names) changed. The new file is written all the same, so that its modification time
// shows when the server last answered.
func TestFetchReportsAKRLOnlyWhenItRevokesSomethingNew(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	te := newTestEnv(t)
	tf := newTrustFiles(t)
	cas := []ssh.PublicKey{f.UserCA.PublicKey(), f.HostCA.PublicKey()}
	f.Body["krl"] = krlOf(1000, []uint64{5}, cas...)
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "output", te.out.String(), "updated "+tf.krl)

	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(tf.krl, old, old)
	f.Body["krl"] = krlOf(1060, []uint64{5}, cas...)
	te.out.b.Reset()
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	mustNotContain(t, "output", te.out.String(), "updated")
	if k, _ := sshca.ParseKRL([]byte(read(t, tf.krl))); k.Version != 1060 {
		t.Errorf("the new list was not written: version %d", k.Version)
	}
	if st, _ := os.Stat(tf.krl); time.Since(st.ModTime()) > time.Minute {
		t.Error("the modification time shows no fetch")
	}

	f.Body["krl"] = krlOf(1120, []uint64{5, 9}, cas...)
	te.out.b.Reset()
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "output", te.out.String(), "updated "+tf.krl+" (revocation list)")
}

func TestCheckTrustLists(t *testing.T) {
	good := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDx0Y2eE6pxk3bGVbrYh7EcoRUdgDGlgPErhQ6sLn6vq quisora:acme/prod:user:k1\n"
	for _, c := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"one key", good, true}, {"comments and blanks", "# keys\n\n" + good, true}, {"two keys", good + good, true},
		{"empty", "", false}, {"only a comment", "# nothing\n", false}, {"html", "<html>", false}, {"one bad line", good + "oops\n", false},
		{"options", "no-pty " + good, false}, {"cert-authority", "cert-authority " + good, false},
		{"principals option", `principals="root" ` + good, false}, {"a certificate", certLine(t), false},
	} {
		if err := checkCAKeys([]byte(c.in)); (err == nil) != c.ok {
			t.Errorf("checkCAKeys %s: %v", c.name, err)
		}
	}
	for _, c := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty", "", true}, {"line", "@cert-authority *.example.com " + good, true}, {"plain host line", "host1 " + good, true},
		{"missing key", "@cert-authority *.example.com\n", false}, {"bad key", "@cert-authority *.example.com ssh-ed25519 nope\n", false},
	} {
		if err := checkKnownHosts([]byte(c.in)); (err == nil) != c.ok {
			t.Errorf("checkKnownHosts %s: %v", c.name, err)
		}
	}
}

// certLine is a user certificate in authorized_keys form.
func certLine(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	c := &ssh.Certificate{Key: sp, CertType: ssh.UserCert, ValidPrincipals: []string{"x"}, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, f2CA()); err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(c))
}

// With SSH turned off the servers go on fetching: the discovery document still answers, and the files are written
// (the revocation list then revokes every certificate), with a warning.
func TestFetchWhileSSHIsOff(t *testing.T) {
	f := sshclitest.New()
	defer f.Close()
	f.Off = true
	te := newTestEnv(t)
	tf := newTrustFiles(t)
	if err := te.Fetch(context.Background(), tf.opts(f.URL)); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	for _, p := range []string{tf.ca, tf.krl, tf.hosts} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	mustContain(t, "warning", te.err.String(), "turned off for acme/prod", "revokes every certificate")
}
