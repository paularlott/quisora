package backup_test

// Regression tests from the external code reviews, one per finding: each states the failure it guards against.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func TestDeepVerifyRejectsDamagedGzipFooter(t *testing.T) {
	f := setup(t, 1)
	var buf bytes.Buffer
	if _, err := backup.WriteWith(f.ctx, f.src, f.sealer, &buf, backup.Options{Password: testPassword}); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	for _, cut := range []int{1, 8} {
		t.Run(string(rune('0'+cut)), func(t *testing.T) {
			if _, err := backup.Verify(bytes.NewReader(data[:len(data)-cut]), f.sealer, testPassword); err == nil {
				t.Fatalf("Verify accepted backup missing %d gzip footer bytes", cut)
			}
		})
	}
}

// The unauthenticated trailer must not let a damaged backup conceal required old keys.
func TestDeepBackupTrailerKeyRequirementsAuthenticated(t *testing.T) {
	f := setup(t, 1)
	u := f.user
	k1 := secure.RandomBytes(32)
	old, _ := secure.NewSealer(k1)
	u.TOTPSecret = old.SealFor(service.TOTPBinding(u.ID), []byte("old-key-secret"))
	if err := f.svc.Users.Update(f.ctx, u); err != nil {
		t.Fatal(err)
	}
	// The backup itself is MACed by the new key, while records still need the old one.
	k2 := secure.RandomBytes(32)
	ring, _ := secure.NewKeyring(k2, k1)
	only2, _ := secure.NewSealer(k2)
	var buf bytes.Buffer
	if _, err := backup.WriteWith(f.ctx, f.src, ring, &buf, backup.Options{Password: testPassword}); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Verify(bytes.NewReader(buf.Bytes()), only2, testPassword); !errors.Is(err, backup.ErrKeyMissing) {
		t.Fatalf("setup should require missing old key: %v", err)
	}
	raw := unpack(t, buf.Bytes())
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	var trailer map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &trailer); err != nil {
		t.Fatal(err)
	}
	delete(trailer, "sealed")
	lines[len(lines)-1], _ = json.Marshal(trailer)
	altered := pack(t, append(bytes.Join(lines, []byte("\n")), '\n'))
	if _, err := backup.Verify(bytes.NewReader(altered), only2, testPassword); err == nil {
		t.Fatal("altering only the un-MACed trailer bypassed required-key verification")
	}
}

func TestDeepVerifyRejectsEncryptedTrailingData(t *testing.T) {
	f := setup(t, 1)
	var buf bytes.Buffer
	const password = "deep-review-password"
	if _, err := backup.WriteWith(f.ctx, f.src, f.sealer, &buf, backup.Options{Password: password}); err != nil {
		t.Fatal(err)
	}
	data := append(bytes.Clone(buf.Bytes()), []byte("unexpected bytes after final encrypted chunk")...)
	if _, err := backup.Verify(bytes.NewReader(data), f.sealer, password); err == nil {
		t.Fatal("Verify accepted data after the authenticated final encrypted chunk")
	}
}

// changedFile is a backup file that is replaced by next once it has been read and rewound: one changed in place after
// a restore verified it.
type changedFile struct {
	r    *bytes.Reader
	next []byte
}

func (f *changedFile) Read(p []byte) (int, error) { return f.r.Read(p) }

func (f *changedFile) Seek(off int64, whence int) (int64, error) {
	if f.next != nil {
		f.r, f.next = bytes.NewReader(f.next), nil
	}
	return f.r.Seek(off, whence)
}

// A restore writes what it verified, not the file as it is when the records are written: the integrity MAC is in the
// trailer, so a file changed after verification would have its records (an injected user, here) written before the
// trailer refuses it, and with --force over a shared database other nodes would serve them at once.
func TestRestoreWritesWhatItVerified(t *testing.T) {
	f := setup(t, 2)
	verified := f.backup(t)
	injected, err := f.svc.CreateUser(f.ctx, service.System, f.user.OrgID, service.UserInput{Username: ptr("injected"),
		Email: ptr("injected@example.com"), GivenName: ptr("Injected"), FamilyName: ptr("User")})
	if err != nil {
		t.Fatal(err)
	}
	forged := f.backup(t) // as the attacker's: the records first, the trailer's MAC broken
	plain := unpack(t, forged)
	lines := bytes.Split(bytes.TrimSuffix(plain, []byte("\n")), []byte("\n"))
	var tr map[string]any
	_ = json.Unmarshal(lines[len(lines)-1], &tr)
	tr["mac"] = "AAAA"
	lines[len(lines)-1], _ = json.Marshal(tr)
	gz := pack(t, append(bytes.Join(lines, []byte("\n")), '\n'))

	dst := memstore.New()
	if _, err := backup.Restore(f.ctx, dst, f.sealer, &changedFile{r: bytes.NewReader(verified), next: gz}, false, testPassword, t.TempDir()); err != nil {
		t.Fatalf("restoring the verified backup: %v", err)
	}
	if _, err := dst.Get(f.ctx, model.KindUser, injected.ID); err == nil {
		t.Fatal("a record of the file as changed after verification was written")
	}
	if _, err := dst.Get(f.ctx, model.KindUser, f.user.ID); err != nil {
		t.Fatalf("the verified backup's records: %v", err)
	}
}

// dirWatch is a backup file that notes, when it is first read, the names of the files in dir.
type dirWatch struct {
	r    io.Reader
	dir  string
	seen []string
}

func (w *dirWatch) Read(p []byte) (int, error) {
	if w.seen == nil {
		entries, _ := os.ReadDir(w.dir)
		w.seen = []string{}
		for _, e := range entries {
			w.seen = append(w.seen, e.Name())
		}
	}
	return w.r.Read(p)
}

// A restore's copy of the backup, as large as the backup, is made in the directory it is given (the node's data
// directory), not os.TempDir, which may be a tmpfs held in memory; copies an interrupted restore left there are
// removed first, and the restore's own once it is done.
func TestRestoreCopiesIntoTheDataDirectory(t *testing.T) {
	f := setup(t, 2)
	data := f.backup(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "quisora-restore-123"), []byte("left over"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "store.db"), []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &dirWatch{r: bytes.NewReader(data), dir: dir}
	if _, err := backup.Restore(f.ctx, memstore.New(), f.sealer, w, false, testPassword, dir); err != nil {
		t.Fatal(err)
	}
	copies := 0
	for _, name := range w.seen {
		switch {
		case name == "quisora-restore-123":
			t.Error("an interrupted restore's copy was left in place")
		case strings.HasPrefix(name, "quisora-restore-"):
			copies++
		}
	}
	if copies != 1 {
		t.Errorf("the restore's copy is not in the data directory: %v", w.seen)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "store.db" {
		t.Errorf("left in the data directory: %v", entries)
	}
}
