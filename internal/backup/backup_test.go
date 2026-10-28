package backup_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

func ptr[T any](v T) *T { return &v }

type fixture struct {
	ctx    context.Context
	cfg    *config.Config
	sealer *secure.Sealer
	src    store.Store
	svc    *service.Service
	user   *model.User
}

func setup(t testing.TB, users int) *fixture {
	t.Helper()
	ctx := context.Background()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	src := memstore.New()
	svc := service.New(cfg, src, sealer)
	super, _, err := svc.Bootstrap(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	var u *model.User
	for i := range users {
		name := "user" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676))
		u, err = svc.CreateUser(ctx, service.System, super.OrgID, service.UserInput{Username: ptr(name),
			Email: ptr(name + "@example.com"), GivenName: ptr("Given"), FamilyName: ptr("Family")})
		if err != nil {
			t.Fatal(err)
		}
	}
	if u == nil {
		u = super
	}
	return &fixture{ctx: ctx, cfg: cfg, sealer: sealer, src: src, svc: svc, user: u}
}

func (f *fixture) backup(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := backup.WriteWith(f.ctx, f.src, f.sealer, &buf, backup.Options{}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A backup restores into an empty store of another backend with every record, version and sealed secret intact.
func TestRoundTripAcrossBackends(t *testing.T) {
	f := setup(t, 1200) // more than one page
	ctx := f.ctx
	// a sealed value (TOTP secret) and an expiring record
	f.user.TOTPSecret = f.sealer.SealFor("user/"+f.user.ID+"/totp", []byte("JBSWY3DPEHPK3PXP"))
	if err := f.svc.Users.Update(ctx, f.user); err != nil {
		t.Fatal(err)
	}
	stored, _ := f.svc.Users.Get(ctx, f.user.ID)
	data := f.backup(t)

	dst, err := sqlstore.Open(ctx, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "r.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	stats, err := backup.Restore(ctx, dst, f.sealer, bytes.NewReader(data), false, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range model.Kinds() {
		if backup.Skipped(k) {
			continue
		}
		want, _ := f.src.Count(ctx, k, "")
		got, _ := dst.Count(ctx, k, "")
		if want != got || stats[k] != want {
			t.Errorf("%s: source %d, restored %d, stats %d", k, want, got, stats[k])
		}
	}
	svc2 := service.New(f.cfg, dst, f.sealer)
	u, err := svc2.Users.Get(ctx, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Version != stored.Version || u.Username != stored.Username {
		t.Errorf("restored user %v/%s, want %v/%s", u.Version, u.Username, stored.Version, stored.Username)
	}
	if got, _ := svc2.Users.GetByUnique(ctx, model.UserUsernameKey(u.OrgID, u.Username)); got == nil || got.ID != u.ID {
		t.Error("unique index not rebuilt")
	}
	if secret, err := f.sealer.OpenFor("user/"+u.ID+"/totp", u.TOTPSecret); err != nil || string(secret) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("sealed secret: %q %v", secret, err)
	}
	// a write after the restore is newer than every restored version
	u.GivenName = "Changed"
	if err := svc2.Users.Update(ctx, u); err != nil {
		t.Fatalf("update after restore: %v", err)
	}
}

func TestRestoreRefusals(t *testing.T) {
	f := setup(t, 3)
	data := f.backup(t)
	ctx := f.ctx

	// another master key
	other, _ := secure.NewSealer(secure.RandomBytes(32))
	if _, err := backup.Restore(ctx, memstore.New(), other, bytes.NewReader(data), false, ""); !errors.Is(err, backup.ErrKey) {
		t.Errorf("other key: %v", err)
	}
	// a store that is not empty, unless forced
	if _, err := backup.Restore(ctx, f.src, f.sealer, bytes.NewReader(data), false, ""); !errors.Is(err, backup.ErrNotEmpty) {
		t.Errorf("non-empty target: %v", err)
	}
	if _, err := backup.Restore(ctx, f.src, f.sealer, bytes.NewReader(data), true, ""); err != nil {
		t.Errorf("forced restore over the same data: %v", err)
	}
	// not a backup, and a truncated one
	if _, err := backup.Restore(ctx, memstore.New(), f.sealer, bytes.NewReader([]byte("hello")), false, ""); !errors.Is(err, backup.ErrFormat) {
		t.Errorf("garbage: %v", err)
	}
	zr, _ := gzip.NewReader(bytes.NewReader(data))
	plain, _ := io.ReadAll(zr)
	var cut bytes.Buffer
	zw := gzip.NewWriter(&cut)
	_, _ = zw.Write(plain[:len(plain)*2/3])
	_ = zw.Close()
	if _, err := backup.Restore(ctx, memstore.New(), f.sealer, bytes.NewReader(cut.Bytes()), false, ""); !errors.Is(err, backup.ErrFormat) {
		t.Errorf("truncated: %v", err)
	}
}

func BenchmarkBackup(b *testing.B) {
	f := setup(b, 2000)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := backup.WriteWith(f.ctx, f.src, f.sealer, io.Discard, backup.Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRestore(b *testing.B) {
	f := setup(b, 2000)
	data := f.backup(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := backup.Restore(f.ctx, memstore.New(), f.sealer, bytes.NewReader(data), false, ""); err != nil {
			b.Fatal(err)
		}
	}
}

// A forced restore of another server's backup over a store that holds its own primary organization is refused: each
// installation's primary organization has an id of its own, and both claim the primary organization's unique value
// (and the name "primary"), which is never resolved by guessing which one should be the server's. The store keeps
// its own.
func TestForcedRestoreOverAnotherServerIsRefused(t *testing.T) {
	f := setup(t, 1)
	data := f.backup(t)
	ctx := f.ctx
	dst := memstore.New()
	other := service.New(f.cfg, dst, f.sealer)
	if _, _, err := other.Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	mine, err := other.PrimaryOrgID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Restore(ctx, dst, f.sealer, bytes.NewReader(data), true, ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("forced restore over another server: %v", err)
	}
	fresh := service.New(f.cfg, dst, f.sealer)
	if id, err := fresh.PrimaryOrgID(ctx); err != nil || id != mine {
		t.Fatalf("primary after the refused restore: %q %v, want %q", id, err, mine)
	}
	if o, err := fresh.OrgByName(ctx, "primary"); err != nil || o.ID != mine {
		t.Fatalf("unique lookup: %v %v", o, err)
	}
}

// An altered backup — here a record line added, with the trailer's count fixed to match — fails the integrity check
// and nothing is written; only the master key can produce a backup that restores.
func TestAlteredBackupRefused(t *testing.T) {
	f := setup(t, 2)
	data := f.backup(t)
	zr, _ := gzip.NewReader(bytes.NewReader(data))
	plain, _ := io.ReadAll(zr)
	lines := bytes.Split(bytes.TrimSuffix(plain, []byte("\n")), []byte("\n"))
	extra := lines[1] // a copy of the first record line
	var out bytes.Buffer
	for _, l := range lines[:len(lines)-1] {
		out.Write(l)
		out.WriteByte('\n')
	}
	out.Write(extra)
	out.WriteByte('\n')
	var tr map[string]any
	_ = json.Unmarshal(lines[len(lines)-1], &tr)
	tr["records"] = tr["records"].(float64) + 1
	tb, _ := json.Marshal(tr)
	out.Write(tb)
	out.WriteByte('\n')
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(out.Bytes())
	_ = zw.Close()
	dst := memstore.New()
	if _, err := backup.Restore(f.ctx, dst, f.sealer, bytes.NewReader(gz.Bytes()), false, ""); !errors.Is(err, backup.ErrFormat) {
		t.Fatalf("altered backup: %v", err)
	}
	if empty, _ := backup.Empty(f.ctx, dst); !empty {
		t.Fatal("an altered backup wrote records before it was refused")
	}
	// the structure alone (no key) still reads, which is all a download check can do
	if _, err := backup.Verify(bytes.NewReader(gz.Bytes()), nil, ""); err != nil {
		t.Fatalf("structure check: %v", err)
	}
}

// A store that holds only deleted records counts as empty but is not: the restore fails instead of dropping records
// silently and reporting them restored.
func TestRestoreOverDeletionsRefused(t *testing.T) {
	f := setup(t, 2)
	data := f.backup(t)
	dst := memstore.New()
	if _, err := backup.Restore(f.ctx, dst, f.sealer, bytes.NewReader(data), false, ""); err != nil {
		t.Fatal(err)
	}
	// delete everything that was restored: only tombstones are left
	for _, k := range []model.Kind{model.KindUser, model.KindOrg, model.KindTenant, model.KindAudit, model.KindLink, model.KindKey} {
		res, _ := dst.List(f.ctx, k, store.ListQuery{})
		for _, r := range res.Records {
			if err := dst.Put(f.ctx, store.Tombstone(k, r.ID)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if empty, _ := backup.Empty(f.ctx, dst); !empty {
		t.Fatal("expected a store holding only deletions")
	}
	if _, err := backup.Restore(f.ctx, dst, f.sealer, bytes.NewReader(data), false, ""); !errors.Is(err, backup.ErrNotEmpty) {
		t.Fatalf("restore over deletions: %v", err)
	}
}

// A12: a backup encrypted with a password reveals nothing without it (not even the names that are not sealed),
// restores with it, and is refused when altered, cut short, or given a wrong or no password. Without the password a
// download can still be checked for completeness.
func TestEncryptedBackup(t *testing.T) {
	f := setup(t, 1200) // several encryption chunks
	const pw = "correct horse battery"
	var buf bytes.Buffer
	if _, err := backup.WriteWith(f.ctx, f.src, f.sealer, &buf, backup.Options{Password: pw}); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if bytes.Contains(data, []byte("@example.com")) {
		t.Fatal("the encrypted backup shows an email address")
	}
	if _, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		t.Fatal("the encrypted backup is a plain gzip stream")
	}
	if !backup.PasswordProtected(data) {
		t.Fatal("not recognised as password protected")
	}
	if st, err := backup.Verify(bytes.NewReader(data), nil, ""); err != nil || st != nil {
		t.Fatalf("framing check without the password: %v %v", st, err)
	}
	dst := memstore.New()
	stats, err := backup.Restore(f.ctx, dst, f.sealer, bytes.NewReader(data), false, pw)
	if err != nil || stats[model.KindUser] != 1201 {
		t.Fatalf("restore: %v %v", stats, err)
	}
	if _, err := backup.Restore(f.ctx, memstore.New(), f.sealer, bytes.NewReader(data), false, "wrong horse battery"); !errors.Is(err, backup.ErrPassword) {
		t.Fatalf("a wrong password: %v", err)
	}
	if _, err := backup.Restore(f.ctx, memstore.New(), f.sealer, bytes.NewReader(data), false, ""); !errors.Is(err, backup.ErrNeedPassword) {
		t.Fatalf("no password: %v", err)
	}
	other, _ := secure.NewSealer(secure.RandomBytes(32))
	if _, err := backup.Restore(f.ctx, memstore.New(), other, bytes.NewReader(data), false, pw); !errors.Is(err, backup.ErrKey) {
		t.Fatalf("another master key: %v", err)
	}
	flipped := bytes.Clone(data)
	flipped[len(flipped)/2] ^= 1
	if _, err := backup.Verify(bytes.NewReader(flipped), f.sealer, pw); err == nil {
		t.Fatal("an altered encrypted backup verified")
	}
	const hdr = 8 + 25 + 7 // magic, KDF parameters, nonce prefix
	if len(data) < hdr+2*(4+64<<10+16) {
		t.Fatalf("test set-up: %d bytes is too few chunks", len(data))
	}
	for _, cut := range []int{len(data) - 1, hdr + 4 + 64<<10 + 16} { // inside the last chunk; after the first
		if _, err := backup.Verify(bytes.NewReader(data[:cut]), nil, ""); err == nil {
			t.Fatalf("cut at %d of %d: the framing check passed", cut, len(data))
		}
		if _, err := backup.Verify(bytes.NewReader(data[:cut]), f.sealer, pw); err == nil {
			t.Fatalf("cut at %d of %d: verified", cut, len(data))
		}
	}
	var short bytes.Buffer
	if _, err := backup.WriteWith(f.ctx, f.src, f.sealer, &short, backup.Options{Password: "too short"}); err == nil {
		t.Fatal("a short password was accepted")
	}
}

// A12: a backup reads a point-in-time view where the backend has one: records written while it runs do not appear
// half-way (here: written between the view being opened and read).
func TestSnapshotIsPointInTime(t *testing.T) {
	ctx := context.Background()
	st, err := sqlstore.Open(ctx, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	put := func(id string) {
		if err := st.Put(ctx, &store.Record{Kind: model.KindGroup, ID: id, Version: store.Clock.Now(), Scope: "o",
			Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	put("before")
	view, err := st.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	put("after")
	res, err := view.List(ctx, model.KindGroup, store.ListQuery{})
	if err != nil || len(res.Records) != 1 || res.Records[0].ID != "before" {
		t.Fatalf("the snapshot sees later writes: %v %+v", err, res)
	}
	if n, _ := st.Count(ctx, model.KindGroup, ""); n != 2 {
		t.Fatalf("live count %d", n)
	}
}

// A backup made before a master key rotation verifies and restores with a keyring that holds the old key as a
// previous one (plain and encrypted), and is refused once the old key is gone.
func TestBackupAcrossKeyRotation(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	k1, k2 := secure.RandomBytes(32), secure.RandomBytes(32)
	old, _ := secure.NewSealer(k1)
	src := memstore.New()
	if _, _, err := service.New(cfg, src, old).Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	ring, _ := secure.NewKeyring(k2, k1)
	only2, _ := secure.NewSealer(k2)
	for _, enc := range []bool{false, true} {
		var buf bytes.Buffer
		opt := backup.Options{}
		if enc {
			opt.Password = "correct horse battery"
		}
		if _, err := backup.WriteWith(ctx, src, old, &buf, opt); err != nil {
			t.Fatal(err)
		}
		if _, err := backup.Verify(bytes.NewReader(buf.Bytes()), ring, opt.Password); err != nil {
			t.Fatalf("encrypt=%v: verify with the ring: %v", enc, err)
		}
		if _, err := backup.Restore(ctx, memstore.New(), ring, bytes.NewReader(buf.Bytes()), false, opt.Password); err != nil {
			t.Fatalf("encrypt=%v: restore with the ring: %v", enc, err)
		}
		if _, err := backup.Verify(bytes.NewReader(buf.Bytes()), only2, opt.Password); err == nil {
			t.Fatalf("encrypt=%v: verified without the key it was made with", enc)
		}
	}
	// a backup made after the rotation is made with the new key
	var buf bytes.Buffer
	if _, err := backup.WriteWith(ctx, src, ring, &buf, backup.Options{Password: "correct horse battery"}); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Verify(bytes.NewReader(buf.Bytes()), only2, "correct horse battery"); err != nil {
		t.Fatalf("new backup with the new key: %v", err)
	}
}

// A backup taken during a rotation (the new key active, a secret still sealed with the old one) is verified with the
// new key but names the old one as needed: a restore without it is refused instead of leaving that secret unopenable.
func TestBackupNamesTheKeysItsSecretsNeed(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	k1, k2 := secure.RandomBytes(32), secure.RandomBytes(32)
	old, _ := secure.NewSealer(k1)
	ring, _ := secure.NewKeyring(k2, k1)
	only2, _ := secure.NewSealer(k2)
	src := memstore.New()
	svc := service.New(cfg, src, ring)
	super, _, err := svc.Bootstrap(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := svc.Users.Get(ctx, super.ID)
	u.TOTPSecret = old.SealFor(service.TOTPBinding(u.ID), []byte("seed"))
	if err := svc.Users.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := backup.WriteWith(ctx, src, ring, &buf, backup.Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Verify(bytes.NewReader(buf.Bytes()), ring, ""); err != nil {
		t.Fatalf("with both keys: %v", err)
	}
	if _, err := backup.Restore(ctx, memstore.New(), only2, bytes.NewReader(buf.Bytes()), false, ""); !errors.Is(err, backup.ErrKeyMissing) ||
		!strings.Contains(err.Error(), secure.KeyID(k1)) {
		t.Fatalf("without the old key: %v", err)
	}
}

// The partition key of a record is a property of the entity, rebuilt from it at restore (like the other index values): no
// backup format change, and every restored record has the key its entity gives, whichever backend restores it.
func TestRestoreKeepsPartitionKey(t *testing.T) {
	f := setup(t, 30)
	ctx := f.ctx
	data := f.backup(t)
	dst, err := sqlstore.Open(ctx, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "p.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if _, err := backup.Restore(ctx, dst, f.sealer, bytes.NewReader(data), false, ""); err != nil {
		t.Fatal(err)
	}
	checked := map[model.Kind]int{}
	for _, k := range model.Kinds() {
		if backup.Skipped(k) {
			continue
		}
		for after := ""; ; {
			page, err := f.src.List(ctx, k, store.ListQuery{After: after, Limit: 200})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Records) == 0 {
				break
			}
			after = page.Records[len(page.Records)-1].ID
			for _, want := range page.Records {
				got, err := dst.Lookup(ctx, k, want.ID)
				if err != nil {
					t.Fatalf("%s %s not restored: %v", k, want.ID, err)
				}
				if got.Partition != want.Partition {
					t.Errorf("%s %s: restored partition key %q, was %q", k, want.ID, got.Partition, want.Partition)
				}
				checked[k]++
			}
		}
	}
	if checked[model.KindUser] < 30 || checked[model.KindOrg] == 0 {
		t.Fatalf("records checked: %v", checked)
	}
	u, err := dst.Get(ctx, model.KindUser, f.user.ID)
	if err != nil || u.Partition != f.user.OrgID || u.Partition == "" {
		t.Fatalf("a user's partition key is its organization: %v %+v", err, u)
	}
	o, err := dst.Get(ctx, model.KindOrg, f.user.OrgID)
	if err != nil || o.Partition != "" {
		t.Fatalf("an organization is global: %v %+v", err, o)
	}
}
