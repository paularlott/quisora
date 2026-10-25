package cmd

import (
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
)

// env is a throwaway installation: a config file and data directory in a temp directory.
type env struct {
	dir, conf, key string
}

func newEnv(t *testing.T, extra string) env {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir) // no ~/.config/quisora/quisora.toml of the developer
	key := base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	conf := filepath.Join(dir, "quisora.toml")
	body := "[server]\nlisten = \"127.0.0.1:0\"\npublic_url = \"https://127.0.0.1:8443\"\ndata_dir = \"" +
		filepath.Join(dir, "data") + "\"\nmaster_key = \"" + key + "\"\n[log]\nlevel = \"error\"\n" + extra
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return env{dir, conf, key}
}

// run executes the command tree with args (after --config) and returns what it wrote to stdout and stderr.
func (e env) run(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	oldArgs, oldOut, oldErr, oldIn := os.Args, os.Stdout, os.Stderr, os.Stdin
	defer func() { os.Args, os.Stdout, os.Stderr, os.Stdin = oldArgs, oldOut, oldErr, oldIn }()
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	ri, wi, _ := os.Pipe()
	go func() { _, _ = io.WriteString(wi, stdin); wi.Close() }()
	os.Stdout, os.Stderr, os.Stdin = wo, we, ri
	outC, errC := make(chan string), make(chan string)
	go func() { b, _ := io.ReadAll(ro); outC <- string(b) }()
	go func() { b, _ := io.ReadAll(re); errC <- string(b) }()
	os.Args = append([]string{"quisora", "--config", e.conf}, args...)
	err = newRoot(config.Default()).Execute(context.Background())
	wo.Close()
	we.Close()
	return <-outC, <-errC, err
}

func TestBootstrapInviteSignOutBackupRestore(t *testing.T) {
	e := newEnv(t, "")
	out, errOut, err := e.run(t, "", "bootstrap")
	if err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, errOut)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "https://127.0.0.1:8443/") || !strings.Contains(errOut, "admin@example.com") {
		t.Fatalf("bootstrap output: %q / %q", out, errOut)
	}
	// a second run changes nothing and says so
	out, errOut, err = e.run(t, "", "bootstrap")
	if err != nil || out != "" || !strings.Contains(errOut, "Already set up") {
		t.Fatalf("second bootstrap: %v %q %q", err, out, errOut)
	}

	out, errOut, err = e.run(t, "", "invite", "primary", "admin@example.com")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(out), "https://") || !strings.Contains(errOut, "Single-use link") {
		t.Fatalf("invite: %v %q %q", err, out, errOut)
	}
	if _, _, err = e.run(t, "", "invite", "primary", "nobody@example.com"); err == nil {
		t.Fatal("invite for an unknown user succeeded")
	}

	// sign-out argument validation, the missing terminal and the real thing
	if _, _, err = e.run(t, "", "sign-out", "--reason", "x"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("neither --org nor --all: %v", err)
	}
	if _, _, err = e.run(t, "", "sign-out", "--reason", "x", "--all", "--org", "primary"); err == nil {
		t.Fatal("both --org and --all accepted")
	}
	if _, _, err = e.run(t, "", "sign-out", "--reason", "x", "--all"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("no terminal and no --yes: %v", err)
	}
	_, errOut, err = e.run(t, "", "sign-out", "--reason", "drill", "--all", "--yes", "--api-tokens")
	if err != nil || !strings.Contains(errOut, "Signed out every organization: removed 0 sessions") {
		t.Fatalf("sign-out all: %v %q", err, errOut)
	}
	if _, errOut, err = e.run(t, "", "sign-out", "--reason", "drill", "--org", "primary", "--yes"); err != nil || !strings.Contains(errOut, "organization primary") {
		t.Fatalf("sign-out org: %v %q", err, errOut)
	}
	if _, _, err = e.run(t, "", "sign-out", "--reason", "drill", "--org", "nosuch", "--yes"); err == nil {
		t.Fatal("sign-out of an unknown organization succeeded")
	}

	// set-primary: an unknown organization is refused
	if _, _, err = e.run(t, "", "set-primary", "nosuch", "--super-admin", "a@example.com"); err == nil {
		t.Fatal("set-primary of an unknown organization succeeded")
	}

	// backup (plain, encrypted with a password file), then restore into a fresh installation with the same key
	pwf := filepath.Join(e.dir, "pw")
	_ = os.WriteFile(pwf, []byte("correct horse battery\nignored\n"), 0o600)
	enc := filepath.Join(e.dir, "enc.bak")
	if _, errOut, err = e.run(t, "", "backup", "--password-file", pwf, enc); err != nil || !strings.Contains(errOut, ", encrypted (") {
		t.Fatalf("encrypted backup: %v %q", err, errOut)
	}
	short := filepath.Join(e.dir, "short")
	_ = os.WriteFile(short, []byte("tiny\n"), 0o600)
	if _, _, err = e.run(t, "", "backup", "--password-file", short, filepath.Join(e.dir, "x.bak")); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("short password: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "x.bak")); err == nil {
		t.Fatal("a failed backup left a file under the real name")
	}
	if _, _, err = e.run(t, "", "backup", "--password-file", filepath.Join(e.dir, "missing"), enc); err == nil {
		t.Fatal("missing password file accepted")
	}
	stdout, _, err := e.run(t, "", "backup", "--password-file", pwf, "-")
	if err != nil || len(stdout) == 0 {
		t.Fatalf("backup to stdout: %v", err)
	}
	if st, err := os.Stat(enc); err != nil || st.Mode().Perm() != 0o600 || st.Size() == 0 {
		t.Fatalf("backup file: %v %v", st, err)
	}

	// restore into the (non-empty) store is refused without --force and works with it
	if _, _, err = e.run(t, "", "restore", "--password-file", pwf, enc); err == nil {
		t.Fatal("restore into a non-empty store without --force")
	}
	if _, _, err = e.run(t, "", "restore", "--password-file", short, enc); err == nil {
		t.Fatal("restore with a wrong password")
	}
	if _, _, err = e.run(t, "", "restore", filepath.Join(e.dir, "missing.bak")); err == nil {
		t.Fatal("restore of a missing file")
	}

	// into an empty installation, from standard input
	e2 := newEnv(t, "")
	e2.key = e.key
	body := mustRead(t, enc)
	conf, _ := os.ReadFile(e.conf)
	if err := os.WriteFile(e2.conf, []byte(strings.NewReplacer(e.dir, e2.dir).Replace(string(conf))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, err = e2.run(t, string(body), "restore", "--password-file", pwf, "-"); err != nil || !strings.Contains(errOut, "Restored") {
		t.Fatalf("restore from stdin: %v %q", err, errOut)
	}
	if out, _, err = e2.run(t, "", "invite", "primary", "admin@example.com"); err != nil || out == "" {
		t.Fatalf("invite on the restored store: %v", err)
	}
}

func TestBootstrapRefusals(t *testing.T) {
	e := newEnv(t, "[cluster]\nbind = \"127.0.0.1:7946\"\nsize = 2\nkey = \""+
		base64.StdEncoding.EncodeToString(secure.RandomBytes(32))+"\"\npeers = [\"127.0.0.1:7947\"]\n")
	if _, _, err := e.run(t, "", "bootstrap"); err == nil || !strings.Contains(err.Error(), "--new-cluster") {
		t.Fatalf("gossip node without --new-cluster: %v", err)
	}
	bad := newEnv(t, "")
	_ = os.WriteFile(bad.conf, []byte("[server]\nlisten = \"nonsense\"\n"), 0o600)
	if _, _, err := bad.run(t, "", "bootstrap"); err == nil || !strings.Contains(err.Error(), "server.listen") {
		t.Fatalf("invalid configuration: %v", err)
	}
	for _, args := range [][]string{{"invite", "primary", "a@example.com"}, {"set-primary", "x", "--super-admin", "a@b.c"},
		{"sign-out", "--all", "--yes", "--reason", "r"}, {"backup", "--password-file", "x", "-"}, {"restore", "-"}, {"serve"}} {
		if _, _, err := bad.run(t, "", args...); err == nil {
			t.Fatalf("%v ran with an invalid configuration", args)
		}
	}
}

func TestForceStart(t *testing.T) {
	e := newEnv(t, "")
	if _, _, err := e.run(t, "", "force-start"); err == nil || !strings.Contains(err.Error(), "not part of a gossip cluster") {
		t.Fatalf("without cluster.bind: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	e = newEnv(t, "[cluster]\nbind = \"127.0.0.1:7946\"\nsize = 2\npeers = [\"127.0.0.1:7947\"]\nkey = \""+key+"\"\n")
	_, errOut, err := e.run(t, "", "force-start")
	if err != nil || !strings.Contains(errOut, "next start") {
		t.Fatalf("force-start: %v %q", err, errOut)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "data", cluster.ForceStartMarker)); err != nil {
		t.Fatalf("marker: %v", err)
	}
}

func TestHealthcheckCommand(t *testing.T) {
	e := newEnv(t, "")
	// nothing listens on port 1
	_ = os.WriteFile(e.conf, append(mustRead(t, e.conf), []byte("")...), 0o600)
	if _, _, err := e.run(t, "", "healthcheck", "--listen", "127.0.0.1:1"); err == nil {
		t.Fatal("healthcheck succeeded with no server")
	}
	if _, _, err := e.run(t, "", "healthcheck", "--ready", "--listen", "bad"); err == nil {
		t.Fatal("healthcheck accepted a bad listen address")
	}
}

func mustRead(t *testing.T, f string) []byte {
	t.Helper()
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGenkey(t *testing.T) {
	e := newEnv(t, "")
	out, _, err := e.run(t, "", "genkey")
	if err != nil {
		t.Fatal(err)
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil || len(k) != 32 {
		t.Fatalf("genkey %q: %v", out, err)
	}
}

func TestRootHelpAndUnknown(t *testing.T) {
	e := newEnv(t, "")
	if out, _, err := e.run(t, "", "--version"); err != nil || !strings.Contains(out, "quisora") {
		t.Fatalf("version: %v %q", err, out)
	}
	if _, _, err := e.run(t, "", "bogus"); err == nil {
		t.Fatal("unknown command accepted")
	}
	if c := Root(); c == nil || c.Name != "quisora" {
		t.Fatal("Root")
	}
}

func TestBackupPassword(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "pw")
	for body, want := range map[string]string{"secret pass 1\n": "secret pass 1", "a b\r\nrest": "a b", "nolf": "nolf"} {
		_ = os.WriteFile(f, []byte(body), 0o600)
		if got, err := backupPassword(f, true, false); err != nil || got != want {
			t.Fatalf("%q: %q %v", body, got, err)
		}
	}
	_ = os.WriteFile(f, []byte("  \nx"), 0o600)
	if _, err := backupPassword(f, true, false); err == nil || !strings.Contains(err.Error(), "no backup password") {
		t.Fatalf("blank: %v", err)
	}
	if _, err := backupPassword(filepath.Join(dir, "none"), true, false); err == nil || !strings.Contains(err.Error(), "--password-file") {
		t.Fatalf("missing file: %v", err)
	}
	// standard input as a pipe
	old := os.Stdin
	defer func() { os.Stdin = old }()
	r, w, _ := os.Pipe()
	_, _ = io.WriteString(w, "from a pipe pw\nmore")
	w.Close()
	os.Stdin = r
	if got, err := backupPassword("", true, true); err != nil || got != "from a pipe pw" {
		t.Fatalf("stdin: %q %v", got, err)
	}
	r, w, _ = os.Pipe()
	w.Close()
	os.Stdin = r
	if _, err := backupPassword("", true, false); err == nil {
		t.Fatal("empty stdin accepted")
	}
}

func TestConfirmSignOutNeedsTerminal(t *testing.T) {
	old := os.Stdin
	defer func() { os.Stdin = old }()
	r, w, _ := os.Pipe()
	w.Close()
	os.Stdin = r
	if err := confirmSignOut("everyone", "everyone", true); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("%v", err)
	}
}

func TestWarnLooseFiles(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("posix permissions")
	}
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	_ = os.WriteFile(tok, []byte("t"), 0o644)
	conf := filepath.Join(dir, "q.toml")
	_ = os.WriteFile(conf, []byte("[server]\nmaster_key = \"abc\"\n"), 0o644)
	cfg := config.Default()
	cfg.Secrets.Vault.TokenFile = tok
	c := parsed(t, cfg, "--config", conf, "serve")
	cfg.Secrets.Vault.TokenFile = tok
	var b strings.Builder
	warnLooseFiles(&b, cfg, c)
	if !strings.Contains(b.String(), tok) {
		t.Fatalf("token file not warned about: %q", b.String())
	}
	if !secretInFile(cfg, c) {
		t.Fatal("a master key in the file is a secret in the file")
	}
	if !strings.Contains(b.String(), conf) {
		t.Fatalf("config file with a secret not warned about: %q", b.String())
	}
	_ = os.Chmod(tok, 0o600)
	_ = os.Chmod(conf, 0o600)
	b.Reset()
	warnLooseFiles(&b, cfg, c)
	if b.Len() != 0 {
		t.Fatalf("0600 files warned about: %q", b.String())
	}
}

func TestPrepareAndLogger(t *testing.T) {
	cfg := config.Default()
	cfg.Cluster.Size = 3 // size without bind
	if err := prepare(context.Background(), cfg); err == nil {
		t.Fatal("invalid configuration prepared")
	}
	if logger(config.Default()) == nil {
		t.Fatal("logger")
	}
}

func TestSummaryOrdered(t *testing.T) {
	if got := summary(backup.Stats{"users": 2, "orgs": 1}); got != "orgs 1, users 2" {
		t.Fatal(got)
	}
}

// Flags of one command must not leak into another: the commands add their own flags to one shared server-flag slice.
func TestCommandFlagsDoNotClobberEachOther(t *testing.T) {
	e := newEnv(t, "")
	for _, args := range [][]string{{"invite", "--break-glass", "primary", "a@example.com"}, {"backup", "--plain", "--server", "x", "-"},
		{"restore", "--force", "-"}, {"healthcheck", "--ready"}} {
		if _, _, err := e.run(t, "", args...); err != nil && strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%v: %v", args, err)
		}
	}
}
