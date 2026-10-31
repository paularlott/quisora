package cmd

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/secure"
)

// One installation goes through the operator commands in order: each step needs what the one before left behind.
func TestOperatorCommandsEndToEnd(t *testing.T) {
	e := newEnv(t, "")
	pwf := filepath.Join(e.dir, "pw")
	enc := filepath.Join(e.dir, "enc.bak")
	short := filepath.Join(e.dir, "short")

	t.Run("bootstrap", func(t *testing.T) {
		out, errOut, err := e.run(t, "", "bootstrap")
		if err != nil {
			t.Fatalf("bootstrap: %v\n%s", err, errOut)
		}
		if !strings.HasPrefix(strings.TrimSpace(out), e.public+"/") || !strings.Contains(errOut, "admin@example.com") {
			t.Fatalf("bootstrap output: %q / %q", out, errOut)
		}
		// a second run changes nothing and says so
		out, errOut, err = e.run(t, "", "bootstrap")
		if err != nil || out != "" || !strings.Contains(errOut, "Already set up") {
			t.Fatalf("second bootstrap: %v %q %q", err, out, errOut)
		}
	})

	t.Run("invite", func(t *testing.T) {
		out, errOut, err := e.run(t, "", "invite", "primary", "admin@example.com")
		if err != nil || !strings.HasPrefix(strings.TrimSpace(out), "https://") || !strings.Contains(errOut, "Single-use link") {
			t.Fatalf("invite: %v %q %q", err, out, errOut)
		}
		if _, _, err = e.run(t, "", "invite", "primary", "nobody@example.com"); err == nil {
			t.Fatal("invite for an unknown user succeeded")
		}
		if _, _, err = e.run(t, "", "invite", "--super-admin", "primary", "admin@example.com"); err == nil || !strings.Contains(err.Error(), "--break-glass") {
			t.Fatalf("--super-admin without --break-glass: %v", err)
		}
		if out, _, err = e.run(t, "", "invite", "--break-glass", "--super-admin", "primary", "admin@example.com"); err != nil || !strings.HasPrefix(strings.TrimSpace(out), "https://") {
			t.Fatalf("invite --break-glass --super-admin: %v %q", err, out)
		}
	})

	// argument validation, the missing terminal and the real thing
	t.Run("sign-out", func(t *testing.T) {
		if _, _, err := e.run(t, "", "sign-out", "--reason", "x"); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("neither --org nor --all: %v", err)
		}
		if _, _, err := e.run(t, "", "sign-out", "--reason", "x", "--all", "--org", "primary"); err == nil {
			t.Fatal("both --org and --all accepted")
		}
		if _, _, err := e.run(t, "", "sign-out", "--reason", "x", "--all"); err == nil || !strings.Contains(err.Error(), "--yes") {
			t.Fatalf("no terminal and no --yes: %v", err)
		}
		_, errOut, err := e.run(t, "", "sign-out", "--reason", "drill", "--all", "--yes", "--api-tokens")
		if err != nil || !strings.Contains(errOut, "Signed out every organization: removed 0 sessions") {
			t.Fatalf("sign-out all: %v %q", err, errOut)
		}
		if _, errOut, err = e.run(t, "", "sign-out", "--reason", "drill", "--org", "primary", "--yes"); err != nil || !strings.Contains(errOut, "organization primary") {
			t.Fatalf("sign-out org: %v %q", err, errOut)
		}
		if _, _, err = e.run(t, "", "sign-out", "--reason", "drill", "--org", "nosuch", "--yes"); err == nil {
			t.Fatal("sign-out of an unknown organization succeeded")
		}
	})

	// plain, then encrypted with a password file
	t.Run("backup", func(t *testing.T) {
		_ = os.WriteFile(pwf, []byte("correct horse battery\nignored\n"), 0o600)
		_, errOut, err := e.run(t, "", "backup", "--password-file", pwf, enc)
		if err != nil || !strings.Contains(errOut, ", encrypted (") {
			t.Fatalf("encrypted backup: %v %q", err, errOut)
		}
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
	})

	t.Run("restore", func(t *testing.T) {
		// into the (non-empty) store it is refused without --force
		if _, _, err := e.run(t, "", "restore", "--password-file", pwf, enc); err == nil {
			t.Fatal("restore into a non-empty store without --force")
		}
		if _, _, err := e.run(t, "", "restore", "--password-file", short, enc); err == nil {
			t.Fatal("restore with a wrong password")
		}
		if _, _, err := e.run(t, "", "restore", filepath.Join(e.dir, "missing.bak")); err == nil {
			t.Fatal("restore of a missing file")
		}

		// into an empty installation with the same key, from standard input
		e2 := newEnv(t, "")
		e2.key = e.key
		body := mustRead(t, enc)
		conf, _ := os.ReadFile(e.conf)
		if err := os.WriteFile(e2.conf, []byte(strings.NewReplacer(e.dir, e2.dir).Replace(string(conf))), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, errOut, err := e2.run(t, string(body), "restore", "--password-file", pwf, "-"); err != nil || !strings.Contains(errOut, "Restored") {
			t.Fatalf("restore from stdin: %v %q", err, errOut)
		}
		if out, _, err := e2.run(t, "", "invite", "primary", "admin@example.com"); err != nil || out == "" {
			t.Fatalf("invite on the restored store: %v", err)
		}
	})
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
	for _, args := range [][]string{{"invite", "primary", "a@example.com"},
		{"sign-out", "--all", "--yes", "--reason", "r"}, {"backup", "--password-file", "x", "-"}, {"restore", "-"}, {"serve"}} {
		if _, _, err := bad.run(t, "", args...); err == nil {
			t.Fatalf("%v ran with an invalid configuration", args)
		}
	}
}
