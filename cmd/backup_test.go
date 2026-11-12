package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// The remote backup keeps only a complete download: it sends the token and the password (the server encrypts with
// it), and refuses a truncated stream and an error answer.
func TestRemoteBackup(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := memstore.New()
	if _, _, err := service.New(config.Default(), st, sealer).Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	const pw = "correct horse battery"
	var full bytes.Buffer
	if _, err := backup.WriteWith(ctx, st, sealer, &full, backup.Options{Password: pw}); err != nil {
		t.Fatal(err)
	}
	cut := full.Bytes()[:full.Len()/2]

	body := full.Bytes()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/backup" || r.Header.Get("X-Backup-Password") != pw || r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"You do not have permission to do that."}`))
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	var out bytes.Buffer
	stats, err := remoteBackup(ctx, srv.URL, "tok", "", true, pw, &out)
	if err != nil || stats.Total() == 0 || !bytes.Equal(out.Bytes(), full.Bytes()) {
		t.Fatalf("download: %v (%d records)", err, stats.Total())
	}
	if !backup.PasswordProtected(out.Bytes()) {
		t.Fatal("not encrypted")
	}
	if _, err := backup.Verify(bytes.NewReader(out.Bytes()), sealer, "wrong horse battery"); !errors.Is(err, backup.ErrPassword) {
		t.Fatalf("verify with a wrong password: %v", err)
	}
	if _, err := remoteBackup(ctx, srv.URL, "wrong", "", true, pw, io.Discard); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("refused token: %v", err)
	}
	if _, err := remoteBackup(ctx, srv.URL, "tok", "", false, pw, io.Discard); err == nil {
		t.Fatal("an unverified certificate was accepted")
	}
	body = cut
	if _, err := remoteBackup(ctx, srv.URL, "tok", "", true, pw, io.Discard); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("truncated download: %v", err)
	}
	if _, err := remoteBackup(ctx, "http://example.com", "tok", "", true, pw, io.Discard); err == nil {
		t.Fatal("plain http accepted")
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

func TestSummaryOrdered(t *testing.T) {
	if got := summary(backup.Stats{"users": 2, "orgs": 1}); got != "orgs 1, users 2" {
		t.Fatal(got)
	}
}

// An interrupted backup (Ctrl+C or SIGTERM at the password prompt, or while it writes) leaves no temporary file
// beside the target. The backup runs in a child process (this test binary again), which the test interrupts.
func TestBackupInterruptedLeavesNoFile(t *testing.T) {
	if args := os.Getenv("QUISORA_TEST_BACKUP_ARGS"); args != "" {
		os.Args = append([]string{"quisora"}, strings.Split(args, "\n")...)
		if err := newRoot(config.Default()).Execute(context.Background()); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	started := make(chan struct{}, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte{0x1f, 0x8b}) // the start of a download that never ends
		w.(http.Flusher).Flush()
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer srv.Close()
	for _, c := range []struct {
		name  string
		args  []string
		ready func()
	}{
		{"password prompt", []string{"backup", "out.bak"}, func() { time.Sleep(time.Second) }},
		{"download", []string{"backup", "--password-file", "pw", "--insecure", "--token", "t", "--server", srv.URL, "out.bak"}, func() { <-started }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, "")
			if err := os.WriteFile(filepath.Join(e.dir, "pw"), []byte("correct horse battery\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestBackupInterruptedLeavesNoFile$")
			child.Dir = e.dir
			child.Env = append(os.Environ(), "HOME="+e.dir, "QUISORA_TEST_BACKUP_ARGS="+
				strings.Join(append([]string{"--config", e.conf}, c.args...), "\n"))
			stdin, err := child.StdinPipe() // open and silent: the password is waited for
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			c.ready()
			_ = child.Process.Signal(syscall.SIGTERM)
			_ = child.Wait()
			left, _ := filepath.Glob(filepath.Join(e.dir, ".quisora-backup-*"))
			if len(left) > 0 {
				t.Fatalf("left behind: %v", left)
			}
		})
	}
}
