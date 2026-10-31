package cmd

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
)

// env is a throwaway installation: a config file and data directory in a temp directory.
type env struct {
	dir, conf, key string
	public         string // server.public_url: an address nothing answers at (freePublicURL)
}

func newEnv(t *testing.T, extra string) env {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir) // no ~/.config/quisora/quisora.toml of the developer
	key := base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	conf := filepath.Join(dir, "quisora.toml")
	public := freePublicURL(t)
	body := "[server]\nlisten = \"127.0.0.1:0\"\npublic_url = \"" + public + "\"\ndata_dir = \"" +
		filepath.Join(dir, "data") + "\"\nmaster_key = \"" + key + "\"\n[log]\nlevel = \"error\"\n" + extra
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return env{dir, conf, key, public}
}

// freePublicURL returns a public URL at a port nothing listens on: the operator commands try a running server at
// server.public_url first, and the one a developer runs (https://127.0.0.1:8443, say) must not be the one they reach.
func freePublicURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return "https://" + l.Addr().String()
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

func mustRead(t *testing.T, f string) []byte {
	t.Helper()
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
