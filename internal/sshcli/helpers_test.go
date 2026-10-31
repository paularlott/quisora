package sshcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// syncBuffer is a buffer the command writes to while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testEnv is an Env that writes into buffers, keeps its files in a temp directory, has no agent unless the test
// gives one, and records its sleeps instead of waiting.
type testEnv struct {
	*Env
	out, err *syncBuffer
	mu       sync.Mutex
	sleeps   []time.Duration
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "") // never the developer's agent
	te := &testEnv{out: &syncBuffer{}, err: &syncBuffer{}}
	te.Env = &Env{Out: te.out, Err: te.err, Dir: filepath.Join(t.TempDir(), "quisora"),
		Sleep: func(ctx context.Context, d time.Duration) error {
			te.mu.Lock()
			te.sleeps = append(te.sleeps, d)
			te.mu.Unlock()
			return ctx.Err()
		}}
	return te
}

func (te *testEnv) slept() []time.Duration {
	te.mu.Lock()
	defer te.mu.Unlock()
	return append([]time.Duration(nil), te.sleeps...)
}

// lifetimeAgent is an in-memory agent that remembers the lifetime each key was added with.
type lifetimeAgent struct {
	agent.Agent
	mu        sync.Mutex
	lifetimes []uint32
}

func (a *lifetimeAgent) Add(k agent.AddedKey) error {
	a.mu.Lock()
	a.lifetimes = append(a.lifetimes, k.LifetimeSecs)
	a.mu.Unlock()
	return a.Agent.Add(k)
}

// refusingAgent is an agent that takes no key added to it, as the ones that keep their keys to themselves
// (1Password, Secretive) answer.
type refusingAgent struct{ agent.Agent }

func (refusingAgent) Add(agent.AddedKey) error { return errors.New("agent: refused") }

// serveAgent serves an in-memory agent on a unix socket and returns the agent and the socket's path. (The socket's
// directory is made under the system's temporary directory: unix socket paths are short.)
func serveAgent(t *testing.T) (*lifetimeAgent, string) {
	t.Helper()
	ag := &lifetimeAgent{Agent: agent.NewKeyring()}
	return ag, serveAgentOf(t, ag)
}

// serveAgentOf serves ag on a unix socket and returns the socket's path.
func serveAgentOf(t *testing.T, ag agent.Agent) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "q")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(ag, c); c.Close() }()
		}
	}()
	return sock
}

// parseCert reads a certificate file.
func parseCert(t *testing.T, path string) *ssh.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("%s is not a certificate", path)
	}
	return c
}

// keygenL runs `ssh-keygen -L -f path` when ssh-keygen is installed and returns its output.
func keygenL(t *testing.T, path string) string {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Log("ssh-keygen not installed: certificate not checked with it")
		return ""
	}
	out, err := exec.Command(bin, "-L", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -L -f %s: %v\n%s", path, err, out)
	}
	return string(out)
}

func mustContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s lacks %q:\n%s", what, sub, s)
		}
	}
}

func mustNotContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			t.Errorf("%s has %q:\n%s", what, sub, s)
		}
	}
}

// f2CA is another certificate authority key.
func f2CA() ssh.Signer {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(k)
	return s
}
