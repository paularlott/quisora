package sshe2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sshdConfig is the server's configuration, as the guide's "Ubuntu server setup" lays it out. Root may log in as far
// as sshd is concerned (it has no principals file, so that is what refuses it), and no other way in is open.
const sshdConfig = `Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
LogLevel VERBOSE
UsePAM yes
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile none
TrustedUserCAKeys /etc/ssh/quisora_user_ca.pub
RevokedKeys /etc/ssh/quisora.krl
AuthorizedPrincipalsFile /etc/ssh/principals/%u
`

// dockerfile is an Ubuntu 24.04 sshd with the users ubuntu, alice and bob (accounts without a password: only a
// certificate gets in), and everything that changes between runs copied in last so the package layer is cached.
const dockerfile = `FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /etc/ssh/principals
RUN id ubuntu >/dev/null 2>&1 || useradd -m -s /bin/bash ubuntu
RUN useradd -m -s /bin/bash alice && useradd -m -s /bin/bash bob
RUN usermod -p '*' root && usermod -p '*' ubuntu && usermod -p '*' alice && usermod -p '*' bob
COPY sshd_config /etc/ssh/sshd_config
COPY quisora_user_ca.pub quisora.krl ssh_host_ed25519_key ssh_host_ed25519_key-cert.pub /etc/ssh/
COPY principals/ /etc/ssh/principals/
RUN chmod 600 /etc/ssh/ssh_host_ed25519_key && chmod 644 /etc/ssh/ssh_host_ed25519_key-cert.pub /etc/ssh/quisora_user_ca.pub /etc/ssh/quisora.krl
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
`

// principalFiles are /etc/ssh/principals/<account>: members of the group ops may log in as ubuntu (a group's principal
// is "group:<name>"; a username is bare), alice as alice.
var principalFiles = map[string]string{"ubuntu": "group:ops\n", "alice": "alice\n", "bob": "bob\n"}

// run runs a program and returns its combined output.
func run(timeout time.Duration, dir, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("%w (timed out after %v)", err, timeout)
	}
	return out.String(), err
}

// requireE2E skips the test unless it is asked for and everything it needs is there.
func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("QUISORA_SSH_E2E") != "1" {
		t.Skip("set QUISORA_SSH_E2E=1 to run the SSH end-to-end test against sshd in Docker (task test-ssh-e2e)")
	}
	for _, tool := range []string{"docker", "ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	if out, err := run(20*time.Second, "", "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		t.Skipf("docker is not usable: %v: %s", err, strings.TrimSpace(out))
	}
}

// sshd is a running container.
type sshd struct {
	name  string
	image string
	port  string // the published port on 127.0.0.1
}

// startSSHD builds the image from the files in ctxDir (its Dockerfile is written here) and starts a container from it,
// and removes both when the test ends. The container's logs are logged if the test failed (or QUISORA_SSH_E2E_LOGS=1).
func startSSHD(t *testing.T, ctxDir string, files map[string]string) *sshd {
	t.Helper()
	id := make([]byte, 4)
	_, _ = rand.Read(id)
	d := &sshd{name: "quisora-ssh-e2e-" + hex.EncodeToString(id)}
	d.image = d.name
	write := func(name, content string) {
		p := filepath.Join(ctxDir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("Dockerfile", dockerfile)
	write("sshd_config", sshdConfig)
	for name, content := range principalFiles {
		write("principals/"+name, content)
	}
	for name, content := range files {
		write(name, content)
	}
	if err := os.Chmod(filepath.Join(ctxDir, "ssh_host_ed25519_key"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if t.Failed() || os.Getenv("QUISORA_SSH_E2E_LOGS") == "1" {
			t.Logf("sshd container logs:\n%s", d.logs())
		}
		_, _ = run(time.Minute, "", "docker", "rm", "-f", d.name)
		_, _ = run(time.Minute, "", "docker", "rmi", "-f", d.image)
	})
	if out, err := run(10*time.Minute, ctxDir, "docker", "build", "-q", "-t", d.image, "."); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	if out, err := run(time.Minute, "", "docker", "run", "-d", "--name", d.name, "-p", "127.0.0.1::22", d.image); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	out, err := run(30*time.Second, "", "docker", "port", d.name, "22/tcp")
	if err != nil {
		t.Fatalf("docker port: %v\n%s", err, out)
	}
	line := strings.TrimSpace(strings.Split(out, "\n")[0])
	i := strings.LastIndex(line, ":")
	if i < 0 {
		t.Fatalf("docker port answered %q", out)
	}
	d.port = line[i+1:]
	d.waitReady(t)
	return d
}

// waitReady waits until sshd answers with its banner (Docker accepts connections on the published port before the
// server in the container does).
func (d *sshd) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+d.port, 2*time.Second)
		if err == nil {
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 8)
			n, _ := c.Read(buf)
			c.Close()
			if strings.HasPrefix(string(buf[:n]), "SSH-2.0-") || strings.HasPrefix(string(buf[:n]), "SSH-") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshd does not answer on 127.0.0.1:%s: %v\n%s", d.port, err, d.logs())
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// logs is everything the container has written so far (sshd logs to its standard error).
func (d *sshd) logs() string {
	out, _ := run(30*time.Second, "", "docker", "logs", d.name)
	return out
}

// copyIn puts the local file at path in the container (as root, mode as it is).
func (d *sshd) copyIn(t *testing.T, local, path string) {
	t.Helper()
	if out, err := run(time.Minute, "", "docker", "cp", local, d.name+":"+path); err != nil {
		t.Fatalf("docker cp %s: %v\n%s", path, err, out)
	}
}

// expectLog waits for sshd to have logged substr after the log's first from bytes (see logLen).
func (d *sshd) expectLog(t *testing.T, from int, substr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		l := d.logs()
		if len(l) >= from && strings.Contains(l[from:], substr) {
			return
		}
		if time.Now().After(deadline) {
			var tail string
			if len(l) >= from {
				tail = l[from:]
			}
			t.Errorf("sshd did not log %q; what it logged meanwhile:\n%s", substr, tail)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// logLen is the size of the log now: pass it to expectLog to look only at what comes after.
func (d *sshd) logLen() int { return len(d.logs()) }
