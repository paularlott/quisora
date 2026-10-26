package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/config"
)

// fakeSMTP is a tiny SMTP server: optional STARTTLS, AUTH PLAIN, and message capture.
type fakeSMTP struct {
	ln       net.Listener
	tlsCfg   *tls.Config
	implicit bool
	mu       sync.Mutex
	got      []string
	auth     string
	usedTLS  bool
}

func startSMTP(t *testing.T, implicit bool, offerStartTLS bool) *fakeSMTP {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	ts.Close()
	f := &fakeSMTP{tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}}, implicit: implicit}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if implicit {
		ln = tls.NewListener(ln, f.tlsCfg)
	}
	f.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, offerStartTLS)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn, offer bool) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	w("220 fake ESMTP")
	secure := f.implicit
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			w("250-fake")
			if offer && !secure {
				w("250-STARTTLS")
			}
			w("250 AUTH PLAIN")
		case cmd == "STARTTLS":
			w("220 go ahead")
			tc := tls.Server(c, f.tlsCfg)
			if tc.Handshake() != nil {
				return
			}
			c, r, secure = tc, bufio.NewReader(tc), true
			w = func(s string) { _, _ = tc.Write([]byte(s + "\r\n")) }
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			f.mu.Lock()
			f.auth = strings.TrimSpace(line)
			f.mu.Unlock()
			w("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"):
			w("250 ok")
		case cmd == "DATA":
			w("354 go")
			var body strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				body.WriteString(l)
			}
			f.mu.Lock()
			f.got = append(f.got, body.String())
			f.usedTLS = secure
			f.mu.Unlock()
			w("250 queued")
		case cmd == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func smtpTransport(f *fakeSMTP, mode string) *SMTP {
	host, port, _ := net.SplitHostPort(f.ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return &SMTP{Cfg: config.Mail{SMTPHost: host, SMTPPort: p, TLS: mode, From: "Acme <no-reply@example.com>",
		Username: "user", Password: "pw"}, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
}

func TestSMTPModes(t *testing.T) {
	msg := Message{To: "bob@example.com", Subject: "Hi", Text: "hello", HTML: "<p>hello</p>"}
	for _, tc := range []struct {
		name     string
		implicit bool
		offer    bool
		mode     string
	}{{"starttls", false, true, "starttls"}, {"default is starttls", false, true, ""}, {"implicit tls", true, false, "tls"}} {
		t.Run(tc.name, func(t *testing.T) {
			f := startSMTP(t, tc.implicit, tc.offer)
			if err := smtpTransport(f, tc.mode).Deliver(context.Background(), msg); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.got) != 1 || !strings.Contains(f.got[0], "To: bob@example.com") || !f.usedTLS || f.auth == "" {
				t.Fatalf("got=%v tls=%v auth=%q", f.got, f.usedTLS, f.auth)
			}
		})
	}
	t.Run("none", func(t *testing.T) {
		f := startSMTP(t, false, false)
		if err := smtpTransport(f, "none").Deliver(context.Background(), msg); err != nil {
			t.Fatal(err)
		}
		if f.usedTLS {
			t.Fatal("tls used in none mode")
		}
	})
	t.Run("starttls required", func(t *testing.T) {
		f := startSMTP(t, false, false) // server does not offer STARTTLS
		if err := smtpTransport(f, "starttls").Deliver(context.Background(), msg); err == nil {
			t.Fatal("sent in clear although STARTTLS is required")
		}
	})
}

func TestSMTPErrors(t *testing.T) {
	msg := Message{To: "bob@example.com", Subject: "Hi", Text: "hello"}
	ctx := context.Background()
	t.Run("connection refused", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := ln.Addr().(*net.TCPAddr)
		ln.Close()
		tr := &SMTP{Cfg: config.Mail{SMTPHost: "127.0.0.1", SMTPPort: addr.Port, TLS: "none"}}
		if err := tr.Deliver(ctx, msg); err == nil {
			t.Fatal("delivered to nothing")
		}
		tr.Cfg.TLS = "tls"
		if err := tr.Deliver(ctx, msg); err == nil {
			t.Fatal("delivered to nothing over TLS")
		}
	})
	t.Run("bad from", func(t *testing.T) {
		f := startSMTP(t, false, true)
		tr := smtpTransport(f, "starttls")
		tr.Cfg.From = "not an address"
		if err := tr.Deliver(ctx, msg); err == nil || !strings.Contains(err.Error(), "from") {
			t.Fatalf("bad from: %v", err)
		}
	})
	t.Run("default from and no auth", func(t *testing.T) {
		f := startSMTP(t, false, false)
		tr := smtpTransport(f, "none")
		tr.Cfg.From, tr.Cfg.Username = "", ""
		if err := tr.Deliver(ctx, msg); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.auth != "" || len(f.got) != 1 || !strings.Contains(f.got[0], "From: quisora@127.0.0.1") {
			t.Fatalf("auth=%q got=%v", f.auth, f.got)
		}
	})
	t.Run("untrusted certificate", func(t *testing.T) {
		f := startSMTP(t, false, true)
		tr := smtpTransport(f, "starttls")
		tr.TLSConfig = nil // verify against system roots: the fake's certificate is self-signed
		if err := tr.Deliver(ctx, msg); err == nil {
			t.Fatal("self-signed certificate accepted")
		}
	})
	t.Run("server name defaults to host", func(t *testing.T) {
		f := startSMTP(t, true, false)
		tr := smtpTransport(f, "tls")
		tr.TLSConfig = &tls.Config{InsecureSkipVerify: true, ServerName: ""}
		if err := tr.Deliver(ctx, msg); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("recipient header injection is stripped", func(t *testing.T) {
		f := startSMTP(t, false, false)
		m := msg
		m.To = "bob@example.com\r\nBcc: evil@example.com"
		if err := smtpTransport(f, "none").Deliver(ctx, m); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.got) != 1 || strings.Contains(f.got[0], "\r\nBcc:") {
			t.Fatalf("injected header: %v", f.got)
		}
	})
}
