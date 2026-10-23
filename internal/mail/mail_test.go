package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func newMailer(t *testing.T, mut func(*config.Config)) *Mailer {
	t.Helper()
	cfg := config.Default()
	cfg.Server.PublicURL = "https://quisora.example.test"
	cfg.UI.SiteName = "Acme ID"
	if mut != nil {
		mut(cfg)
	}
	cfg.Server.DataDir = t.TempDir()
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(cfg, logger.NewNullLogger(), sealer)
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	m.SetService(service.New(cfg, st, sealer))
	t.Cleanup(func() { m.Close(); _ = st.Close() })
	return m
}

type capture struct {
	mu   sync.Mutex
	msgs []Message
	ch   chan Message
}

func newCapture() *capture { return &capture{ch: make(chan Message, 16)} }
func (c *capture) Deliver(_ context.Context, m Message) error {
	c.mu.Lock()
	c.msgs = append(c.msgs, m)
	c.mu.Unlock()
	c.ch <- m
	return nil
}
func (c *capture) wait(t *testing.T) Message {
	t.Helper()
	select {
	case m := <-c.ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message delivered")
	}
	return Message{}
}

func TestTemplatesAndLinks(t *testing.T) {
	m := newMailer(t, nil)
	cap := newCapture()
	m.Transport = cap
	ctx := context.Background()
	org, err := m.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("widgets"), DisplayName: ptr("Widgets")})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: ptr("ann"), GivenName: ptr("Ann <b>"), Email: ptr("ann@example.com")})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		purpose string
		send    func() error
		subject string
		path    string
	}{
		{service.LinkInvite, func() error { return m.SendInvite(ctx, u, org) }, "invited to Acme ID", "/invite?token="},
		{service.LinkReset, func() error { return m.SendReset(ctx, u, org) }, "Reset your Acme ID password", "/reset?token="},
		{service.LinkVerify, func() error { return m.SendVerify(ctx, u, org) }, "Confirm your email", "/verify-email?token="},
	} {
		if err := tc.send(); err != nil {
			t.Fatal(err)
		}
		msg := cap.wait(t)
		if msg.To != "ann@example.com" || !strings.Contains(msg.Subject, tc.subject) {
			t.Fatalf("%s: %+v", tc.purpose, msg)
		}
		i := strings.Index(msg.Text, "https://quisora.example.test"+tc.path)
		if i < 0 {
			t.Fatalf("%s: link missing in text: %s", tc.purpose, msg.Text)
		}
		link := strings.Fields(msg.Text[i:])[0]
		tok := strings.TrimPrefix(link, "https://quisora.example.test"+tc.path)
		if strings.Contains(msg.HTML, "Ann <b>") || !strings.Contains(msg.HTML, "Ann &lt;b&gt;") {
			t.Fatalf("%s: html not escaped: %s", tc.purpose, msg.HTML)
		}
		if !strings.Contains(msg.HTML, link) {
			t.Fatalf("%s: link missing in html", tc.purpose)
		}
		// Wrong purpose never redeems, the right one works exactly once.
		if _, _, err := m.Svc.PeekLink(ctx, tok, service.LinkVerify+"x"); !errors.Is(err, service.ErrLink) {
			t.Fatal("purpose mismatch accepted")
		}
		l, got, err := m.Svc.PeekLink(ctx, tok, tc.purpose)
		if err != nil || l.Purpose != tc.purpose || got.ID != u.ID {
			t.Fatalf("peek: %v %v", l, err)
		}
		if tc.purpose == service.LinkVerify && l.Email != "ann@example.com" {
			t.Fatalf("verification link lost the address: %q", l.Email)
		}
		if _, _, err := m.Svc.RedeemLink(ctx, tok, tc.purpose); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.Svc.RedeemLink(ctx, tok, tc.purpose); !errors.Is(err, service.ErrLink) {
			t.Fatal("link reusable")
		}
	}
	if err := m.SendReset(ctx, &model.User{Meta: model.Meta{ID: "x"}}, org); err == nil {
		t.Fatal("user without email accepted")
	}
	if err := m.Send(ctx, Message{To: "not an address"}); err == nil {
		t.Fatal("bad recipient accepted")
	}
}

func TestSendInviteLinkAndExpiry(t *testing.T) {
	m := newMailer(t, nil)
	cap := newCapture()
	m.Transport = cap
	ctx := context.Background()
	org, _ := m.Svc.PrimaryOrg(ctx)
	if org == nil {
		var err error
		if org, err = m.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")}); err != nil {
			t.Fatal(err)
		}
	}
	u, err := m.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: ptr("bob"), Email: ptr("bob@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	link, exp, err := m.Svc.CreateInvite(ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SendInviteLink(ctx, u, org, link, exp); err != nil {
		t.Fatal(err)
	}
	msg := cap.wait(t)
	if !strings.Contains(msg.Text, link) || !strings.Contains(msg.Text, "7 days") {
		t.Fatalf("invite mail: %s", msg.Text)
	}
	// Mailing a new invitation revokes the one issued before.
	if err := m.SendInvite(ctx, u, org); err != nil {
		t.Fatal(err)
	}
	cap.wait(t)
	tok := strings.TrimPrefix(link, "https://quisora.example.test/invite?token=")
	if _, _, err := m.Svc.PeekLink(ctx, tok, service.LinkInvite); err == nil {
		t.Fatal("older invitation still valid")
	}
	// No service: link mails are refused rather than sent without a token.
	bareCfg := config.Default()
	bareCfg.Server.DataDir = t.TempDir()
	bare, err := New(bareCfg, logger.NewNullLogger(), m.sealer)
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Close()
	if err := bare.SendReset(ctx, u, org); err == nil {
		t.Fatal("reset mail without a service")
	}
}

func ptr[T any](v T) *T { return &v }

func TestHumanTTL(t *testing.T) {
	for d, want := range map[time.Duration]string{7 * 24 * time.Hour: "7 days", 24 * time.Hour: "24 hours", time.Hour: "1 hour",
		2 * time.Hour: "2 hours", 10 * time.Minute: "10 minutes", time.Second: "1 minute"} {
		if got := humanTTL(d); got != want {
			t.Errorf("%v: %q want %q", d, got, want)
		}
	}
}

func TestRetryQueue(t *testing.T) {
	m := newMailer(t, nil)
	m.Backoff = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	var tries atomic.Int32
	cap := newCapture()
	m.Transport = TransportFunc(func(ctx context.Context, msg Message) error {
		if tries.Add(1) < 3 {
			return errors.New("temporary failure")
		}
		return cap.Deliver(ctx, msg)
	})
	if err := m.Send(context.Background(), Message{To: "a@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatal(err)
	}
	cap.wait(t)
	if tries.Load() != 3 {
		t.Fatalf("tries %d", tries.Load())
	}

	// Gives up after the last backoff.
	var n atomic.Int32
	m.Transport = TransportFunc(func(context.Context, Message) error { n.Add(1); return errors.New("down") })
	_ = m.Send(context.Background(), Message{To: "a@example.com"})
	time.Sleep(300 * time.Millisecond)
	if n.Load() != 3 {
		t.Fatalf("expected 3 attempts then give up, got %d", n.Load())
	}
}

func TestBuildMessage(t *testing.T) {
	raw := Build("Acme <no-reply@example.com>", Message{To: "bob@example.com\r\nBcc: evil@example.com",
		Subject: "Héllo\r\nX-Injected: 1", Text: "plain é", HTML: "<p>html</p>"})
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Bcc") != "" || msg.Header.Get("X-Injected") != "" {
		t.Fatal("header injection")
	}
	if !strings.HasPrefix(msg.Header.Get("Content-Type"), "multipart/alternative") {
		t.Fatal(msg.Header.Get("Content-Type"))
	}
	b, _ := io.ReadAll(msg.Body)
	if !strings.Contains(string(b), "text/plain") || !strings.Contains(string(b), "text/html") {
		t.Fatalf("parts: %s", b)
	}
	if !strings.Contains(msg.Header.Get("Subject"), "=?utf-8?q?") {
		t.Fatalf("subject not encoded: %q", msg.Header.Get("Subject"))
	}
}

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

// The queue is on disk: a message not yet delivered when the mailer stops goes out from the next one on the same
// data directory. The files are sealed (no address or link readable on disk), and one that cannot be opened (sealed
// under a master key since removed) is dropped rather than retried for ever.
func TestQueueSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.DataDir = dir
	m, err := New(cfg, logger.NewNullLogger(), sealer)
	if err != nil {
		t.Fatal(err)
	}
	m.Backoff = []time.Duration{time.Hour} // the first attempt fails, the retry is far off
	m.Transport = TransportFunc(func(context.Context, Message) error { return errors.New("smtp down") })
	secret := "https://quisora.example.test/reset?token=s3cr3t"
	if err := m.Send(context.Background(), Message{To: "ann@example.com", Subject: "Reset", Text: secret}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return queuedAttempts(t, m) == 1 })
	m.Close()

	files, _ := os.ReadDir(cfg.DataPath(config.DirMailQueue))
	if len(files) != 1 {
		t.Fatalf("queue holds %d files", len(files))
	}
	raw, _ := os.ReadFile(filepath.Join(cfg.DataPath(config.DirMailQueue), files[0].Name()))
	if strings.Contains(string(raw), "ann@example.com") || strings.Contains(string(raw), "s3cr3t") {
		t.Fatal("queued message readable on disk")
	}

	// The next start delivers it once its retry is due (made due here), and removes the file.
	q, _ := m.read(files[0].Name())
	q.Next = time.Time{}
	if err := m.write(files[0].Name(), q); err != nil {
		t.Fatal(err)
	}
	cap := newCapture()
	m2, err := newWith(cfg, sealer, cap)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	if got := cap.wait(t); got.To != "ann@example.com" || got.Text != secret {
		t.Fatalf("delivered %+v", got)
	}
	waitFor(t, func() bool { return m2.Queued() == 0 })

	// sealed under another master key: dropped, not retried
	other, _ := secure.NewSealer(secure.RandomBytes(32))
	foreign := &Mailer{dir: cfg.DataPath(config.DirMailQueue), sealer: other}
	if err := foreign.write("00000000000000000001-aa.mail", &queued{Msg: Message{To: "x@example.com"}}); err != nil {
		t.Fatal(err)
	}
	m3, err := newWith(cfg, sealer, newCapture())
	if err != nil {
		t.Fatal(err)
	}
	defer m3.Close()
	waitFor(t, func() bool { files, _ := os.ReadDir(cfg.DataPath(config.DirMailQueue)); return len(files) == 0 })
}

// newWith makes a mailer whose transport is set before its worker reads the queue (a restart with messages waiting).
func newWith(cfg *config.Config, sealer *secure.Sealer, tr Transport) (*Mailer, error) {
	old := testTransport
	testTransport = tr
	defer func() { testTransport = old }()
	return New(cfg, logger.NewNullLogger(), sealer)
}

func queuedAttempts(t *testing.T, m *Mailer) int {
	names, _ := m.files()
	if len(names) != 1 {
		return -1
	}
	q, err := m.read(names[0])
	if err != nil {
		t.Fatal(err)
	}
	return q.Attempt
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestQueueFull(t *testing.T) {
	m := newMailer(t, nil)
	m.queued.Store(QueueSize)
	if err := m.Send(context.Background(), Message{To: "a@example.com"}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full queue: %v", err)
	}
}

// Messages sent while the worker reads the queue are never lost to it, and a temporary file a crash left behind is
// cleared at the next start.
func TestQueueConcurrentSends(t *testing.T) {
	m := newMailer(t, nil)
	cap := newCapture()
	cap.ch = make(chan Message, 200)
	m.Transport = cap
	_ = os.WriteFile(filepath.Join(m.dir, ".leftover.mail.tmp"), []byte("x"), 0o600)
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Send(context.Background(), Message{To: "a@example.com", Subject: strconv.Itoa(i)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	waitFor(t, func() bool { cap.mu.Lock(); defer cap.mu.Unlock(); return len(cap.msgs) == 100 })
	m2, err := New(m.Cfg, logger.NewNullLogger(), m.sealer)
	if err != nil {
		t.Fatal(err)
	}
	m2.Close()
	if _, err := os.Stat(filepath.Join(m.dir, ".leftover.mail.tmp")); !os.IsNotExist(err) {
		t.Fatal("a crash's temporary file was not cleared at start")
	}
}
