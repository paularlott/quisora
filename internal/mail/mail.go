// Package mail sends the transactional emails (invitation, password reset, address verification): SMTP with
// STARTTLS or implicit TLS, a queue on disk with retries, and durable single-use links from the service.
//
// Without an SMTP host there is no mailer at all: nothing is emailed, and administrators share invitation links
// themselves (see app.modules).
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

// Message is one outgoing email.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Transport delivers a message once: SMTP in the server, a capturing one in tests.
type Transport interface {
	Deliver(ctx context.Context, m Message) error
}

// TransportFunc adapts a function to Transport.
type TransportFunc func(ctx context.Context, m Message) error

func (f TransportFunc) Deliver(ctx context.Context, m Message) error { return f(ctx, m) }

// Mailer queues messages and delivers them with retries.
//
// The queue is on disk, in <data-dir>/mailqueue: a message is one file, written before Send returns, so it survives a
// restart (or a crash) and is delivered by the node once it is back. Each file is sealed with the master key: the
// messages carry single-use invitation and reset links. A file is removed once its message is delivered, or given up
// on after the last retry. After a master key change the queue is re-sealed with the active key (Reseal) before the
// node reports that key, so a rotation the cluster reports complete leaves no queued message needing a previous
// key. A message sealed with a key that is not configured is kept (and sent once that key is configured again).
type Mailer struct {
	Cfg *config.Config
	Log logger.Logger
	// Transport delivers messages (SMTP). A mailer is only made when an SMTP server is configured (config.Mail.Enabled).
	Transport Transport
	// Retry delays between attempts; the message is dropped (and logged) after the last one fails.
	Backoff []time.Duration

	// Svc issues the single-use links; set by SetService.
	Svc *service.Service

	dir    string
	sealer *secure.Sealer
	fileMu sync.Mutex // one change to a queued message's file at a time: the worker's, or Reseal's
	queued atomic.Int64
	kick   chan struct{}
	stop   chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
}

// queued is a message in the queue, as its file holds it (sealed).
type queued struct {
	Msg     Message   `json:"m"`
	Attempt int       `json:"a"` // failed deliveries so far
	Next    time.Time `json:"n"` // not before
}

// QueueSize bounds the queue; when it is full, new messages are refused (and logged). The queue is on disk, so this
// only stops a flood of messages SMTP cannot take from filling it.
const QueueSize = 10000

// queueBinding binds the sealed queue files to their purpose (secure.Sealer.SealFor).
const queueBinding = "mail/queue"

// New builds a mailer on the queue in cfg's data directory (made if missing) and starts its delivery worker, which
// first delivers whatever a previous run left queued through tr; call Close to stop it.
func New(cfg *config.Config, log logger.Logger, sealer *secure.Sealer, tr Transport) (*Mailer, error) {
	dir := cfg.DataPath(config.DirMailQueue)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mail queue: %w", err)
	}
	m := &Mailer{Cfg: cfg, Log: log, Transport: tr, Backoff: []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour},
		dir: dir, sealer: sealer, kick: make(chan struct{}, 1), stop: make(chan struct{})}
	m.removeTemp()
	m.Reseal()
	names, err := m.files()
	if err != nil {
		return nil, fmt.Errorf("mail queue: %w", err)
	}
	m.queued.Store(int64(len(names)))
	if len(names) > 0 {
		log.Info("mail queue: delivering messages left from before", "messages", len(names))
	}
	m.wg.Add(1)
	go m.run()
	return m, nil
}

// Close stops the worker; messages not yet delivered stay queued for the next start.
func (m *Mailer) Close() {
	m.once.Do(func() { close(m.stop) })
	m.wg.Wait()
}

// ErrQueueFull is returned when the queue is full.
var ErrQueueFull = errors.New("mail: queue full")

// Send queues msg for delivery and returns once it is on disk.
func (m *Mailer) Send(_ context.Context, msg Message) error {
	if _, err := mail.ParseAddress(msg.To); err != nil {
		return fmt.Errorf("mail: bad recipient: %w", err)
	}
	if m.queued.Load() >= QueueSize {
		m.Log.Error("mail queue full, refusing message", "to", msg.To, "subject", msg.Subject)
		return ErrQueueFull
	}
	name := fmt.Sprintf("%020d-%s.mail", time.Now().UnixNano(), randomHex(6)) // oldest first when listed
	if err := m.write(name, &queued{Msg: msg}); err != nil {
		m.Log.Error("mail queue: message not queued", "to", msg.To, "error", err)
		return err
	}
	m.queued.Add(1)
	select {
	case m.kick <- struct{}{}:
	default:
	}
	return nil
}

// write stores q as name, atomically: a crash leaves the old file or the new one, never part of one.
func (m *Mailer) write(name string, q *queued) error {
	b, err := json.Marshal(q)
	if err != nil {
		return err
	}
	return m.writeSealed(name, m.sealer.SealFor(queueBinding, b))
}

func (m *Mailer) writeSealed(name, sealed string) error {
	tmp := filepath.Join(m.dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(sealed), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(m.dir, name))
}

// Reseal re-seals every queued message with the active master key, and returns how many no configured key opens
// (those stay queued, and are sent once their key is configured again). Call it after the master keys change, before
// the node reports its new key (service.ReportMasterKey).
func (m *Mailer) Reseal() (unopenable int) {
	names, err := m.files()
	if err != nil {
		m.Log.Error("mail queue: cannot be read", "error", err)
		return 0
	}
	for _, name := range names {
		if err := m.reseal(name); err != nil {
			unopenable++
		}
	}
	if unopenable > 0 {
		m.Log.Error("mail queue: messages sealed with a master key that is not configured are kept until it is "+
			"(put it back in server.previous_master_keys)", "messages", unopenable)
	}
	return unopenable
}

func (m *Mailer) reseal(name string) error {
	m.fileMu.Lock()
	defer m.fileMu.Unlock()
	b, err := os.ReadFile(filepath.Join(m.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil // delivered meanwhile
	} else if err != nil {
		return err
	}
	sealed, err := m.sealer.Reseal(queueBinding, string(b))
	if err != nil || sealed == string(b) {
		return err
	}
	return m.writeSealed(name, sealed)
}

func (m *Mailer) read(name string) (*queued, error) {
	b, err := os.ReadFile(filepath.Join(m.dir, name))
	if err != nil {
		return nil, err
	}
	plain, err := m.sealer.OpenFor(queueBinding, string(b))
	if err != nil {
		return nil, err
	}
	var q queued
	return &q, json.Unmarshal(plain, &q)
}

func (m *Mailer) remove(name string) {
	if err := os.Remove(filepath.Join(m.dir, name)); err == nil {
		m.queued.Add(-1)
	}
}

// files lists the queued messages, oldest first. Temporary files are a Send writing one (or, at start, a write a
// crash cut short: removeTemp).
func (m *Mailer) files() ([]string, error) {
	ents, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if n := e.Name(); strings.HasSuffix(n, ".mail") && !strings.HasPrefix(n, ".") && e.Type().IsRegular() {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// removeTemp removes the temporary files of writes a crash cut short (their Send reported the failure). Only at
// start, before anything can be writing one.
func (m *Mailer) removeTemp() {
	ents, _ := os.ReadDir(m.dir)
	for _, e := range ents {
		if n := e.Name(); strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".tmp") {
			_ = os.Remove(filepath.Join(m.dir, n))
		}
	}
}

// idleCheck bounds how long the worker sleeps: it notices a retry that is due, or files put there by hand.
const idleCheck = time.Minute

func (m *Mailer) run() {
	defer m.wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-m.stop; cancel() }()
	for {
		wait := idleCheck
		if next := m.deliverDue(ctx); !next.IsZero() {
			wait = min(max(time.Until(next), 0), idleCheck)
		}
		t := time.NewTimer(wait)
		select {
		case <-m.stop:
			t.Stop()
			return
		case <-m.kick:
		case <-t.C:
		}
		t.Stop()
	}
}

// deliverDue tries every message that is due, and returns when the next waiting one is (zero: none waiting).
func (m *Mailer) deliverDue(ctx context.Context) time.Time {
	names, err := m.files()
	if err != nil {
		m.Log.Error("mail queue: cannot be read", "error", err)
		return time.Time{}
	}
	var next time.Time
	for _, name := range names {
		if ctx.Err() != nil {
			return time.Time{}
		}
		if due := m.deliverOne(ctx, name); !due.IsZero() && (next.IsZero() || due.Before(next)) {
			next = due
		}
	}
	return next
}

// deliverOne tries one queued message if it is due, and returns when it is next due (zero: no longer queued, cannot
// be opened yet, or the worker is stopping).
func (m *Mailer) deliverOne(ctx context.Context, name string) time.Time {
	m.fileMu.Lock()
	defer m.fileMu.Unlock()
	q, err := m.read(name)
	switch {
	case errors.Is(err, os.ErrNotExist), errors.Is(err, secure.ErrUnknownKey):
		return time.Time{} // gone, or sealed with a key not configured now: kept for when it is (Reseal logs it)
	case err != nil:
		m.Log.Error("mail queue: message cannot be read, dropping it", "file", name, "error", err)
		m.remove(name)
		return time.Time{}
	}
	if q.Next.After(time.Now()) {
		return q.Next
	}
	dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
	err = m.Transport.Deliver(dctx, q.Msg)
	dcancel()
	if err == nil {
		m.remove(name)
		return time.Time{}
	}
	if ctx.Err() != nil { // stopping: the attempt does not count
		return time.Time{}
	}
	if q.Attempt >= len(m.Backoff) {
		m.Log.Error("mail delivery failed, giving up", "to", q.Msg.To, "subject", q.Msg.Subject, "error", err)
		m.remove(name)
		return time.Time{}
	}
	delay := m.Backoff[q.Attempt]
	q.Attempt++
	q.Next = time.Now().Add(delay)
	m.Log.Warn("mail delivery failed, will retry", "to", q.Msg.To, "attempt", q.Attempt, "in", delay, "error", err)
	if err := m.write(name, q); err != nil {
		m.Log.Error("mail queue: retry not recorded", "to", q.Msg.To, "error", err)
	}
	return q.Next
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------------------------------------------
// SMTP transport

// SMTP delivers through cfg.Mail: TLS "starttls" (default, required), "tls" (implicit) or "none".
type SMTP struct {
	Cfg config.Mail
	// TLSConfig overrides the TLS settings (tests trust a self-signed server certificate).
	TLSConfig *tls.Config
}

func (t *SMTP) Deliver(ctx context.Context, m Message) error {
	port := t.Cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(t.Cfg.SMTPHost, strconv.Itoa(port))
	tc := t.TLSConfig
	if tc == nil {
		tc = &tls.Config{ServerName: t.Cfg.SMTPHost, MinVersion: tls.VersionTLS12}
	} else if tc.ServerName == "" {
		tc = tc.Clone()
		tc.ServerName = t.Cfg.SMTPHost
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if t.Cfg.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: tc}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, t.Cfg.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if t.Cfg.TLS == "" || t.Cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("mail: server does not offer STARTTLS")
		}
		if err := c.StartTLS(tc); err != nil {
			return err
		}
	}
	if t.Cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", t.Cfg.Username, t.Cfg.Password, t.Cfg.SMTPHost)); err != nil {
			return err
		}
	}
	from := t.Cfg.From
	if from == "" {
		from = "quisora@" + t.Cfg.SMTPHost
	}
	fa, err := mail.ParseAddress(from)
	if err != nil {
		return fmt.Errorf("mail: bad from address: %w", err)
	}
	if err := c.Mail(fa.Address); err != nil {
		return err
	}
	if err := c.Rcpt(clean(m.To)); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(Build(from, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// clean removes anything that could inject extra headers or SMTP commands.
func clean(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(strings.TrimSpace(s))
}

// Build renders msg as an RFC 5322 multipart/alternative message (text first, HTML preferred).
func Build(from string, m Message) []byte {
	var b bytes.Buffer
	var id [12]byte
	_, _ = rand.Read(id[:])
	host := "quisora.invalid"
	if fa, err := mail.ParseAddress(from); err == nil {
		if _, h, ok := strings.Cut(fa.Address, "@"); ok {
			host = h
		}
	}
	mp := multipart.NewWriter(&b)
	hdr := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	hdr("From", clean(from))
	hdr("To", clean(m.To))
	hdr("Subject", mime.QEncoding.Encode("utf-8", clean(m.Subject)))
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+host+">")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")
	hdr("Content-Type", "multipart/alternative; boundary="+mp.Boundary())
	b.WriteString("\r\n")
	part := func(ct, body string) {
		w, _ := mp.CreatePart(textproto.MIMEHeader{"Content-Type": {ct + "; charset=utf-8"},
			"Content-Transfer-Encoding": {"quoted-printable"}})
		q := quotedprintable.NewWriter(w)
		_, _ = q.Write([]byte(strings.ReplaceAll(body, "\r\n", "\n")))
		_ = q.Close()
	}
	part("text/plain", m.Text)
	if m.HTML != "" {
		part("text/html", m.HTML)
	}
	_ = mp.Close()
	return b.Bytes()
}

// Queued is the number of messages waiting to be sent.
func (m *Mailer) Queued() int { return int(m.queued.Load()) }
