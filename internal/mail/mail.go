// Package mail sends the transactional emails (invitation, password reset, address verification): SMTP with
// STARTTLS or implicit TLS, a durable queue with retries (package queue), and durable single-use links from the
// service.
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
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/queue"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
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

// Mailer queues messages and delivers them with retries. The queue is this node's, in the store (package queue): a
// message is written before Send returns, survives a restart or a crash, is sealed with the master key (the messages
// carry single-use invitation and reset links) and is re-sealed after a master key change (Reseal).
type Mailer struct {
	Cfg *config.Config
	Log logger.Logger
	// Svc issues the single-use links; set by SetService.
	Svc *service.Service

	q *queue.Queue[Message]
}

// QueueSize bounds this node's queue; when it is full, new messages are refused (and logged). The queue is in the
// store, so this only stops a flood of messages SMTP cannot take from filling it.
const QueueSize = 10000

// DefaultBackoff are the delays between delivery attempts; a message is given up on (and logged) after the last.
var DefaultBackoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

// New builds a mailer on node's mail queue in st and starts its delivery worker, which first delivers whatever a
// previous run of the node left queued through tr; call Close to stop it. backoff replaces DefaultBackoff when given.
func New(cfg *config.Config, log logger.Logger, st store.Store, node string, sealer *secure.Sealer, tr Transport,
	backoff ...time.Duration) *Mailer {
	if len(backoff) == 0 {
		backoff = DefaultBackoff
	}
	m := &Mailer{Cfg: cfg, Log: log}
	m.q = queue.Open(queue.Options[Message]{
		Name: "mail", Log: log, Store: st, Node: node, Sealer: sealer, Binding: "mail/queue", Backoff: backoff,
		Max: QueueSize, Deliver: tr.Deliver,
		Failed: func(msg Message, attempt int, retry time.Duration, err error) {
			if retry == 0 {
				log.Error("mail delivery failed, giving up", "to", msg.To, "subject", msg.Subject, "error", err)
			} else {
				log.Warn("mail delivery failed, will retry", "to", msg.To, "attempt", attempt, "in", retry, "error", err)
			}
		}})
	return m
}

// Close stops the worker; messages not yet delivered stay queued for the next start.
func (m *Mailer) Close() { m.q.Close() }

// Queued returns how many messages are waiting to be sent.
func (m *Mailer) Queued() int { return m.q.Queued() }

// Reseal re-seals the queued messages with the active master key, returning how many still need a previous key and
// how many need one that is not configured (queue.Queue.Reseal).
func (m *Mailer) Reseal() (stale, lost int) { return m.q.Reseal() }

// ErrQueueFull is returned when the queue is full.
var ErrQueueFull = queue.ErrFull

// Send queues msg for delivery and returns once it is stored.
func (m *Mailer) Send(_ context.Context, msg Message) error {
	if _, err := mail.ParseAddress(msg.To); err != nil {
		return fmt.Errorf("mail: bad recipient: %w", err)
	}
	if err := m.q.Add(msg, 0, 0); err != nil {
		if errors.Is(err, queue.ErrFull) {
			m.Log.Error("mail queue full, refusing message", "to", msg.To, "subject", msg.Subject)
		} else {
			m.Log.Error("mail queue: message not queued", "to", msg.To, "error", err)
		}
		return err
	}
	return nil
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
