// Package mail sends the transactional emails (invitation, password reset, address verification): SMTP with
// STARTTLS or implicit TLS, a small in-memory retry queue, and durable single-use links from the service.
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
	"sync"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/service"
)

// Message is one outgoing email.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Transport delivers a message once. The SMTP transport is the default; tests substitute a capturing one.
type Transport interface {
	Deliver(ctx context.Context, m Message) error
}

// TransportFunc adapts a function to Transport.
type TransportFunc func(ctx context.Context, m Message) error

func (f TransportFunc) Deliver(ctx context.Context, m Message) error { return f(ctx, m) }

// Mailer queues messages and delivers them with retries.
type Mailer struct {
	Cfg *config.Config
	Log logger.Logger
	// Transport delivers messages (SMTP). A mailer is only made when an SMTP server is configured (config.Mail.Enabled).
	Transport Transport
	// Retry delays between attempts; the message is dropped (and logged) after the last one fails.
	Backoff []time.Duration

	// Svc issues the single-use links; set by SetService.
	Svc *service.Service

	queue chan *job
	stop  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

type job struct {
	msg     Message
	attempt int
}

// QueueSize bounds the in-memory outbox; when it is full, new messages are dropped with an error log.
const QueueSize = 1024

// New builds a mailer and starts its delivery worker; call Close to stop it.
func New(cfg *config.Config, log logger.Logger) *Mailer {
	m := &Mailer{Cfg: cfg, Log: log, Backoff: []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour},
		queue: make(chan *job, QueueSize), stop: make(chan struct{})}
	m.Transport = &SMTP{Cfg: cfg.Mail}
	m.wg.Add(1)
	go m.run()
	return m
}

// Close stops the worker; queued messages that have not been delivered are dropped.
func (m *Mailer) Close() {
	m.once.Do(func() { close(m.stop) })
	m.wg.Wait()
}

// ErrQueueFull is returned when the outbox is full.
var ErrQueueFull = errors.New("mail: outbox full")

// Send queues msg for delivery and returns immediately.
func (m *Mailer) Send(_ context.Context, msg Message) error {
	if _, err := mail.ParseAddress(msg.To); err != nil {
		return fmt.Errorf("mail: bad recipient: %w", err)
	}
	select {
	case m.queue <- &job{msg: msg}:
		return nil
	default:
		m.Log.Error("mail outbox full, dropping message", "to", msg.To, "subject", msg.Subject)
		return ErrQueueFull
	}
}

func (m *Mailer) run() {
	defer m.wg.Done()
	for {
		select {
		case <-m.stop:
			return
		case j := <-m.queue:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := m.Transport.Deliver(ctx, j.msg)
			cancel()
			if err == nil {
				continue
			}
			if j.attempt >= len(m.Backoff) {
				m.Log.Error("mail delivery failed, giving up", "to", j.msg.To, "subject", j.msg.Subject, "error", err)
				continue
			}
			delay := m.Backoff[j.attempt]
			j.attempt++
			m.Log.Warn("mail delivery failed, will retry", "to", j.msg.To, "attempt", j.attempt, "in", delay, "error", err)
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				t := time.NewTimer(delay)
				defer t.Stop()
				select {
				case <-m.stop:
				case <-t.C:
					select {
					case m.queue <- j:
					default:
						m.Log.Error("mail outbox full, dropping retry", "to", j.msg.To)
					}
				}
			}()
		}
	}
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
