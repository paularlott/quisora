package web

import (
	"crypto/tls"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
)

// certCheckEvery is how often the certificate files are looked at for a renewal: renewals come weeks before expiry,
// and SIGHUP loads one at once (a variable so tests can shorten it).
var certCheckEvery = time.Hour

// certSource serves the TLS certificate and replaces it without a restart: a configured tls_cert/tls_key pair when
// either file changes on disk (certbot, cert-manager or an operator renewing it), the self-signed certificate when
// it nears expiry, and either on Reload (SIGHUP). A pair that does not load (a renewal caught half-written, a
// mismatched key) leaves the current certificate in place and is tried again at the next check.
type certSource struct {
	certFile, keyFile, dir, host string
	log                          logger.Logger

	cur  atomic.Pointer[tls.Certificate]
	mu   sync.Mutex // one load at a time
	seen fileStamp  // the configured files as last loaded
	stop chan struct{}
	once sync.Once
}

// fileStamp identifies the content of the certificate and key files without reading them.
type fileStamp struct {
	certMod, keyMod   time.Time
	certSize, keySize int64
}

func stampOf(certFile, keyFile string) (fileStamp, error) {
	c, err := os.Stat(certFile)
	if err != nil {
		return fileStamp{}, err
	}
	k, err := os.Stat(keyFile)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{certMod: c.ModTime(), keyMod: k.ModTime(), certSize: c.Size(), keySize: k.Size()}, nil
}

func newCertSource(certFile, keyFile, dir, host string, log logger.Logger) (*certSource, error) {
	cs := &certSource{certFile: certFile, keyFile: keyFile, dir: dir, host: host, log: log, stop: make(chan struct{})}
	if err := cs.load(); err != nil {
		return nil, err
	}
	return cs, nil
}

// load reads the certificate (or makes the self-signed one) and makes it current.
func (cs *certSource) load() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	var st fileStamp
	if cs.certFile != "" {
		var err error
		if st, err = stampOf(cs.certFile, cs.keyFile); err != nil {
			return err
		}
	}
	c, err := LoadOrCreateCert(cs.certFile, cs.keyFile, cs.dir, cs.host)
	if err != nil {
		return err
	}
	cs.cur.Store(&c)
	cs.seen = st
	return nil
}

// due reports whether the certificate should be loaded again: the configured files changed, or the self-signed
// certificate is within 30 days of expiry (LoadOrCreateCert then makes a new one).
func (cs *certSource) due() bool {
	if cs.certFile == "" {
		c := cs.cur.Load()
		return c == nil || c.Leaf == nil || time.Until(c.Leaf.NotAfter) < 30*24*time.Hour
	}
	st, err := stampOf(cs.certFile, cs.keyFile)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return err == nil && st != cs.seen
}

// Reload loads the certificate again now (SIGHUP).
func (cs *certSource) Reload() error {
	err := cs.load()
	if err != nil {
		cs.log.Error("TLS certificate not reloaded: the current one stays in use", "error", err)
		return err
	}
	cs.log.Info("TLS certificate loaded", "not_after", cs.notAfter())
	return nil
}

func (cs *certSource) notAfter() time.Time {
	if c := cs.cur.Load(); c != nil && c.Leaf != nil {
		return c.Leaf.NotAfter
	}
	return time.Time{}
}

// watch checks for a renewal every certCheckEvery until Close.
func (cs *certSource) watch() {
	t := time.NewTicker(certCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-cs.stop:
			return
		case <-t.C:
			if cs.due() {
				_ = cs.Reload()
			}
		}
	}
}

func (cs *certSource) Close() { cs.once.Do(func() { close(cs.stop) }) }

// GetCertificate is the tls.Config hook: every handshake gets the current certificate.
func (cs *certSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cs.cur.Load(), nil
}
