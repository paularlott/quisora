package secure

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/paularlott/logger"
)

var (
	// cgnat is the carrier-grade NAT range, private in practice.
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	// metadata are cloud instance-metadata endpoints outside the link-local range (AWS over IPv6, Alibaba Cloud):
	// never reachable, whatever allow_private_networks says.
	metadata = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}
	nat64    = netip.MustParsePrefix("64:ff9b::/96")   // RFC 6052 well-known prefix: the last 32 bits are an IPv4 address
	nat64loc = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215 local-use NAT64
	sixto4   = netip.MustParsePrefix("2002::/16")      // RFC 3056: bits 16-47 are an IPv4 address
)

// BlockedAddr reports whether an outbound connection to a must be refused: unspecified, multicast and link-local
// addresses and cloud metadata endpoints always (169.254.169.254 is link-local); loopback, RFC 1918, CGNAT and
// unique-local addresses unless private networks are allowed. IPv6 addresses that carry an IPv4 address (NAT64,
// 6to4) are judged by that address.
func BlockedAddr(a netip.Addr, allowPrivate bool) bool {
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return true
	}
	for _, m := range metadata {
		if a == m {
			return true
		}
	}
	if a.Is6() {
		b := a.As16()
		switch {
		case nat64.Contains(a):
			return BlockedAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), allowPrivate)
		case sixto4.Contains(a):
			return BlockedAddr(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), allowPrivate)
		case nat64loc.Contains(a):
			return !allowPrivate
		}
	}
	if allowPrivate {
		return false
	}
	return a.IsLoopback() || a.IsPrivate() || cgnat.Contains(a)
}

// ErrDestination is returned when an outbound connection is refused by the address guard (errors.Is; the error
// itself is a *DestinationError).
var ErrDestination = errors.New("outbound connection to this address is not allowed")

// DestinationError is an outbound connection refused by the address guard.
type DestinationError struct {
	Addr netip.Addr
	// Private: refused only because private networks are not allowed (allow_private_networks would let it through).
	// Otherwise the address is never reachable (link-local, multicast, cloud metadata).
	Private bool
}

func (e *DestinationError) Error() string {
	if e.Private {
		return "outbound connection to " + e.Addr.String() + " refused: it is a private address and allow_private_networks is off"
	}
	return "outbound connection to " + e.Addr.String() + " is not allowed (link-local, multicast or cloud metadata address)"
}

// Is makes errors.Is(err, ErrDestination) hold.
func (e *DestinationError) Is(target error) bool { return target == ErrDestination }

// warnEvery spaces out the warnings for one host: a relying party that keeps failing logs once a minute, not per call.
const warnEvery = time.Minute

// OutboundClient is the HTTP client for requests to administrator-supplied URLs (sign-in providers, client JWKS,
// back-channel logout): the guard is applied to the address actually dialled (after DNS, so a name that resolves to
// an internal address is refused too), redirects are not followed, and roots (nil: the system's) verify TLS.
// allowPrivate is read at every connection. When the guard refuses a call, log (if not nil) gets a warning that names
// the host, the address and, for a private address, the setting that would allow it.
func OutboundClient(allowPrivate func() bool, roots *x509.CertPool, log logger.Logger) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if a := ap.Addr(); BlockedAddr(a, allowPrivate()) {
			return &DestinationError{Addr: a.Unmap(), Private: !BlockedAddr(a, true)}
		}
		return nil
	}}
	var rt http.RoundTripper = &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		MaxIdleConns:    64, MaxIdleConnsPerHost: 4, IdleConnTimeout: 60 * time.Second, ForceAttemptHTTP2: true}
	if log != nil {
		rt = &guardWarner{base: rt, log: log}
	}
	return &http.Client{
		Timeout:       10 * time.Second,
		Transport:     rt,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// guardWarner logs a warning when the address guard refuses a request, at most once per host per warnEvery.
type guardWarner struct {
	base  http.RoundTripper
	log   logger.Logger
	last  sync.Map     // host -> time.Time of the last warning
	swept atomic.Int64 // unix nanos of the last pruning of last
}

func (g *guardWarner) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := g.base.RoundTrip(r)
	var de *DestinationError
	if err == nil || !errors.As(err, &de) {
		return resp, err
	}
	now := time.Now()
	if t, ok := g.last.Load(r.URL.Host); ok && now.Sub(t.(time.Time)) < warnEvery {
		return resp, err
	}
	g.last.Store(r.URL.Host, now)
	if s := g.swept.Load(); now.UnixNano()-s > int64(warnEvery) && g.swept.CompareAndSwap(s, now.UnixNano()) {
		// Hosts warned about more than warnEvery ago would be warned about again anyway: forgotten, so made-up
		// hosts (a client_id metadata URL can name any) do not pile up.
		g.last.Range(func(k, v any) bool {
			if now.Sub(v.(time.Time)) >= warnEvery {
				g.last.Delete(k)
			}
			return true
		})
	}
	if de.Private {
		g.log.Warn("outbound call blocked: the host resolves to a private address and private networks are not allowed; "+
			"set server.allow_private_networks (QUISORA_ALLOW_PRIVATE_NETWORKS, --allow-private-networks) if it is meant to be reachable",
			"host", r.URL.Host, "address", de.Addr.String())
	} else {
		g.log.Warn("outbound call blocked: the host resolves to a link-local, multicast or cloud metadata address, which is never allowed",
			"host", r.URL.Host, "address", de.Addr.String())
	}
	return resp, err
}
