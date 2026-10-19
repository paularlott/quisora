package secure

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/paularlott/logger"
)

// warnLog records Warn calls.
type warnLog struct {
	logger.NullLogger
	mu   sync.Mutex
	msgs []string
}

func (l *warnLog) Warn(msg string, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, msg)
}

func (l *warnLog) count() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.msgs) }

func TestBlockedAddr(t *testing.T) {
	for _, tc := range []struct {
		addr           string
		strict, permit bool // blocked without / with allow_private_networks
	}{
		{"169.254.169.254", true, true}, // cloud metadata: always
		{"fe80::1", true, true},
		{"0.0.0.0", true, true},
		{"224.0.0.1", true, true},
		{"127.0.0.1", true, false},
		{"::1", true, false},
		{"10.1.2.3", true, false},
		{"192.168.8.10", true, false},
		{"100.64.0.1", true, false},
		{"::ffff:10.0.0.1", true, false},
		{"fd00:ec2::254", true, true},      // AWS metadata over IPv6: always
		{"100.100.100.200", true, true},    // Alibaba Cloud metadata: always
		{"64:ff9b::a9fe:a9fe", true, true}, // NAT64 of 169.254.169.254
		{"64:ff9b::7f00:1", true, false},   // NAT64 of 127.0.0.1
		{"64:ff9b::808:808", false, false}, // NAT64 of 8.8.8.8
		{"2002:a9fe:a9fe::1", true, true},  // 6to4 of 169.254.169.254
		{"2002:c0a8:0101::1", true, false}, // 6to4 of 192.168.1.1
		{"64:ff9b:1::1", true, false},      // local-use NAT64
		{"fd12:3456::1", true, false},      // unique local
		{"8.8.8.8", false, false},
		{"2606:4700::1111", false, false},
	} {
		a := netip.MustParseAddr(tc.addr)
		if BlockedAddr(a, false) != tc.strict || BlockedAddr(a, true) != tc.permit {
			t.Errorf("%s: blocked %v/%v, want %v/%v", tc.addr, BlockedAddr(a, false), BlockedAddr(a, true), tc.strict, tc.permit)
		}
	}
}

func TestOutboundClientGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	allow := false
	log := &warnLog{}
	c := OutboundClient(func() bool { return allow }, nil, log)
	_, err := c.Get(srv.URL)
	if err == nil || !errors.Is(err, ErrDestination) {
		t.Fatalf("loopback reached: %v", err)
	}
	// The error and the log say why: a private address, fixable with allow_private_networks.
	var de *DestinationError
	if !errors.As(err, &de) || !de.Private || de.Addr.String() != "127.0.0.1" || !strings.Contains(err.Error(), "allow_private_networks") {
		t.Fatalf("error does not explain the refusal: %v", err)
	}
	if log.count() != 1 || !strings.Contains(log.msgs[0], "allow_private_networks") {
		t.Fatalf("warnings: %q", log.msgs)
	}
	_, _ = c.Get(srv.URL) // the same host again within a minute: no second warning
	if log.count() != 1 {
		t.Fatalf("warning repeated: %q", log.msgs)
	}
	allow = true
	res, err := c.Get(srv.URL)
	if err != nil || res.StatusCode != 204 {
		t.Fatalf("allowed: %v", err)
	}
	res.Body.Close()
}
