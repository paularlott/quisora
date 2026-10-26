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
		strict, permit := BlockedAddr(a, Reach{}), BlockedAddr(a, Reach{Private: true})
		if strict != tc.strict || permit != tc.permit {
			t.Errorf("%s: blocked %v/%v, want %v/%v", tc.addr, strict, permit, tc.strict, tc.permit)
		}
	}
}

// allowed_networks lets through the private networks it lists, and only those; never what is always refused.
func TestBlockedAddrAllowedNetworks(t *testing.T) {
	r := Reach{Networks: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("10.9.8.7/32"),
		netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fd12::/16")}}
	for addr, blocked := range map[string]bool{
		"172.16.4.10":       false, // listed network
		"172.31.255.1":      false,
		"::ffff:172.20.0.1": false, // IPv4-mapped
		"64:ff9b::ac10:40a": false, // NAT64 of 172.16.4.10
		"fd12:1::1":         false,
		"10.9.8.7":          false, // listed address
		"10.9.8.8":          true,  // private, not listed
		"192.168.1.1":       true,
		"127.0.0.1":         true,
		"169.254.169.254":   true, // listed, but link-local and metadata: never
		"64:ff9b:1::ac10:1": true, // local-use NAT64 outside the listed IPv6 network
		"8.8.8.8":           false,
	} {
		if got := BlockedAddr(netip.MustParseAddr(addr), r); got != blocked {
			t.Errorf("%s: blocked %v, want %v", addr, got, blocked)
		}
	}
}

func TestOutboundClientGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	var reach Reach
	log := &warnLog{}
	c := OutboundClient(func() Reach { return reach }, nil, log)
	_, err := c.Get(srv.URL)
	if err == nil || !errors.Is(err, ErrDestination) {
		t.Fatalf("loopback reached: %v", err)
	}
	// The error and the log say why: a private address, fixable with allowed_networks or allow_private_networks.
	var de *DestinationError
	if !errors.As(err, &de) || !de.Private || de.Addr.String() != "127.0.0.1" || !strings.Contains(err.Error(), "allowed_networks") {
		t.Fatalf("error does not explain the refusal: %v", err)
	}
	if log.count() != 1 || !strings.Contains(log.msgs[0], "allowed_networks") || !strings.Contains(log.msgs[0], "allow_private_networks") {
		t.Fatalf("warnings: %q", log.msgs)
	}
	_, _ = c.Get(srv.URL) // the same host again within a minute: no second warning
	if log.count() != 1 {
		t.Fatalf("warning repeated: %q", log.msgs)
	}
	for _, r := range []Reach{{Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}, {Private: true}} {
		reach = r // read at each connection
		res, err := c.Get(srv.URL)
		if err != nil || res.StatusCode != 204 {
			t.Fatalf("allowed by %+v: %v", r, err)
		}
		res.Body.Close()
	}
}

// Special-purpose IPv4 ranges are refused whatever allow_private_networks says.
func TestBlockedSpecialPurposeRanges(t *testing.T) {
	for _, s := range []string{"0.1.2.3", "192.0.0.8", "198.18.0.1", "198.19.255.254", "240.0.0.1", "255.255.255.254"} {
		if !BlockedAddr(netip.MustParseAddr(s), Reach{Private: true}) {
			t.Errorf("%s allowed", s)
		}
	}
	if BlockedAddr(netip.MustParseAddr("198.20.0.1"), Reach{}) {
		t.Error("a public address next to the benchmarking range blocked")
	}
}

// A refused destination says why: a private address can be allowed by configuration, a link-local one never.
func TestDestinationErrorMessages(t *testing.T) {
	e := &DestinationError{Addr: netip.MustParseAddr("10.0.0.1"), Private: true}
	if !strings.Contains(e.Error(), "allow_private_networks") {
		t.Fatal(e.Error())
	}
	e.Private = false
	if !strings.Contains(e.Error(), "link-local") || !errors.Is(e, ErrDestination) {
		t.Fatal(e.Error())
	}
}
