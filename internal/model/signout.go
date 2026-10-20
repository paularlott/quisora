package model

import "time"

// Emergency sign-out ("break glass"). An organization, and the server as a whole, keep sign-out counters. Every
// browser session, refresh grant and personal API token is stamped with the counters current when it was made, and
// works only while its stamp is still current: pulling the lever increments a counter, which ends at once everything
// stamped before it. It is one small write, so it cannot be half done, and it does not depend on the nodes' clocks
// (a credential made on a node that has not yet seen the new counter is stamped with the old one and ends too).
// Records from before the counters existed carry zeros, which stay current until the first pull.

// SignOutCounters are the counters of an organization, or of the server (kept on the primary organization).
type SignOutCounters struct {
	Sessions  uint64 `msgpack:"s,omitempty" json:"-"` // browser sessions and refresh grants (so access tokens)
	APITokens uint64 `msgpack:"t,omitempty" json:"-"` // personal API tokens
}

// SignOutStamp is what a credential was made under: the server's and its organization's counter of its kind.
type SignOutStamp struct {
	Server uint64 `msgpack:"s,omitempty"`
	Org    uint64 `msgpack:"o,omitempty"`
}

// Current reports whether a credential with this stamp still works, given the counters it must have reached.
func (s SignOutStamp) Current(want SignOutStamp) bool {
	return s.Server >= want.Server && s.Org >= want.Org
}

// SignOutEvent records the last time a lever was pulled, for the console (the audit log has every one).
type SignOutEvent struct {
	At        time.Time `msgpack:"at" json:"at"`
	By        string    `msgpack:"by" json:"by"` // username of who pulled it
	Reason    string    `msgpack:"r" json:"reason"`
	APITokens bool      `msgpack:"t" json:"api_tokens"` // personal API tokens ended too
}

// MaxSignOutReason bounds the reason given for an emergency sign-out.
const MaxSignOutReason = 500
