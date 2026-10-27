//go:build faults

package cluster

// faultHooks are the faults a test injects into a node's store (built with the faults tag only: a production binary
// has none).
type faultHooks struct {
	// loseReply makes a write that landed report an unknown outcome when it returns true (the reply lost), for the
	// settling to settle.
	loseReply func() bool
}

// lostReply reports whether the reply of a write that landed is to be lost (loseReply).
func (h *faultHooks) lostReply() bool { return h.loseReply != nil && h.loseReply() }
