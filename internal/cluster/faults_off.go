//go:build !faults

package cluster

// faultHooks are the faults a test injects into a node's store: none without the faults tag (faults.go).
type faultHooks struct{}

func (*faultHooks) lostReply() bool { return false }
