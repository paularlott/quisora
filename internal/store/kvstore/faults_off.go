//go:build !faults

package kvstore

// The release build's no-ops for the instrumentation of faults.go.

func noteRetryConflict()  {}
func noteImportFallback() {}
