//go:build faults

package kvstore

import "sync/atomic"

// Instrumentation for tests, built only with -tags faults (faults_off.go has the release build's no-ops).
var (
	// retryConflicts counts the transactions retried after a conflict.
	retryConflicts atomic.Int64
	// importFallbacks counts the import batches that did not fit one transaction.
	importFallbacks atomic.Int64
)

func noteRetryConflict()  { retryConflicts.Add(1) }
func noteImportFallback() { importFallbacks.Add(1) }
