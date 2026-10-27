//go:build faults

package sqlstore

import (
	"context"
	"database/sql"
)

// Instrumentation for tests, built only with -tags faults (faults_off.go has the release build's no-op).

// partitionTxHook, when set, is called inside every partition write transaction before its work, with whether the
// transaction commits unsynced.
var partitionTxHook func(ctx context.Context, tx *sql.Tx, unsynced bool)

func partitionTxStarted(ctx context.Context, tx *sql.Tx, unsynced bool) {
	if partitionTxHook != nil {
		partitionTxHook(ctx, tx, unsynced)
	}
}
