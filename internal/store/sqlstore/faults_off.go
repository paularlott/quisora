//go:build !faults

package sqlstore

import (
	"context"
	"database/sql"
)

// The release build's no-op for the instrumentation of faults.go.

func partitionTxStarted(context.Context, *sql.Tx, bool) {}
