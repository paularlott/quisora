package sqlstore

import (
	"context"
	"time"
)

// ServerTime is the database server's clock now. Nodes sharing a database stamp expiries (a code, a request_uri, a
// lease) with their own clocks, so each compares its clock with this one. The query returns microseconds since the
// Unix epoch, which spares reading a time zone back: MySQL and MariaDB convert with the session's zone, which is the
// zone their NOW() is in. SQLite is the process's own file: its clock is this machine's.
func (s *Store) ServerTime(ctx context.Context) (time.Time, error) {
	var q string
	switch {
	case s.d.isPG():
		q = "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000000)::bigint"
	case s.d.isMySQL():
		q = "SELECT CAST(UNIX_TIMESTAMP(NOW(6)) * 1000000 AS SIGNED)"
	default:
		return time.Now(), nil
	}
	var us int64
	if err := s.rdb.QueryRowContext(ctx, q).Scan(&us); err != nil {
		return time.Time{}, unavailable(err)
	}
	return time.UnixMicro(us), nil
}
