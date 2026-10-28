package sqlstore

import (
	"context"
	"testing"
	"time"
)

// The database's time agrees with this machine's (the test databases run on it), whatever zone the session is in:
// nodes compare their clocks in UTC, so a zone that leaked into the reading would show as hours of skew. (SQLite has
// no server: its clock is the process's.)
func TestServerTime(t *testing.T) {
	ctx := context.Background()
	forEachDialect(t, dialects[1:], func(t *testing.T, d testDialect) {
		s, _ := openTest(t, d.name, d.env, 1) // one connection: the zone set below stays with it
		defer s.Close()
		zone := map[string]string{"postgres": "SET TIME ZONE 'Asia/Tokyo'", "mysql": "SET time_zone = '+05:30'",
			"mariadb": "SET time_zone = '+05:30'"}[d.name]
		for _, set := range []string{"", zone} {
			if set != "" {
				if _, err := s.rdb.ExecContext(ctx, set); err != nil {
					t.Fatal(err)
				}
			}
			now, err := s.ServerTime(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if off := time.Since(now); off > 5*time.Second || off < -5*time.Second {
				t.Fatalf("%s (%q): the database's time %s is %s from this machine's", d.name, set, now, off)
			}
		}
	})
}
