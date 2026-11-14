package ephemeral

import "time"

// SetNow replaces the clock the held budgets' windows are told by, and returns what puts it back.
func SetNow(f func() time.Time) (restore func()) {
	old := now
	now = f
	return func() { now = old }
}
