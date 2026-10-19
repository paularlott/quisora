package upstream_test

import "github.com/paularlott/quisora/internal/store"

// gn returns a pointer to the first name given to users that tests create.
func gn(s string) *string { return &s }

func storeQuery() store.ListQuery { return store.ListQuery{Limit: 100} }
