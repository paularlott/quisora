package store

import "context"

type durableKey struct{}

// WithDurable marks a write as security-critical: in a replicated cluster the write call returns once enough peers
// to make a majority with this node hold it, or once they failed to confirm it in time (see docs/REPLICATION.md,
// "Durable writes"; with cluster.strict_durability the write then fails with ErrUnconfirmed).
func WithDurable(ctx context.Context) context.Context {
	return context.WithValue(ctx, durableKey{}, true)
}

// WithoutDurable clears the WithDurable mark (for a follow-up write that must not wait for the peers again).
func WithoutDurable(ctx context.Context) context.Context {
	return context.WithValue(ctx, durableKey{}, false)
}

// IsDurable reports whether ctx was marked with WithDurable.
func IsDurable(ctx context.Context) bool { v, _ := ctx.Value(durableKey{}).(bool); return v }
