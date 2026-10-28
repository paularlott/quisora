package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// UseOnce records that the single-use value key (the caller namespaces it) was used, until expires, and reports
// false when it was used already. The record is a model.Replay, created only where none exists (the store lets one
// creation win): unlike state kept in one node's memory, it holds for every node and survives a node stopping or
// restarting.
func (s *Service) UseOnce(ctx context.Context, key string, expires time.Time) (bool, error) {
	sum := sha256.Sum256([]byte(key))
	err := s.Replays.Create(ctx, &model.Replay{Meta: model.Meta{ID: base64.RawURLEncoding.EncodeToString(sum[:])}, Expires: expires})
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrStale):
		return false, nil
	}
	return false, mapStore(err)
}

// Used reports whether UseOnce has recorded the single-use value key and still holds it, without recording it.
func (s *Service) Used(ctx context.Context, key string) (bool, error) {
	sum := sha256.Sum256([]byte(key))
	_, err := s.Replays.Get(ctx, base64.RawURLEncoding.EncodeToString(sum[:]))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	}
	return false, mapStore(err)
}
