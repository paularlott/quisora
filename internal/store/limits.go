package store

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/paularlott/quisora/internal/model"
)

// The longest values a record may carry, the same in every store (a server database's columns are this wide, and the
// others keep to it so that what one store takes every store takes). Unique values have no limit.
const (
	// MaxIDLength is the longest record id and scope, in characters.
	MaxIDLength = 191
	// MaxPartitionLength is the longest partition key, in characters.
	MaxPartitionLength = 512
	// MaxFieldLength is the longest string field, in characters (a Words field: model.MaxTagsText).
	MaxFieldLength = 255
)

// MaxUniqueIndexKey is the longest unique value a store indexes as itself (UniqueIndexKey).
const MaxUniqueIndexKey = 512

// UniqueIndexKey is how a store indexes unique value u: as itself, or, longer than MaxUniqueIndexKey (or looking like a
// hash), as "#" and its SHA-256, so a value of any length is indexed whole within every engine's key limits (a SQL
// column, a Badger key); the same value always gives the same key, and the record keeps the value itself.
func UniqueIndexKey(u string) string {
	if len(u) <= MaxUniqueIndexKey && !strings.HasPrefix(u, "#") {
		return u
	}
	h := sha256.Sum256([]byte(u))
	return "#" + base64.RawURLEncoding.EncodeToString(h[:])
}

// CheckRecord refuses a record longer than the limits above (ErrBadRecord). Every store checks each record a write
// brings before it writes anything.
func CheckRecord(rec *Record) error {
	if rec == nil {
		return fmt.Errorf("%w: no record", ErrBadRecord)
	}
	if n := utf8.RuneCountInString(rec.ID); n > MaxIDLength {
		return fmt.Errorf("%w: a %s id of %d characters (at most %d)", ErrBadRecord, rec.Kind, n, MaxIDLength)
	}
	if n := utf8.RuneCountInString(rec.Scope); n > MaxIDLength {
		return fmt.Errorf("%w: a %s scope of %d characters (at most %d)", ErrBadRecord, rec.Kind, n, MaxIDLength)
	}
	if n := utf8.RuneCountInString(rec.Partition); n > MaxPartitionLength {
		return fmt.Errorf("%w: a %s partition key of %d characters (at most %d)", ErrBadRecord, rec.Kind, n, MaxPartitionLength)
	}
	schema := model.Schemas[rec.Kind]
	for name, v := range rec.Fields {
		s, ok := v.(string)
		if !ok {
			continue
		}
		max := MaxFieldLength
		if f, ok := schema.Field(name); ok && f.Words {
			max = model.MaxTagsText
		}
		if n := utf8.RuneCountInString(s); n > max {
			return fmt.Errorf("%w: the %s field %q of %d characters (at most %d)", ErrBadRecord, rec.Kind, name, n, max)
		}
	}
	return nil
}

// CheckTx is CheckRecord for every record of a transaction, and refuses one that writes a value unique across
// organizations (model.GlobalUnique: a gossip cluster reserves it with a write of its own, so a record holding one is
// written alone): ErrBadTx.
func CheckTx(ops []Op) error {
	for _, op := range ops {
		if err := CheckRecord(op.Rec); err != nil {
			return err
		}
		if op.Rec.Deleted {
			continue
		}
		for _, u := range op.Rec.Unique {
			if model.GlobalUnique(op.Rec.Kind, u) {
				return fmt.Errorf("%w: %s %s holds a value unique across organizations (it is written alone)", ErrBadTx,
					op.Rec.Kind, op.Rec.ID)
			}
		}
	}
	return nil
}

// CheckMove refuses a write of rec over a stored record (stored: there is one, in any state, with partition key
// oldPartition) that would change its partition key: a record never moves (ErrBadRecord). A tombstone takes the
// stored record's key.
func CheckMove(rec *Record, stored bool, oldPartition string) error {
	if !stored {
		return nil
	}
	if rec.Deleted {
		rec.Partition = oldPartition // a tombstone keeps the partition key of the record it deletes
		return nil
	}
	if rec.Partition != oldPartition {
		return fmt.Errorf("%w: %s %s is in partition %q, not %q (a record never moves)", ErrBadRecord, rec.Kind, rec.ID,
			oldPartition, rec.Partition)
	}
	return nil
}
