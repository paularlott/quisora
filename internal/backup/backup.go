// Package backup writes every live record of a store to a portable stream and restores such a stream into an
// empty store of any backend.
//
// The stream is gzip-compressed JSON lines: a header, one line per record, and a trailer with the record count and
// an HMAC of every line before it under a key derived from the master key. A truncated, altered or forged backup is
// refused as a whole before anything is written. Records keep their ids, versions, generations (Epoch, Created) and
// origins, so a restored node rejoins a cluster without its data looking newer than it is. Secrets stay sealed with
// the master key: the header carries a check value derived from it, and a restore with a different key is refused
// (the sealed data would be unreadable).
//
// Optionally (Options.Encrypt) the whole compressed stream is encrypted with AES-256-GCM under a key derived from the
// master key, in authenticated chunks (a STREAM construction: a truncated, reordered or altered file is refused), so
// the backup file reveals nothing — not even the names and addresses that are not sealed. Restore and Verify detect
// an encrypted backup by its magic bytes.
//
// Where the backend offers a point-in-time view (store.Snapshotter: Badger, SQLite, PostgreSQL, MySQL, MariaDB) the
// backup reads through it and is a consistent snapshot of the whole store. Otherwise (Valkey) it reads the live store
// page by page: every record that existed throughout the backup is in it, records written meanwhile may or may not
// be.
//
// The format has no compatibility with backups made by earlier pre-release builds (version 3; older versions are
// refused).
package backup

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

const (
	format   = "quisora-backup"
	version  = 3
	pageSize = 1000
	maxLine  = 16 << 20 // one record line, base64 of the entity: far above any real record
)

var (
	// ErrNotEmpty means the target store already holds records (restore needs Force).
	ErrNotEmpty = errors.New("backup: the target store is not empty")
	// ErrKey means the backup was made with another master key.
	ErrKey = errors.New("backup: made with a different master key; configure the master key of the server it came from")
	// ErrFormat means the stream is not a complete, unaltered Quisora backup.
	ErrFormat = errors.New("backup: not a complete, unaltered Quisora backup")
)

type header struct {
	Format   string    `json:"format"`
	Version  int       `json:"version"`
	Created  time.Time `json:"created"`
	KeyCheck string    `json:"key_check"`
}

type line struct {
	Kind    model.Kind    `json:"k,omitempty"`
	ID      string        `json:"i,omitempty"`
	Version hlc.Timestamp `json:"v,omitempty"`
	Epoch   hlc.Timestamp `json:"e,omitempty"` // store.Record.Epoch
	Created hlc.Timestamp `json:"c,omitempty"` // store.Record.Created
	Origin  string        `json:"o,omitempty"`
	Data    string        `json:"d,omitempty"`
	// trailer
	End     bool   `json:"end,omitempty"`
	Records int    `json:"records,omitempty"`
	MAC     string `json:"mac,omitempty"` // HMAC-SHA256 of every line before the trailer (newlines included)
}

func keyCheck(s *secure.Sealer) string {
	return base64.RawURLEncoding.EncodeToString(s.MAC("backup key check")[:12])
}

func newMAC(s *secure.Sealer) hash.Hash { return hmac.New(sha256.New, s.MAC("backup mac")) }

// Stats counts the records of each kind written or restored.
type Stats map[model.Kind]int

// Total is the number of records.
func (s Stats) Total() int {
	n := 0
	for _, v := range s {
		n += v
	}
	return n
}

// Options adjust Write.
type Options struct {
	// Encrypt encrypts the backup with a key derived from the master key (see the package documentation).
	Encrypt bool
}

// Write streams every live record of st to w (unencrypted).
func Write(ctx context.Context, st store.Store, sealer *secure.Sealer, w io.Writer) (Stats, error) {
	return WriteWith(ctx, st, sealer, w, Options{})
}

// skipped reports whether a kind is left out of backups: short-lived sign-in state and cluster locks are
// meaningless in a restored store.
func skipped(k model.Kind) bool { return k == model.KindEphemeral || k == model.KindLock }

// WriteWith streams every live record of st to w, read from a point-in-time view when the backend has one.
func WriteWith(ctx context.Context, st store.Store, sealer *secure.Sealer, w io.Writer, opt Options) (stats Stats, err error) {
	var rd store.Reader = liveReader{st}
	if sn, ok := st.(store.Snapshotter); ok {
		v, err := sn.Snapshot(ctx)
		switch {
		case err == nil:
			rd = v
			defer v.Close()
		case !errors.Is(err, store.ErrNoSnapshot):
			return nil, fmt.Errorf("backup: snapshot: %w", err)
		}
	}
	if opt.Encrypt {
		ew, err := newEncWriter(w, sealer)
		if err != nil {
			return nil, err
		}
		defer func() {
			if cerr := ew.Close(); err == nil {
				err = cerr
			}
		}()
		w = ew
	}
	zw := gzip.NewWriter(w)
	bw := bufio.NewWriterSize(zw, 64<<10)
	mac := newMAC(sealer)
	emit := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		b = append(b, '\n')
		mac.Write(b)
		_, err = bw.Write(b)
		return err
	}
	if err := emit(header{Format: format, Version: version, Created: time.Now().UTC(), KeyCheck: keyCheck(sealer)}); err != nil {
		return nil, err
	}
	stats = Stats{}
	for _, k := range model.Kinds() {
		if skipped(k) {
			continue
		}
		// Paged by key, so a backup of a running server sees every record that existed throughout it: records
		// created or deleted meanwhile cannot shift the pages (they may or may not be included themselves).
		for after := ""; ; {
			if err := ctx.Err(); err != nil {
				return stats, err
			}
			res, err := rd.List(ctx, k, store.ListQuery{After: after, Limit: pageSize})
			if err != nil {
				return stats, fmt.Errorf("list %s: %w", k, err)
			}
			if len(res.Records) == 0 {
				break
			}
			after = res.Records[len(res.Records)-1].ID
			for _, r := range res.Records {
				if err := emit(line{Kind: k, ID: r.ID, Version: r.Version, Epoch: r.Epoch, Created: r.Created, Origin: r.Origin,
					Data: base64.StdEncoding.EncodeToString(r.Data)}); err != nil {
					return stats, err
				}
				stats[k]++
			}
		}
	}
	trailer, _ := json.Marshal(line{End: true, Records: stats.Total(),
		MAC: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))})
	if _, err := bw.Write(append(trailer, '\n')); err != nil {
		return stats, err
	}
	if err := bw.Flush(); err != nil {
		return stats, err
	}
	return stats, zw.Close()
}

// liveReader reads the live store (no snapshot).
type liveReader struct{ st store.Store }

func (l liveReader) List(ctx context.Context, k model.Kind, q store.ListQuery) (*store.ListResult, error) {
	return l.st.List(ctx, k, q)
}
func (l liveReader) Count(ctx context.Context, k model.Kind, scope string) (int, error) {
	return l.st.Count(ctx, k, scope)
}
func (liveReader) Close() error { return nil }

// Empty reports whether st holds no live record.
func Empty(ctx context.Context, st store.Store) (bool, error) {
	for _, k := range model.Kinds() {
		if skipped(k) {
			continue
		}
		n, err := st.Count(ctx, k, "")
		if err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	return true, nil
}

// read walks a backup: the header, then fn for every record line, then the trailer, which must match the count
// and (with a sealer) the MAC. fn may be nil.
func read(r io.Reader, sealer *secure.Sealer, fn func(line, *store.Record) error) (Stats, error) {
	br0 := bufio.NewReader(r)
	var dec *decReader
	if encrypted(br0) {
		if sealer == nil {
			// Without the master key only the encryption framing can be checked: every chunk present, the last one
			// marked as such. The content is verified when it is restored (or verified with the key).
			return nil, checkFraming(br0)
		}
		dr, err := newDecReader(br0, sealer)
		if err != nil {
			return nil, err
		}
		r, dec = dr, dr
	} else {
		r = br0
	}
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	defer zr.Close()
	br := bufio.NewReaderSize(zr, 64<<10)
	var mac hash.Hash
	next := func() ([]byte, error) {
		b, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) { // a long record line
			var buf bytes.Buffer
			buf.Write(b)
			for errors.Is(err, bufio.ErrBufferFull) && buf.Len() < maxLine {
				b, err = br.ReadSlice('\n')
				buf.Write(b)
			}
			b = buf.Bytes()
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFormat, err) // EOF before the trailer: truncated
		}
		return b, nil
	}
	first, err := next()
	if err != nil {
		return nil, err
	}
	var h header
	if json.Unmarshal(first, &h) != nil || h.Format != format {
		return nil, ErrFormat
	}
	if h.Version != version {
		return nil, fmt.Errorf("%w: version %d is not supported by this build", ErrFormat, h.Version)
	}
	if sealer != nil {
		// The key of the master keyring the backup was made with (a backup from before a master key rotation needs
		// the old key as one of server.previous_master_keys); an encrypted one was opened with that same key.
		keys := sealer.Keys()
		if dec != nil {
			keys = keys[dec.key : dec.key+1]
		}
		i := slices.IndexFunc(keys, func(k *secure.Sealer) bool { return h.KeyCheck == keyCheck(k) })
		if i < 0 {
			return nil, ErrKey
		}
		mac = newMAC(keys[i])
		mac.Write(first)
	}
	stats := Stats{}
	for {
		b, err := next()
		if err != nil {
			return stats, err
		}
		var l line
		if err := json.Unmarshal(b, &l); err != nil {
			return stats, fmt.Errorf("%w: %v", ErrFormat, err)
		}
		if l.End {
			if l.Records != stats.Total() {
				return stats, fmt.Errorf("%w: %d records read, the trailer says %d", ErrFormat, stats.Total(), l.Records)
			}
			if mac != nil {
				want, err := base64.RawURLEncoding.DecodeString(l.MAC)
				if err != nil || !hmac.Equal(want, mac.Sum(nil)) {
					return stats, fmt.Errorf("%w: its integrity check failed (altered, or not made with this master key)", ErrFormat)
				}
			}
			return stats, nil
		}
		if mac != nil {
			mac.Write(b)
		}
		rec, err := record(l)
		if err != nil {
			return stats, err
		}
		if fn != nil {
			if err := fn(l, rec); err != nil {
				return stats, err
			}
		}
		stats[l.Kind]++
	}
}

// Verify reads a whole backup and checks it: the header, every record line, the trailer's count and, given the
// master key's sealer, the key check and the integrity MAC (and, for an encrypted backup, every chunk's
// authentication). It writes nothing. Without a sealer (a downloaded backup checked where the key is not available)
// only the structure is checked; for an encrypted backup that is its framing, and the Stats are nil.
func Verify(r io.Reader, sealer *secure.Sealer) (Stats, error) {
	return read(r, sealer, nil)
}

// Restore loads a backup from r into st. The whole backup is verified first (structure, master key, integrity MAC)
// and nothing is written unless it passes; r is then read again from the start. The store must be empty unless
// force is set, in which case records from the backup replace stored ones with an older version, records the backup
// does not hold are left alone, and of two different records claiming one unique value the one created first keeps
// it and the other is kept without it (as in replication: a record is never deleted over a unique clash).
func Restore(ctx context.Context, st store.Store, sealer *secure.Sealer, r io.ReadSeeker, force bool) (Stats, error) {
	if _, err := Verify(r, sealer); err != nil {
		return nil, err
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if !force {
		empty, err := Empty(ctx, st)
		if err != nil {
			return nil, err
		}
		if !empty {
			return nil, ErrNotEmpty
		}
	}
	return read(r, sealer, func(l line, rec *store.Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		store.Witness(rec.Version) // versions minted after the restore stay newer than every restored one
		applied, losers, err := st.PutReplicated(ctx, rec)
		if err != nil {
			return fmt.Errorf("restore %s %s: %w", l.Kind, l.ID, err)
		}
		if !applied && !force {
			// The store held a newer version or a deletion of it: it was not empty after all (deleted records do not
			// count as data, but they still win). Say so instead of reporting it restored.
			return fmt.Errorf("%w: the store already holds a newer version or a deletion of %s %s; restore into a new, "+
				"empty database", ErrNotEmpty, l.Kind, l.ID)
		}
		if len(losers) > 0 && !force {
			return fmt.Errorf("%w: %s %s clashes with another record on a unique value", ErrFormat, l.Kind, l.ID)
		}
		// Merging (force): a record that lost a unique value to another is kept, without that value in the index
		// (as after a replication clash); a cluster reports it when it starts serving.
		return nil
	})
}

// record rebuilds a store record from a backup line. Index values (scope, unique values, query fields, expiry) are
// derived from the entity again by this build rather than trusted from the file.
func record(l line) (*store.Record, error) {
	e := model.NewEntity(l.Kind)
	if e == nil || skipped(l.Kind) {
		return nil, fmt.Errorf("%w: unknown kind %q", ErrFormat, l.Kind)
	}
	data, err := base64.StdEncoding.DecodeString(l.Data)
	if err != nil || l.ID == "" || l.Version == 0 {
		return nil, fmt.Errorf("%w: bad %s record", ErrFormat, l.Kind)
	}
	if err := store.Decode(&store.Record{Data: data, Version: l.Version}, e); err != nil {
		return nil, fmt.Errorf("%w: %s %s: %v", ErrFormat, l.Kind, l.ID, err)
	}
	if e.GetMeta().ID != l.ID {
		return nil, fmt.Errorf("%w: %s %s: id mismatch", ErrFormat, l.Kind, l.ID)
	}
	rec, err := store.EncodeAsIs(e)
	if err != nil {
		return nil, err
	}
	if l.Epoch >= l.Version || l.Created > l.Version {
		return nil, fmt.Errorf("%w: %s %s: bad generation", ErrFormat, l.Kind, l.ID)
	}
	rec.Origin, rec.Epoch, rec.Created = l.Origin, l.Epoch, l.Created
	return rec, nil
}
