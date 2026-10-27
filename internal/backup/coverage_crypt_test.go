package backup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store/memstore"
)

const covPassword = "correct horse battery"

// failWriter fails the write numbered failAt (1 is the first), accepting the ones before.
type failWriter struct {
	failAt, n int
}

func (f *failWriter) Write(p []byte) (int, error) {
	f.n++
	if f.n >= f.failAt {
		return 0, errors.New("injected: write failed")
	}
	return len(p), nil
}

func TestEncryptWriterRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := covSealer(t)
	src := covStoreWithGroups(t, 3)
	var plain bytes.Buffer
	if _, err := WriteWith(ctx, src, s, &plain, Options{}); err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	w, err := EncryptWriter(&enc, covPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil { // idempotent
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("write after close accepted")
	}
	if !PasswordProtected(enc.Bytes()) || PasswordProtected(enc.Bytes()[:4]) || PasswordProtected(plain.Bytes()) {
		t.Fatal("PasswordProtected")
	}
	dst := memstore.New()
	if st, err := Restore(ctx, dst, s, bytes.NewReader(enc.Bytes()), false, covPassword); err != nil || st[model.KindGroup] != 3 {
		t.Fatalf("restore: %v %v", st, err)
	}
	if _, err := EncryptWriter(io.Discard, "short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestEncryptWriterWriteFailures(t *testing.T) {
	// The header cannot be written.
	if _, err := newEncWriter(&failWriter{failAt: 1}, covPassword); err == nil {
		t.Fatal("header write failure ignored")
	}
	// A full chunk cannot be written: its length prefix, then its ciphertext.
	for failAt := 2; failAt <= 3; failAt++ {
		w, err := newEncWriter(&failWriter{failAt: failAt}, covPassword)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(make([]byte, chunkSize)); err == nil {
			t.Fatalf("chunk write %d failure ignored", failAt)
		}
	}
	w, err := newEncWriter(&failWriter{failAt: 2}, covPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err == nil {
		t.Fatal("final chunk failure ignored")
	}
}

func TestEncWriterChunkCounterOverflow(t *testing.T) {
	w, err := newEncWriter(io.Discard, covPassword)
	if err != nil {
		t.Fatal(err)
	}
	w.n = math.MaxUint32
	if err := w.Close(); err == nil {
		t.Fatal("a backup past 2^32 chunks was sealed")
	}
}

// WriteWith reports a failed final chunk of the encryption as the backup's error, and a failed header as one too.
func TestWriteWithPasswordWriterFailures(t *testing.T) {
	s := covSealer(t)
	st := covStoreWithGroups(t, 1)
	if _, err := WriteWith(context.Background(), st, s, &failWriter{failAt: 1}, Options{Password: covPassword}); err == nil {
		t.Fatal("header failure ignored")
	}
	if _, err := WriteWith(context.Background(), st, s, &failWriter{failAt: 1}, Options{}); err == nil {
		t.Fatal("plain write failure ignored")
	}
}

// The final encrypted chunk is written when WriteWith returns; its failure must fail the backup, or a truncated file
// (no final chunk: unrestorable) is reported as written.
func TestWriteWithPasswordFinalChunkFailureIsReported(t *testing.T) {
	s := covSealer(t)
	if _, err := WriteWith(context.Background(), s2store(t), s, &failWriter{failAt: 2}, Options{Password: covPassword}); err == nil {
		t.Fatal("final chunk failure ignored")
	}
}

func s2store(t *testing.T) *memstore.Store { return covStoreWithGroups(t, 1).(*memstore.Store) }

func TestEncryptedBackupDamage(t *testing.T) {
	ctx := context.Background()
	s := covSealer(t)
	var enc bytes.Buffer
	if _, err := WriteWith(ctx, covStoreWithGroups(t, 3), s, &enc, Options{Password: covPassword}); err != nil {
		t.Fatal(err)
	}
	data := enc.Bytes()
	const hdr = len(encMagic) + kdfLen + prefixLen

	t.Run("short header", func(t *testing.T) {
		for _, n := range []int{len(encMagic) + 3, hdr - 1} {
			for _, check := range []struct {
				name string
				s    func() error
			}{
				{"password", func() error { _, err := Verify(bytes.NewReader(data[:n]), s, covPassword); return err }},
				{"framing only", func() error { _, err := Verify(bytes.NewReader(data[:n]), nil, ""); return err }},
				{"framing, other password", func() error { _, err := Verify(bytes.NewReader(data[:n]), nil, covPassword); return err }},
			} {
				if err := check.s(); !errors.Is(err, ErrFormat) {
					t.Errorf("%s with %d bytes: %v", check.name, n, err)
				}
			}
		}
	})
	t.Run("bad chunk length", func(t *testing.T) {
		for _, n := range []uint32{0, 15, maxChunkLen + 1} {
			bad := bytes.Clone(data)
			binary.BigEndian.PutUint32(bad[hdr:], n)
			if _, err := Verify(bytes.NewReader(bad), s, covPassword); !errors.Is(err, ErrFormat) {
				t.Errorf("length %d: %v", n, err)
			}
			if _, err := Verify(bytes.NewReader(bad), nil, ""); !errors.Is(err, ErrFormat) {
				t.Errorf("framing, length %d: %v", n, err)
			}
		}
	})
	t.Run("cut inside a length prefix", func(t *testing.T) {
		if _, err := Verify(bytes.NewReader(data[:hdr+2]), s, covPassword); !errors.Is(err, ErrFormat) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("nothing after the header", func(t *testing.T) {
		if _, err := Verify(bytes.NewReader(data[:hdr]), s, covPassword); !errors.Is(err, ErrFormat) {
			t.Fatalf("%v", err)
		}
		if _, err := Verify(bytes.NewReader(data[:hdr]), nil, ""); !errors.Is(err, ErrFormat) {
			t.Fatalf("framing: %v", err)
		}
	})
	t.Run("data after the final chunk", func(t *testing.T) {
		extended := append(bytes.Clone(data), 0)
		if _, err := Verify(bytes.NewReader(extended), nil, ""); !errors.Is(err, ErrFormat) {
			t.Fatalf("framing: %v", err)
		}
		if _, err := Verify(bytes.NewReader(extended), s, covPassword); !errors.Is(err, ErrFormat) {
			t.Fatalf("with the password: %v", err)
		}
	})
	t.Run("without the master key", func(t *testing.T) {
		if st, err := Verify(bytes.NewReader(data), nil, ""); err != nil || st != nil {
			t.Fatalf("%v %v", st, err)
		}
		if _, err := Verify(bytes.NewReader(data), nil, covPassword); err != nil {
			t.Fatalf("with a password but no key: %v", err)
		}
	})
}
