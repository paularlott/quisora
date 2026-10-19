package backup

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/paularlott/quisora/internal/secure"
)

// Encrypted backups (Options.Encrypt) are the gzip stream sealed with AES-256-GCM in chunks (the STREAM
// construction):
//
//	magic "QSRBKEN1" | 7-byte random nonce prefix | chunk... where chunk = uint32 length | ciphertext
//
// Each chunk holds up to chunkSize bytes of plaintext. Its nonce is the prefix, the chunk's 4-byte big-endian index
// and a final-chunk flag byte, so chunks cannot be reordered, dropped or repeated, and a stream cut after any chunk
// but the last is refused. The key is derived from the master key (it never leaves the process).
const (
	encMagic    = "QSRBKEN1"
	prefixLen   = 7
	chunkSize   = 64 << 10
	maxChunkLen = chunkSize + 16 // plaintext plus the GCM tag
)

// ErrEncrypted means an encrypted backup cannot be read: it needs the master key it was made with, or it is
// damaged.
var ErrEncrypted = errors.New("backup: encrypted backup cannot be decrypted with this master key, or is damaged")

func encKey(s *secure.Sealer) (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.MAC("quisora backup encryption v1"))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkNonce(prefix []byte, i uint32, last bool) []byte {
	n := make([]byte, 12)
	copy(n, prefix)
	binary.BigEndian.PutUint32(n[prefixLen:], i)
	if last {
		n[11] = 1
	}
	return n
}

// encWriter seals what is written to it in chunks; Close seals the final one.
type encWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	prefix []byte
	buf    []byte
	n      uint32
	closed bool
}

func newEncWriter(w io.Writer, s *secure.Sealer) (*encWriter, error) {
	aead, err := encKey(s)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, prefixLen)
	if _, err := rand.Read(prefix); err != nil {
		return nil, err
	}
	if _, err := w.Write(append([]byte(encMagic), prefix...)); err != nil {
		return nil, err
	}
	return &encWriter{w: w, aead: aead, prefix: prefix, buf: make([]byte, 0, chunkSize)}, nil
}

func (e *encWriter) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("backup: write after close")
	}
	n := len(p)
	for len(p) > 0 {
		k := min(chunkSize-len(e.buf), len(p))
		e.buf = append(e.buf, p[:k]...)
		p = p[k:]
		if len(e.buf) == chunkSize {
			if err := e.flush(false); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

func (e *encWriter) flush(last bool) error {
	ct := e.aead.Seal(nil, chunkNonce(e.prefix, e.n, last), e.buf, nil)
	e.n++
	if e.n == 0 {
		return errors.New("backup: too large to encrypt")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
	if _, err := e.w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := e.w.Write(ct)
	e.buf = e.buf[:0]
	return err
}

// Close seals the final chunk (possibly empty). The underlying writer is not closed.
func (e *encWriter) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.flush(true)
}

// encrypted reports whether the stream starts with the encrypted-backup magic (without consuming it).
func encrypted(br *bufio.Reader) bool {
	b, err := br.Peek(len(encMagic))
	return err == nil && string(b) == encMagic
}

// decReader opens the chunks of an encrypted backup as they are read; a missing final chunk, trailing data or a
// chunk that does not authenticate is an error.
type decReader struct {
	r      *bufio.Reader
	aead   cipher.AEAD
	prefix []byte
	n      uint32
	buf    []byte
	done   bool
}

func readHeader(br *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, len(encMagic)+prefixLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	return hdr[len(encMagic):], nil
}

func newDecReader(br *bufio.Reader, s *secure.Sealer) (*decReader, error) {
	aead, err := encKey(s)
	if err != nil {
		return nil, err
	}
	prefix, err := readHeader(br)
	if err != nil {
		return nil, err
	}
	return &decReader{r: br, aead: aead, prefix: prefix}, nil
}

// nextChunk reads one chunk's ciphertext; io.EOF only exactly at a chunk boundary.
func nextChunk(br *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 16 || n > maxChunkLen {
		return nil, fmt.Errorf("%w: bad chunk length %d", ErrFormat, n)
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(br, ct); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	return ct, nil
}

func (d *decReader) Read(p []byte) (int, error) {
	for len(d.buf) == 0 {
		if d.done {
			if _, err := d.r.ReadByte(); err == nil {
				return 0, fmt.Errorf("%w: data after the final chunk", ErrFormat)
			}
			return 0, io.EOF
		}
		ct, err := nextChunk(d.r)
		if errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("%w: truncated (no final chunk)", ErrFormat)
		}
		if err != nil {
			return 0, err
		}
		// A chunk opens either as an inner chunk or as the final one; anything else is damaged or forged.
		pt, err := d.aead.Open(nil, chunkNonce(d.prefix, d.n, false), ct, nil)
		if err != nil {
			pt, err = d.aead.Open(nil, chunkNonce(d.prefix, d.n, true), ct, nil)
			if err != nil {
				return 0, ErrEncrypted
			}
			d.done = true
		}
		d.n++
		d.buf = pt
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

// checkFraming walks an encrypted backup's chunks without the key. Every chunk but the last holds exactly chunkSize
// bytes of plaintext and the last one less (the writer flushes a full chunk as soon as it has one), so a stream cut
// anywhere — inside a chunk or at a chunk boundary — is detected here too. Authentication needs the key.
func checkFraming(br *bufio.Reader) error {
	if _, err := readHeader(br); err != nil {
		return err
	}
	for {
		ct, err := nextChunk(br)
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: truncated (no final chunk)", ErrFormat)
		}
		if err != nil {
			return err
		}
		if len(ct) < maxChunkLen { // the final chunk
			if _, err := br.ReadByte(); err == nil {
				return fmt.Errorf("%w: data after the final chunk", ErrFormat)
			}
			return nil
		}
	}
}
