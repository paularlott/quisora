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

	"golang.org/x/crypto/argon2"
)

// Encrypted backups are the gzip stream sealed with AES-256-GCM in chunks (the STREAM construction):
//
//	magic "QSRBKEN2" | KDF parameters | 7-byte random nonce prefix | chunk... where chunk = uint32 length | ciphertext
//
// The key is derived from a password (Options.Password) with argon2id; its salt and cost travel in the header
// (16-byte salt, uint32 passes, uint32 memory in KiB, one byte of threads), so the cost can change without changing
// the format. Encryption no longer depends on the master key, so a backup's confidentiality survives the master key
// (and a master key exposure does not open old backups).
//
// Each chunk holds up to chunkSize bytes of plaintext. Its nonce is the prefix, the chunk's 4-byte big-endian index
// and a final-chunk flag byte, so chunks cannot be reordered, dropped or repeated, and a stream cut after any chunk
// but the last is refused.
const (
	encMagic    = "QSRBKEN2" // the key derived from a password
	prefixLen   = 7
	saltLen     = 16
	kdfLen      = saltLen + 4 + 4 + 1
	chunkSize   = 64 << 10
	maxChunkLen = chunkSize + 16 // plaintext plus the GCM tag

	// argon2id cost of a backup's key: once per backup and restore, so it can be high.
	kdfTime    = 3
	kdfMemory  = 64 * 1024 // KiB
	kdfThreads = 4
)

var (
	// ErrPassword means the password does not open the backup, or it is damaged.
	ErrPassword = errors.New("backup: the password does not open this backup, or it is damaged")
	// ErrNeedPassword means the backup is encrypted with a password and none was given.
	ErrNeedPassword = errors.New("backup: the backup is encrypted: its password is needed")
)

// MinPassword is the shortest password a new backup is encrypted with.
const MinPassword = 12

func passwordKey(password string, salt []byte, t, m uint32, p uint8) (cipher.AEAD, error) {
	block, err := aes.NewCipher(argon2.IDKey([]byte(password), salt, t, m, p, 32))
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

// newEncWriter encrypts what is written to it with a key derived from password.
func newEncWriter(w io.Writer, password string) (*encWriter, error) {
	if len(password) < MinPassword {
		return nil, fmt.Errorf("backup: the password must have at least %d characters", MinPassword)
	}
	hdr := make([]byte, 0, len(encMagic)+kdfLen+prefixLen)
	hdr = append(hdr, encMagic...)
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	hdr = append(hdr, salt...)
	hdr = binary.BigEndian.AppendUint32(hdr, kdfTime)
	hdr = binary.BigEndian.AppendUint32(hdr, kdfMemory)
	hdr = append(hdr, kdfThreads)
	aead, err := passwordKey(password, salt, kdfTime, kdfMemory, kdfThreads)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, prefixLen)
	if _, err := rand.Read(prefix); err != nil {
		return nil, err
	}
	if _, err := w.Write(append(hdr, prefix...)); err != nil {
		return nil, err
	}
	return &encWriter{w: w, aead: aead, prefix: prefix, buf: make([]byte, 0, chunkSize)}, nil
}

// EncryptWriter returns a writer that encrypts a backup stream written to it with password (as Options.Password
// does): for a backup made elsewhere, such as one downloaded unencrypted over TLS. Close it to finish the file.
func EncryptWriter(w io.Writer, password string) (io.WriteCloser, error) {
	return newEncWriter(w, password)
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

// encrypted reports whether the stream is encrypted (with a password), without consuming it.
func encrypted(br *bufio.Reader) bool {
	b, err := br.Peek(len(encMagic))
	return err == nil && string(b) == encMagic
}

// PasswordProtected reports whether a backup that starts with head (its first bytes, at least 8) is encrypted with
// a password, which restoring it needs.
func PasswordProtected(head []byte) bool {
	return len(head) >= len(encMagic) && string(head[:len(encMagic)]) == encMagic
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

// readHeader reads an encrypted backup's header: the KDF parameters and the nonce prefix.
func readHeader(br *bufio.Reader) (prefix, kdf []byte, err error) {
	hdr := make([]byte, len(encMagic)+kdfLen+prefixLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	hdr = hdr[len(encMagic):]
	return hdr[kdfLen:], hdr[:kdfLen], nil
}

// newPasswordDecReader opens a password-encrypted backup.
func newPasswordDecReader(br *bufio.Reader, password string) (*decReader, error) {
	prefix, kdf, err := readHeader(br)
	if err != nil {
		return nil, err
	}
	t, m, p := binary.BigEndian.Uint32(kdf[saltLen:]), binary.BigEndian.Uint32(kdf[saltLen+4:]), kdf[saltLen+8]
	// Bounded to twice what the writer uses, so a crafted file cannot make a verify or restore spend much more memory
	// or time than a real backup does before anything is checked. (A build that raises the writer's cost raises
	// these with it.)
	if t < 1 || t > 2*kdfTime || m < 8*1024 || m > 2*kdfMemory || p < 1 || p > 2*kdfThreads {
		return nil, fmt.Errorf("%w: key derivation parameters out of range", ErrFormat)
	}
	aead, err := passwordKey(password, kdf[:saltLen], t, m, p)
	if err != nil {
		return nil, err
	}
	return &decReader{r: br, aead: aead, prefix: prefix}, nil
}

// open opens chunk n, as an inner chunk or as the final one.
func (d *decReader) open(ct []byte) (pt []byte, last bool, err error) {
	if pt, err := d.aead.Open(nil, chunkNonce(d.prefix, d.n, false), ct, nil); err == nil {
		return pt, false, nil
	}
	pt, err = d.aead.Open(nil, chunkNonce(d.prefix, d.n, true), ct, nil)
	return pt, true, err
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
		pt, last, err := d.open(ct)
		if err != nil {
			return 0, ErrPassword
		}
		d.done = last
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
	if _, _, err := readHeader(br); err != nil {
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
