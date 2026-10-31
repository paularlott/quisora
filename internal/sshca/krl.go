package sshca

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

// OpenSSH key revocation lists (PROTOCOL.krl): the magic, a format version, the list's version and date, flags, a
// reserved string and a comment, then sections. Quisora writes certificate sections (one per CA key) holding serial
// lists, and an explicit key section revoking CA keys outright (sshd checks a certificate's signing key against the list
// too, so a CA key listed there is distrusted by a server whatever its CA file says). It reads what it writes plus the
// other certificate subsections (serial ranges, bitmaps, key ids), so a list made by ssh-keygen validates too. The list
// is not signed.
const (
	krlMagic         uint64 = 0x5353484b524c0a00 // "SSHKRL\n\0"
	krlFormatVersion uint32 = 1

	krlSectionCertificates = 1
	krlSectionExplicitKey  = 2
	krlSectionSHA1         = 3
	krlSectionSignature    = 4
	krlSectionSHA256       = 5

	krlCertSerialList   = 0x20
	krlCertSerialRange  = 0x21
	krlCertSerialBitmap = 0x22
	krlCertKeyID        = 0x23
)

// KRLCA is one certificate authority's part of a KRL: the serials revoked among the certificates it signed.
type KRLCA struct {
	Key     []byte      // the CA's public key blob (ssh.PublicKey.Marshal); empty: every CA (read only)
	Serials []uint64    // sorted, without repeats
	Ranges  [][2]uint64 // inclusive serial ranges (read only)
	KeyIDs  []string    // revoked key ids (read only)
}

// KRL is a key revocation list.
type KRL struct {
	Version   uint64 // the list's version: it only goes up
	Generated time.Time
	Comment   string
	CAs       []KRLCA
	// Keys are public key blobs (ssh.PublicKey.Marshal) revoked outright: a CA key listed here revokes every
	// certificate it signed.
	Keys [][]byte
}

// NewKRL starts an empty list.
func NewKRL(version uint64, generated time.Time, comment string) *KRL {
	return &KRL{Version: version, Generated: generated, Comment: comment}
}

// Add lists serials as revoked among the certificates signed by ca. The CA gets its section even with none.
func (k *KRL) Add(ca ssh.PublicKey, serials ...uint64) {
	blob := ca.Marshal()
	for i := range k.CAs {
		if bytes.Equal(k.CAs[i].Key, blob) {
			k.CAs[i].Serials = sortedUnique(append(k.CAs[i].Serials, serials...))
			return
		}
	}
	k.CAs = append(k.CAs, KRLCA{Key: blob, Serials: sortedUnique(slices.Clone(serials))})
}

// RevokeKey lists key as revoked outright (an explicit key section). For a CA key, that revokes every certificate it
// signed.
func (k *KRL) RevokeKey(key ssh.PublicKey) {
	blob := key.Marshal()
	if !k.KeyRevoked(key) {
		k.Keys = append(k.Keys, blob)
	}
}

// KeyRevoked reports whether the list revokes key itself.
func (k *KRL) KeyRevoked(key ssh.PublicKey) bool {
	blob := key.Marshal()
	return slices.ContainsFunc(k.Keys, func(b []byte) bool { return bytes.Equal(b, blob) })
}

func sortedUnique(s []uint64) []uint64 {
	slices.Sort(s)
	return slices.Compact(s)
}

// Revoked reports whether the list revokes the certificate with this serial and key id signed by ca: by its serial or
// key id, or because ca itself is revoked.
func (k *KRL) Revoked(ca ssh.PublicKey, serial uint64, keyID string) bool {
	if k.KeyRevoked(ca) {
		return true
	}
	blob := ca.Marshal()
	for _, c := range k.CAs {
		if len(c.Key) != 0 && !bytes.Equal(c.Key, blob) {
			continue
		}
		if _, found := slices.BinarySearch(c.Serials, serial); found || slices.Contains(c.KeyIDs, keyID) {
			return true
		}
		for _, r := range c.Ranges {
			if serial >= r[0] && serial <= r[1] {
				return true
			}
		}
	}
	return false
}

// Marshal encodes the list.
func (k *KRL) Marshal() []byte {
	var b []byte
	b = binary.BigEndian.AppendUint64(b, krlMagic)
	b = binary.BigEndian.AppendUint32(b, krlFormatVersion)
	b = binary.BigEndian.AppendUint64(b, k.Version)
	b = binary.BigEndian.AppendUint64(b, uint64(k.Generated.Unix()))
	b = binary.BigEndian.AppendUint64(b, 0) // flags
	b = appendString(b, nil)                // reserved
	b = appendString(b, []byte(k.Comment))
	for _, c := range k.CAs {
		var sect []byte
		sect = appendString(sect, c.Key)
		sect = appendString(sect, nil) // reserved
		if len(c.Serials) > 0 {
			var list []byte
			for _, s := range sortedUnique(slices.Clone(c.Serials)) {
				list = binary.BigEndian.AppendUint64(list, s)
			}
			sect = append(sect, krlCertSerialList)
			sect = appendString(sect, list)
		}
		b = append(b, krlSectionCertificates)
		b = appendString(b, sect)
	}
	if len(k.Keys) > 0 {
		var sect []byte
		for _, key := range k.Keys {
			sect = appendString(sect, key)
		}
		b = append(b, krlSectionExplicitKey)
		b = appendString(b, sect)
	}
	return b
}

func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// ErrKRL is the error of a list that does not parse.
var ErrKRL = errors.New("not a valid OpenSSH key revocation list")

// krlReader reads the wire types of the format.
type krlReader struct {
	b   []byte
	err error
}

func (r *krlReader) fail(what string) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: truncated at %s", ErrKRL, what)
	}
}

func (r *krlReader) take(n int, what string) []byte {
	if r.err != nil || n < 0 || len(r.b) < n {
		r.fail(what)
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *krlReader) u8(what string) byte {
	if v := r.take(1, what); v != nil {
		return v[0]
	}
	return 0
}

func (r *krlReader) u32(what string) uint32 {
	if v := r.take(4, what); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

func (r *krlReader) u64(what string) uint64 {
	if v := r.take(8, what); v != nil {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

func (r *krlReader) str(what string) []byte {
	n := r.u32(what)
	if r.err != nil {
		return nil
	}
	if uint64(n) > uint64(len(r.b)) {
		r.fail(what)
		return nil
	}
	return r.take(int(n), what)
}

// ParseKRL parses an OpenSSH key revocation list. It checks the magic, the format version and that every section is
// whole; it does not check a signature (a signed list is accepted, its signature section skipped). An unknown
// certificate subsection is an error, as OpenSSH refuses one.
func ParseKRL(data []byte) (*KRL, error) {
	r := &krlReader{b: data}
	if m := r.u64("the magic"); r.err == nil && m != krlMagic {
		return nil, fmt.Errorf("%w: bad magic", ErrKRL)
	}
	if v := r.u32("the format version"); r.err == nil && v != krlFormatVersion {
		return nil, fmt.Errorf("%w: unsupported format version %d", ErrKRL, v)
	}
	k := &KRL{}
	k.Version = r.u64("the version")
	k.Generated = time.Unix(int64(r.u64("the date")), 0).UTC()
	r.u64("the flags")
	r.str("the reserved string")
	k.Comment = string(r.str("the comment"))
	for r.err == nil && len(r.b) > 0 {
		typ := r.u8("a section type")
		body := &krlReader{b: r.str("a section")}
		if r.err != nil {
			break
		}
		switch typ {
		case krlSectionCertificates:
			ca, err := parseKRLCertificates(body)
			if err != nil {
				return nil, err
			}
			k.CAs = append(k.CAs, ca)
		case krlSectionExplicitKey:
			for len(body.b) > 0 && body.err == nil {
				if key := body.str("a revoked key"); body.err == nil {
					k.Keys = append(k.Keys, key)
				}
			}
			if body.err != nil {
				return nil, body.err
			}
		case krlSectionSHA1, krlSectionSHA256, krlSectionSignature:
			// keys revoked by fingerprint, and signatures: nothing Quisora writes or needs to read
		default:
			return nil, fmt.Errorf("%w: unknown section type %d", ErrKRL, typ)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	return k, nil
}

func parseKRLCertificates(r *krlReader) (KRLCA, error) {
	var ca KRLCA
	ca.Key = r.str("the CA key")
	r.str("the reserved string")
	for r.err == nil && len(r.b) > 0 {
		typ := r.u8("a certificate subsection type")
		body := &krlReader{b: r.str("a certificate subsection")}
		if r.err != nil {
			break
		}
		switch typ {
		case krlCertSerialList:
			for len(body.b) > 0 && body.err == nil {
				ca.Serials = append(ca.Serials, body.u64("a serial"))
			}
		case krlCertSerialRange:
			for len(body.b) > 0 && body.err == nil {
				lo, hi := body.u64("a serial range"), body.u64("a serial range")
				if body.err == nil && lo > hi {
					return ca, fmt.Errorf("%w: serial range %d-%d is backwards", ErrKRL, lo, hi)
				}
				ca.Ranges = append(ca.Ranges, [2]uint64{lo, hi})
			}
		case krlCertSerialBitmap:
			offset := body.u64("a serial bitmap offset")
			mp := body.str("a serial bitmap")
			if body.err == nil {
				// an SSH mpint: big-endian, bit i of the integer revokes serial offset+i
				n := new(big.Int).SetBytes(mp)
				for i := 0; i < n.BitLen(); i++ {
					if n.Bit(i) == 1 {
						ca.Serials = append(ca.Serials, offset+uint64(i))
					}
				}
			}
		case krlCertKeyID:
			for len(body.b) > 0 && body.err == nil {
				ca.KeyIDs = append(ca.KeyIDs, string(body.str("a key id")))
			}
		default:
			return ca, fmt.Errorf("%w: unknown certificate subsection type %d", ErrKRL, typ)
		}
		if body.err != nil {
			return ca, body.err
		}
	}
	if r.err != nil {
		return ca, r.err
	}
	slices.Sort(ca.Serials)
	ca.Serials = slices.Compact(ca.Serials)
	return ca, nil
}

// krlHeaderLen is the length of a list's fixed header: the magic, the format version, the version, the date and the
// flags.
const krlHeaderLen = 8 + 4 + 8 + 8 + 8

// KRLTag is a tag of what the encoded list data revokes: a hash of everything after its version and date, quoted for
// an HTTP ETag. Two lists made at different times that revoke the same have the same tag.
func KRLTag(data []byte) string {
	if len(data) > krlHeaderLen {
		data = data[krlHeaderLen:]
	}
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}
