package secure

import (
	"bytes"
	"crypto/sha512"
	"strconv"
	"strings"
)

// SHA-512 crypt ("$6$", Ulrich Drepper, "Unix crypt using SHA-256 and SHA-512"; what glibc and PHP's crypt() make) is
// accepted for imported hashes only, like bcrypt: Quisora never makes one.
const (
	sha512CryptPrefix        = "$6$"
	sha512CryptDefaultRounds = 5000    // when the hash names none
	sha512CryptMinRounds     = 1000    // the specification treats fewer as this many
	sha512CryptMaxRounds     = 1000000 // more is refused: an imported hash must not tie up the hashing workers
	sha512CryptMaxSalt       = 16
	sha512CryptHashLen       = 86
	sha512CryptAlphabet      = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// isSHA512Crypt reports whether encoded is a SHA-512 crypt hash: its own prefix says so, so a password is only ever
// compared one way.
func isSHA512Crypt(encoded string) bool { return strings.HasPrefix(encoded, sha512CryptPrefix) }

// parseSHA512Crypt parses $6$[rounds=N$]salt$hash, refusing a salt of more than 16 characters, rounds above the cap,
// and a hash that is not 86 characters of the crypt alphabet. The error says nothing of the hash.
func parseSHA512Crypt(encoded string) (salt []byte, rounds int, hash string, err error) {
	parts := strings.Split(strings.TrimPrefix(encoded, sha512CryptPrefix), "$")
	rounds = sha512CryptDefaultRounds
	if len(parts) == 3 {
		n, ok := strings.CutPrefix(parts[0], "rounds=")
		r, perr := strconv.ParseUint(n, 10, 32)
		if !ok || perr != nil || r > sha512CryptMaxRounds {
			return nil, 0, "", ErrHashParams
		}
		rounds = max(int(r), sha512CryptMinRounds)
		parts = parts[1:]
	}
	if len(parts) != 2 || len(parts[0]) > sha512CryptMaxSalt || strings.HasPrefix(parts[0], "rounds=") ||
		len(parts[1]) != sha512CryptHashLen {
		return nil, 0, "", ErrHashParams
	}
	for i := range len(parts[1]) {
		if strings.IndexByte(sha512CryptAlphabet, parts[1][i]) < 0 {
			return nil, 0, "", ErrHashParams
		}
	}
	return []byte(parts[0]), rounds, parts[1], nil
}

// sha512Crypt returns the 86-character crypt hash of password: the algorithm of the specification, step by step.
func sha512Crypt(password, salt []byte, rounds int) string {
	h := sha512.New()
	h.Write(password)
	h.Write(salt)
	h.Write(password)
	altSum := h.Sum(nil)

	h.Reset()
	h.Write(password)
	h.Write(salt)
	h.Write(cycle(altSum, len(password)))
	for n := len(password); n > 0; n >>= 1 {
		if n&1 != 0 {
			h.Write(altSum)
		} else {
			h.Write(password)
		}
	}
	sum := h.Sum(nil)

	h.Reset()
	for range len(password) {
		h.Write(password)
	}
	p := cycle(h.Sum(nil), len(password))
	h.Reset()
	for range 16 + int(sum[0]) {
		h.Write(salt)
	}
	s := cycle(h.Sum(nil), len(salt))

	for i := range rounds {
		h.Reset()
		if i&1 != 0 {
			h.Write(p)
		} else {
			h.Write(sum)
		}
		if i%3 != 0 {
			h.Write(s)
		}
		if i%7 != 0 {
			h.Write(p)
		}
		if i&1 != 0 {
			h.Write(sum)
		} else {
			h.Write(p)
		}
		sum = h.Sum(sum[:0])
	}

	// Three bytes at a time, in the specification's order, as four characters of six bits each, low bits first.
	out := make([]byte, 0, sha512CryptHashLen)
	emit := func(n uint32, chars int) {
		for range chars {
			out = append(out, sha512CryptAlphabet[n&0x3f])
			n >>= 6
		}
	}
	for _, t := range [21][3]int{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48},
		{28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13},
		{56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41},
	} {
		emit(uint32(sum[t[0]])<<16|uint32(sum[t[1]])<<8|uint32(sum[t[2]]), 4)
	}
	emit(uint32(sum[63]), 2)
	return string(out)
}

// cycle returns n bytes of b repeated as often as needed.
func cycle(b []byte, n int) []byte { return bytes.Repeat(b, n/len(b)+1)[:n] }
