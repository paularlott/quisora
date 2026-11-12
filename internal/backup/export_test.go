package backup

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
)

// Skipped reports whether backups leave kind k out (skipped), for the tests that compare a store with its restore.
var Skipped = skipped

// Every test in the package derives keys at the lowest cost argon2id allows the reader's bounds (see
// newPasswordDecReader), so the real writer and reader run but the 64 MiB production cost is not paid per backup.
func init() {
	kdfTime, kdfMemory, kdfThreads = 1, 8*1024, 1
}

// Decrypt returns the gzip stream inside an encrypted backup.
func Decrypt(data []byte, password string) ([]byte, error) {
	br := bufio.NewReader(bytes.NewReader(data))
	dr, err := newPasswordDecReader(br, password)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(dr)
}

// Unpack returns the JSON lines inside an encrypted backup, for tests that alter a backup.
func Unpack(data []byte, password string) ([]byte, error) {
	gz, err := Decrypt(data, password)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

// Pack makes an encrypted backup of JSON lines, the inverse of Unpack: what a forger who knows the password would
// write, with the integrity MAC the only thing left that refuses it.
func Pack(lines []byte, password string) ([]byte, error) {
	var out bytes.Buffer
	ew, err := EncryptWriter(&out, password)
	if err != nil {
		return nil, err
	}
	zw := gzip.NewWriter(ew)
	if _, err := zw.Write(lines); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := ew.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
