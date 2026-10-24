package backup

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// A crafted header cannot make a verify or restore derive a key at a cost far above what a real backup uses.
func TestPasswordKDFBounded(t *testing.T) {
	header := func(tm, mem uint32, p uint8) []byte {
		b := append([]byte(encMagic2), make([]byte, saltLen)...) // magic, KDF parameters, then the nonce prefix
		b = binary.BigEndian.AppendUint32(b, tm)
		b = binary.BigEndian.AppendUint32(b, mem)
		return append(append(b, p), make([]byte, prefixLen)...)
	}
	for name, h := range map[string][]byte{
		"1 GiB":     header(kdfTime, 1024*1024, kdfThreads),
		"16 passes": header(16, kdfMemory, kdfThreads),
		"32 lanes":  header(kdfTime, kdfMemory, 32),
	} {
		if _, err := newPasswordDecReader(bufio.NewReader(bytes.NewReader(h)), "password"); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v, want ErrFormat before any key is derived", name, err)
		}
	}
	if _, err := newPasswordDecReader(bufio.NewReader(bytes.NewReader(header(kdfTime, kdfMemory, kdfThreads))), "password"); err != nil {
		t.Fatalf("the writer's own parameters: %v", err)
	}
}
